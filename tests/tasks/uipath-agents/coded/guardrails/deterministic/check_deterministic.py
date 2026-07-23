#!/usr/bin/env python3
"""Check that a deterministic guardrail blocking 'secret' was correctly added to graph.py.

Validates (middleware or decorator style both accepted):
- Either UiPathDeterministicGuardrailMiddleware or CustomValidator is used
- A lambda/rule that checks for the word "secret" in the input is present
- BlockAction is used
- The guardrail targets the lookup_account_info tool
"""

import ast
import sys
from pathlib import Path

GRAPH = Path("graph.py")


def read() -> str:
    if not GRAPH.is_file():
        sys.exit(f"FAIL: {GRAPH} not found in {Path.cwd()}")
    return GRAPH.read_text()


def check(condition: bool, msg: str) -> None:
    if not condition:
        sys.exit(f"FAIL: {msg}")


def _call_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _assigned_names(node: ast.Assign | ast.AnnAssign) -> list[str]:
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    return [target.id for target in targets if isinstance(target, ast.Name)]


Scope = ast.Module | ast.FunctionDef | ast.AsyncFunctionDef
CallableNode = ast.Lambda | ast.FunctionDef


def _callable_argument(call: ast.Call) -> ast.expr | None:
    if call.args:
        return call.args[0]
    return next(
        (
            keyword.value
            for keyword in call.keywords
            if keyword.arg in {"rule", "predicate", "validator"}
        ),
        None,
    )


class _ConfiguredRuleCollector(ast.NodeVisitor):
    def __init__(self, tree: ast.Module) -> None:
        self.current_scope: Scope = tree
        self.parent_scope: dict[Scope, Scope | None] = {tree: None}
        self.callables: dict[Scope, dict[str, CallableNode]] = {tree: {}}
        self.string_constants: dict[Scope, dict[str, str]] = {tree: {}}
        self.configured_rules: list[tuple[ast.expr, Scope]] = []

    def _ensure_scope(self, scope: Scope, parent: Scope) -> None:
        self.parent_scope[scope] = parent
        self.callables[scope] = {}
        self.string_constants[scope] = {}

    def _visit_function_scope(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> None:
        parent = self.current_scope
        if isinstance(node, ast.FunctionDef):
            self.callables[parent][node.name] = node

        # Decorators and defaults are evaluated in the containing scope.
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Call) and _call_name(decorator.func) == "guardrail":
                self._record_guardrail_validator(decorator)
            self.visit(decorator)
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self.visit(default)

        self._ensure_scope(node, parent)
        self.current_scope = node
        for statement in node.body:
            self.visit(statement)
        self.current_scope = parent

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function_scope(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function_scope(node)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        # Lambda bodies cannot introduce named local rule declarations.
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        # Class bodies have different name-resolution rules and are not needed
        # for the supported module/function guardrail wiring patterns.
        for decorator in node.decorator_list:
            self.visit(decorator)

    def visit_Assign(self, node: ast.Assign) -> None:
        self._register_assignment(node)
        self.visit(node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self._register_assignment(node)
        if node.value is not None:
            self.visit(node.value)

    def _register_assignment(self, node: ast.Assign | ast.AnnAssign) -> None:
        value = node.value
        if value is None:
            return
        for name in _assigned_names(node):
            if isinstance(value, ast.Lambda):
                self.callables[self.current_scope][name] = value
            elif isinstance(value, ast.Constant) and isinstance(value.value, str):
                self.string_constants[self.current_scope][name] = value.value

    def _record_guardrail_validator(self, call: ast.Call) -> None:
        validator_values = [
            keyword.value for keyword in call.keywords if keyword.arg == "validator"
        ]
        validator_values.extend(call.args)
        for value in validator_values:
            if (
                isinstance(value, ast.Call)
                and _call_name(value.func) == "CustomValidator"
            ):
                rule = _callable_argument(value)
                if rule is not None:
                    self.configured_rules.append((rule, self.current_scope))

    def visit_Call(self, node: ast.Call) -> None:
        call_name = _call_name(node.func)
        if call_name == "UiPathDeterministicGuardrailMiddleware":
            rules_keyword = next(
                (keyword.value for keyword in node.keywords if keyword.arg == "rules"),
                None,
            )
            if isinstance(rules_keyword, (ast.List, ast.Tuple, ast.Set)):
                self.configured_rules.extend(
                    (rule, self.current_scope) for rule in rules_keyword.elts
                )
            elif rules_keyword is not None:
                self.configured_rules.append((rules_keyword, self.current_scope))
        elif (
            isinstance(node.func, ast.Call)
            and _call_name(node.func.func) == "guardrail"
            and node.args
        ):
            self._record_guardrail_validator(node.func)
        self.generic_visit(node)

    def lookup_callable(
        self, name: str, scope: Scope
    ) -> tuple[CallableNode, Scope] | None:
        current: Scope | None = scope
        while current is not None:
            callable_node = self.callables[current].get(name)
            if callable_node is not None:
                return callable_node, current
            current = self.parent_scope[current]
        return None

    def constants_in_scope(self, scope: Scope) -> dict[str, str]:
        scopes: list[Scope] = []
        current: Scope | None = scope
        while current is not None:
            scopes.append(current)
            current = self.parent_scope[current]

        constants: dict[str, str] = {}
        for lexical_scope in reversed(scopes):
            constants.update(self.string_constants[lexical_scope])
        return constants


class _SecretBodyVisitor(ast.NodeVisitor):
    def __init__(self, string_constants: dict[str, str]) -> None:
        self.string_constants = string_constants
        self.found = False

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str) and "secret" in node.value.lower():
            self.found = True

    def visit_Name(self, node: ast.Name) -> None:
        value = self.string_constants.get(node.id)
        if isinstance(node.ctx, ast.Load) and value is not None and "secret" in value.lower():
            self.found = True

    def visit_Lambda(self, node: ast.Lambda) -> None:
        # A nested lambda is a different callable and is not executed by itself.
        return

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        # A nested function is a different callable and is not executed by itself.
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return


def _callable_body_mentions_secret(
    node: ast.Lambda | ast.FunctionDef,
    string_constants: dict[str, str],
) -> bool:
    visitor = _SecretBodyVisitor(string_constants)
    if isinstance(node, ast.Lambda):
        visitor.visit(node.body)
        return visitor.found

    body = node.body
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]
    for statement in body:
        visitor.visit(statement)
    return visitor.found


def has_secret_callable(src: str) -> bool:
    """Return whether a configured synchronous rule checks for ``secret``."""
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return False

    collector = _ConfiguredRuleCollector(tree)
    collector.visit(tree)

    for expression, configured_scope in collector.configured_rules:
        callable_node: CallableNode | None
        callable_scope: Scope
        if isinstance(expression, ast.Lambda):
            callable_node = expression
            callable_scope = configured_scope
        elif isinstance(expression, ast.Name):
            resolved = collector.lookup_callable(expression.id, configured_scope)
            if resolved is None:
                continue
            callable_node, declaration_scope = resolved
            callable_scope = (
                callable_node
                if isinstance(callable_node, ast.FunctionDef)
                else declaration_scope
            )
        else:
            callable_node = None
        if callable_node is not None and _callable_body_mentions_secret(
            callable_node, collector.constants_in_scope(callable_scope)
        ):
            return True
    return False


def main() -> None:
    src = read()

    # Accept either middleware or decorator style
    has_middleware = "UiPathDeterministicGuardrailMiddleware" in src
    has_decorator = "CustomValidator" in src

    check(
        has_middleware or has_decorator,
        "Neither UiPathDeterministicGuardrailMiddleware nor CustomValidator found in graph.py "
        "— deterministic guardrail not added",
    )
    if has_middleware:
        print("OK: UiPathDeterministicGuardrailMiddleware used (middleware style)")
    else:
        print("OK: CustomValidator used (decorator style)")

    # Rule must check for "secret" somewhere in the source
    check(
        "secret" in src.lower(),
        "No reference to 'secret' found in graph.py — the blocking rule must check for this word",
    )
    print("OK: 'secret' keyword referenced in the rule")

    # A lambda (or function) must be the rule
    check(
        has_secret_callable(src),
        "No lambda or function rule checking for 'secret' found — the rule must be a callable",
    )
    print("OK: lambda/function rule checking for 'secret' found")

    check(
        "BlockAction" in src,
        "BlockAction not found — deterministic guardrail must use a block action",
    )
    print("OK: BlockAction used")

    # lookup_account_info should be referenced near the guardrail
    check(
        "lookup_account_info" in src,
        "lookup_account_info not referenced after modification — Tool-scoped guardrail "
        "should target this tool",
    )
    print("OK: lookup_account_info referenced (target tool)")

    print("OK: Deterministic guardrail with 'secret' rule correctly added to graph.py")


if __name__ == "__main__":
    main()
