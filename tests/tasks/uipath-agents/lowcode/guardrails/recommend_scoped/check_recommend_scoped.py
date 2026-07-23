#!/usr/bin/env python3
"""Tool-scoped deterministic guardrail check — Send message to channel.

Validates that a custom guardrail was added for the Slack tool:
  - At least 1 guardrail with $guardrailType == "custom" exists
  - It targets Tool scope with matchNames containing "Send message to channel"
  - It blocks violations
  - It has a word rule whose contains value or regular expression matches
    CONFIDENTIAL
  - It has a UUID id
"""

import json
import os
import re
import sys
import uuid
from pathlib import Path

ROOT = Path(os.getcwd()) / "WebResearchBriefingSolution" / "WebResearchBriefingAgent"
AGENT = ROOT / "agent.json"

TARGET_TOOL = "Send message to channel"
FORBIDDEN_TERM = "CONFIDENTIAL"


def load(path: Path) -> dict:
    if not path.is_file():
        sys.exit(f"FAIL: Missing {path}")
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as e:
        sys.exit(f"FAIL: {path} is not valid JSON: {e}")


def blocks_forbidden_term(rule: dict) -> bool:
    """Return whether a word rule triggers for the forbidden term."""
    if rule.get("$ruleType") != "word":
        return False

    operator = rule.get("operator")
    value = rule.get("value")
    if not isinstance(value, str) or not value:
        return False
    if operator == "contains":
        return value in FORBIDDEN_TERM
    if operator == "matchesRegex":
        try:
            return re.search(value, FORBIDDEN_TERM) is not None
        except re.error:
            return False
    return False


def main() -> None:
    agent = load(AGENT)

    guardrails = agent.get("guardrails")
    if not isinstance(guardrails, list) or len(guardrails) == 0:
        sys.exit(
            "FAIL: agent.json.guardrails must be a non-empty array, "
            f"got {type(guardrails).__name__}: {guardrails!r}"
        )
    print(f"OK: guardrails array has {len(guardrails)} entry/entries")

    # Find custom guardrails
    custom = [g for g in guardrails if g.get("$guardrailType") == "custom"]
    if not custom:
        types = [(g.get("$guardrailType"), g.get("validatorType")) for g in guardrails]
        sys.exit(
            f'FAIL: no guardrail with $guardrailType == "custom" found. Got: {types}'
        )
    print(f"OK: found {len(custom)} custom guardrail(s)")

    # Find one targeting the Slack tool
    slack_guards = []
    for g in custom:
        match_names = (g.get("selector") or {}).get("matchNames") or []
        if TARGET_TOOL in match_names:
            slack_guards.append(g)

    if not slack_guards:
        all_match_names = [
            (g.get("selector") or {}).get("matchNames") or [] for g in custom
        ]
        sys.exit(
            f'FAIL: no custom guardrail targets "{TARGET_TOOL}". '
            f"matchNames found across custom guardrails: {all_match_names}"
        )
    g = slack_guards[0]
    print(f'OK: custom guardrail targets "{TARGET_TOOL}"')

    # UUID id
    gid = g.get("id")
    try:
        if not isinstance(gid, str):
            raise ValueError
        uuid.UUID(gid)
    except (ValueError, AttributeError):
        sys.exit(f"FAIL: guardrail.id is not a valid UUID: {gid!r}")
    print(f"OK: guardrail id is a UUID: {gid}")

    # blocking action
    action = g.get("action")
    if not isinstance(action, dict) or action.get("$actionType") != "block":
        sys.exit(
            'FAIL: guardrail.action.$actionType must be "block". '
            f"action={action!r}"
        )
    print('OK: action.$actionType == "block"')

    # selector.scopes contains "Tool"
    scopes = (g.get("selector") or {}).get("scopes") or []
    if "Tool" not in scopes:
        sys.exit(
            f'FAIL: guardrail selector.scopes must contain "Tool", got {scopes!r}'
        )
    print(f"OK: selector.scopes includes 'Tool': {scopes}")

    # rules array
    rules = g.get("rules")
    if not isinstance(rules, list) or len(rules) == 0:
        sys.exit(
            f"FAIL: guardrail.rules must be a non-empty array, got {rules!r}"
        )
    for i, rule in enumerate(rules):
        if not rule.get("$ruleType"):
            sys.exit(
                f"FAIL: rules[{i}] missing $ruleType discriminator. rule={rule!r}"
            )
    print(f"OK: rules array has {len(rules)} rule(s), all have $ruleType")

    matching_rules = [rule for rule in rules if blocks_forbidden_term(rule)]
    if not matching_rules:
        sys.exit(
            "FAIL: guardrail.rules must include a word rule whose contains "
            "value or matchesRegex pattern can semantically match "
            f"CONFIDENTIAL. rules={rules!r}"
        )
    print("OK: found word rule that blocks CONFIDENTIAL")

    print("OK: custom tool-scoped guardrail check passed")


if __name__ == "__main__":
    main()
