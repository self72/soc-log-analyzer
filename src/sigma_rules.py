"""
sigma_rules.py
A simplified Sigma-style rule engine. Real Sigma rules are YAML with a
`detection.selection` block of field:value matches and a `condition`.
This engine supports the common subset: equality, contains ('|contains'),
and simple AND-of-selection conditions - enough for SOC log triage rules
stored under rules/sigma/*.yml.

Example rule:
  title: Multiple Failed Logins Followed by Success
  id: brute-force-success
  status: experimental
  logsource: {category: authentication}
  detection:
    selection:
      status|contains: FAIL
    condition: selection
  level: high
"""

import glob
import yaml


def load_sigma_rules(rules_dir):
    rules = []
    for path in glob.glob(f"{rules_dir}/*.yml") + glob.glob(f"{rules_dir}/*.yaml"):
        with open(path, "r", encoding="utf-8") as f:
            try:
                rule = yaml.safe_load(f)
                rule["_path"] = path
                rules.append(rule)
            except yaml.YAMLError as exc:
                print(f"[!] Failed to parse sigma rule {path}: {exc}")
    return rules


def _field_matches(record, field_expr, expected):
    if "|contains" in field_expr:
        field = field_expr.split("|")[0]
        actual = str(record.get(field, "")).upper()
        return str(expected).upper() in actual
    if "|startswith" in field_expr:
        field = field_expr.split("|")[0]
        actual = str(record.get(field, "")).upper()
        return actual.startswith(str(expected).upper())
    # plain equality
    actual = str(record.get(field_expr, "")).upper()
    return actual == str(expected).upper()


def evaluate_rule(rule, records):
    """Returns list of matching records for a given sigma-style rule."""
    detection = rule.get("detection", {})
    selection = detection.get("selection", {})
    if not selection:
        return []

    matches = []
    for r in records:
        if all(_field_matches(r, field, value) for field, value in selection.items()):
            matches.append(r)
    return matches


def run_sigma_rules(rules_dir, records):
    """Runs all rules found in rules_dir against records. Returns dict rule_title -> matches."""
    results = {}
    for rule in load_sigma_rules(rules_dir):
        title = rule.get("title", rule.get("_path"))
        matches = evaluate_rule(rule, records)
        if matches:
            results[title] = {
                "level": rule.get("level", "medium"),
                "id": rule.get("id", ""),
                "matches": matches,
            }
    return results
