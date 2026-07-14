"""
yara_scan.py
Optional YARA rule scanning of the raw log file (or any target file) for
suspicious strings/patterns (e.g. known webshell markers, tool names,
IOC strings sometimes left in log messages).

Requires the optional 'yara-python' package:
    pip install yara-python

This module degrades gracefully if yara-python is not installed -
it will report that YARA scanning is unavailable rather than crashing
the rest of the tool.
"""

import glob

try:
    import yara  # type: ignore
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


def compile_rules(rules_dir):
    if not YARA_AVAILABLE:
        return None
    rule_files = glob.glob(f"{rules_dir}/*.yar") + glob.glob(f"{rules_dir}/*.yara")
    if not rule_files:
        return None
    filepaths = {f"rule_{i}": path for i, path in enumerate(rule_files)}
    try:
        return yara.compile(filepaths=filepaths)
    except Exception as exc:  # noqa: BLE001
        print(f"[!] Failed to compile YARA rules: {exc}")
        return None


def scan_file(target_path, rules_dir):
    """
    Returns list of {rule, tags, strings} matches, or a status dict if
    YARA is unavailable / no rules found.
    """
    if not YARA_AVAILABLE:
        return {"available": False, "reason": "yara-python not installed", "matches": []}

    rules = compile_rules(rules_dir)
    if rules is None:
        return {"available": False, "reason": "no compiled rules found", "matches": []}

    try:
        raw_matches = rules.match(target_path)
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "reason": str(exc), "matches": []}

    matches = []
    for m in raw_matches:
        matches.append({
            "rule": m.rule,
            "tags": list(m.tags),
            "strings": [(offset, ident, str(data)[:80]) for offset, ident, data in m.strings],
        })
    return {"available": True, "reason": "", "matches": matches}
