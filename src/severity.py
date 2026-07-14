"""
severity.py
Assigns severity levels to detected findings: INFO, WARNING, ERROR, CRITICAL
"""

SEVERITY_ORDER = ["INFO", "WARNING", "ERROR", "CRITICAL"]

SEVERITY_COLOR = {
    "INFO": "cyan",
    "WARNING": "yellow",
    "ERROR": "red",
    "CRITICAL": "bold white on red",
}

SEVERITY_ICON = {
    "INFO": "🔵",
    "WARNING": "🟡",
    "ERROR": "🟠",
    "CRITICAL": "🔴",
}


def severity_for_finding(finding_type: str, **kwargs) -> str:
    """
    finding_type: 'failed_login' | 'brute_force' | 'multiple_ips' | 'event_summary'
    kwargs: extra context, e.g. attempt_count, ip_count
    """
    if finding_type == "failed_login":
        return "INFO"
    if finding_type == "multiple_ips":
        ip_count = kwargs.get("ip_count", 0)
        return "CRITICAL" if ip_count >= 5 else "WARNING"
    if finding_type == "brute_force":
        attempts = kwargs.get("attempt_count", 0)
        if attempts >= 15:
            return "CRITICAL"
        if attempts >= 5:
            return "ERROR"
        return "WARNING"
    return "INFO"


def rank(severity: str) -> int:
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return 0
