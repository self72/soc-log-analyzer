"""
detectors.py
Core detection logic: failed logins, brute force, multiple-IP usage,
event ID counts, and successful-login-after-failed-attempts.
"""

from collections import defaultdict, Counter
from datetime import timedelta

FAILED_STATUS_KEYWORDS = {"FAILED", "FAIL", "FAILURE", "DENIED"}
FAILED_EVENT_IDS = {"4625"}  # Windows: An account failed to log on
SUCCESS_EVENT_IDS = {"4624"}


def is_failed(record) -> bool:
    return (
        record["status"].upper() in FAILED_STATUS_KEYWORDS
        or record["event_id"] in FAILED_EVENT_IDS
    )


def is_success(record) -> bool:
    return (
        record["status"].upper() in {"SUCCESS", "OK", "ACCEPTED"}
        or record["event_id"] in SUCCESS_EVENT_IDS
    )


def detect_failed_logins(records):
    """Returns list of failed login records."""
    return [r for r in records if is_failed(r)]


def detect_brute_force(records, threshold=5, window_minutes=10):
    """
    Groups failed logins by (user, src_ip) and flags any group with
    >= threshold failed attempts within a rolling window_minutes window.

    Returns list of findings:
      {user, src_ip, attempt_count, first_seen, last_seen, records}
    """
    failed = [r for r in detect_failed_logins(records) if r["timestamp"]]
    grouped = defaultdict(list)
    for r in failed:
        grouped[(r["user"], r["src_ip"])].append(r)

    findings = []
    window = timedelta(minutes=window_minutes)

    for (user, ip), recs in grouped.items():
        recs = sorted(recs, key=lambda r: r["timestamp"])
        # sliding window scan
        start_idx = 0
        for end_idx in range(len(recs)):
            while recs[end_idx]["timestamp"] - recs[start_idx]["timestamp"] > window:
                start_idx += 1
            count = end_idx - start_idx + 1
            if count >= threshold:
                findings.append({
                    "user": user,
                    "src_ip": ip,
                    "attempt_count": count,
                    "first_seen": recs[start_idx]["timestamp"],
                    "last_seen": recs[end_idx]["timestamp"],
                    "records": recs[start_idx:end_idx + 1],
                })
                break  # one finding per (user, ip) is enough; avoid duplicate overlapping alerts

    # Also handle records lacking timestamps: fall back to raw count threshold
    untimed_failed = [r for r in detect_failed_logins(records) if not r["timestamp"]]
    untimed_grouped = defaultdict(list)
    for r in untimed_failed:
        untimed_grouped[(r["user"], r["src_ip"])].append(r)
    for (user, ip), recs in untimed_grouped.items():
        if len(recs) >= threshold:
            findings.append({
                "user": user,
                "src_ip": ip,
                "attempt_count": len(recs),
                "first_seen": None,
                "last_seen": None,
                "records": recs,
            })

    return findings


def detect_multiple_ips(records, ip_threshold=3):
    """
    Flags users who authenticated (or attempted to) from >= ip_threshold
    distinct source IPs. Useful for detecting credential sharing,
    distributed brute force, or password spraying.
    """
    user_ips = defaultdict(set)
    user_records = defaultdict(list)
    for r in records:
        user_ips[r["user"]].add(r["src_ip"])
        user_records[r["user"]].append(r)

    findings = []
    for user, ips in user_ips.items():
        if len(ips) >= ip_threshold:
            findings.append({
                "user": user,
                "ip_count": len(ips),
                "ips": sorted(ips),
                "records": user_records[user],
            })
    return findings


def detect_successful_after_failures(records, min_failed=3, window_minutes=15):
    """
    Flags a successful login that follows >= min_failed failed attempts
    from the same (user, src_ip) within window_minutes - a classic
    'brute force finally succeeded' pattern.
    """
    window = timedelta(minutes=window_minutes)
    grouped = defaultdict(list)
    for r in records:
        if r["timestamp"]:
            grouped[(r["user"], r["src_ip"])].append(r)

    findings = []
    for key, recs in grouped.items():
        recs = sorted(recs, key=lambda r: r["timestamp"])
        fail_streak = 0
        streak_start = None
        for r in recs:
            if is_failed(r):
                if fail_streak == 0:
                    streak_start = r["timestamp"]
                fail_streak += 1
            elif is_success(r):
                if fail_streak >= min_failed and streak_start and \
                        (r["timestamp"] - streak_start) <= window:
                    findings.append({
                        "user": key[0],
                        "src_ip": key[1],
                        "failed_attempts": fail_streak,
                        "success_time": r["timestamp"],
                    })
                fail_streak = 0
                streak_start = None
    return findings


def count_event_ids(records):
    return Counter(r["event_id"] for r in records)


def count_by_ip(records):
    return Counter(r["src_ip"] for r in records)


def count_by_user(records):
    return Counter(r["user"] for r in records)


def timestamp_analysis(records):
    """
    Basic timestamp/time-of-day analysis: hourly activity distribution
    and off-hours (00:00-05:00) activity flag.
    """
    hourly = Counter()
    off_hours_events = []
    for r in records:
        if r["timestamp"]:
            hour = r["timestamp"].hour
            hourly[hour] += 1
            if 0 <= hour < 5:
                off_hours_events.append(r)
    return {
        "hourly_distribution": dict(sorted(hourly.items())),
        "off_hours_count": len(off_hours_events),
        "off_hours_events": off_hours_events,
    }
