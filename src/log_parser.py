"""
log_parser.py
Parses security logs into a normalized list of LogRecord dicts.

Supported formats:
1. CSV format (recommended, produced by most SIEM exports):
   timestamp,event_id,user,src_ip,status,message
   Example:
   2026-07-10 08:15:32,4625,admin,192.168.1.10,FAILED,Failed password for admin

2. Raw Linux sshd auth.log lines (auto-detected fallback), e.g.:
   Jul 10 08:15:32 server sshd[1234]: Failed password for admin from 192.168.1.10 port 51515 ssh2
   Jul 10 08:16:01 server sshd[1234]: Accepted password for admin from 192.168.1.11 port 51520 ssh2
"""

import csv
import re
from datetime import datetime
from pathlib import Path

# Normalized record keys:
# timestamp (datetime), event_id (str), user (str), src_ip (str),
# status (str: SUCCESS/FAILED/UNKNOWN), message (str), raw (str)

# Timestamp can be either the classic syslog format ("Jul 10 08:15:01") or
# the modern ISO 8601 format used by rsyslog/journald on newer distros
# (e.g. Kali/Debian 12+): "2026-07-14T15:21:32.347389-04:00"
TS_PATTERN = (
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?"
    r"|\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})"
)

SSHD_FAILED_RE = re.compile(
    TS_PATTERN + r".*sshd.*Failed password for "
    r"(invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
)
SSHD_ACCEPTED_RE = re.compile(
    TS_PATTERN + r".*sshd.*Accepted password for "
    r"(?P<user>\S+) from (?P<ip>[\d.]+)"
)

CURRENT_YEAR = datetime.now().year


def _parse_ts(ts_str: str):
    ts_str = ts_str.strip()

    # Modern ISO 8601 with optional microseconds and timezone offset,
    # e.g. "2026-07-14T15:21:32.347389-04:00" (Kali/Debian 12+ journald format)
    try:
        dt = datetime.fromisoformat(ts_str)
        return dt.replace(tzinfo=None)  # normalize to naive local wall-clock time
    except ValueError:
        pass

    fmts = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
    ]
    for fmt in fmts:
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    # syslog-style "Jul 10 08:15:32" (no year)
    try:
        dt = datetime.strptime(ts_str, "%b %d %H:%M:%S")
        return dt.replace(year=CURRENT_YEAR)
    except ValueError:
        pass
    return None


def _looks_like_csv(first_line: str) -> bool:
    return "," in first_line and (
        "event_id" in first_line.lower() or first_line.count(",") >= 4
    )


def parse_csv_log(path: str):
    records = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        sample = f.readline()
        f.seek(0)
        has_header = "timestamp" in sample.lower() and "event_id" in sample.lower()
        reader = csv.reader(f)
        rows = list(reader)
        if has_header:
            rows = rows[1:]
        for row in rows:
            if not row or len(row) < 5:
                continue
            row = [c.strip() for c in row] + [""] * (6 - len(row))
            ts_raw, event_id, user, src_ip, status, message = row[:6]
            ts = _parse_ts(ts_raw)
            records.append({
                "timestamp": ts,
                "timestamp_raw": ts_raw,
                "event_id": event_id or "UNKNOWN",
                "user": user or "unknown",
                "src_ip": src_ip or "0.0.0.0",
                "status": (status or "UNKNOWN").upper(),
                "message": message,
                "raw": ",".join(row),
            })
    return records


def parse_sshd_log(path: str):
    records = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            m = SSHD_FAILED_RE.search(line)
            if m:
                records.append({
                    "timestamp": _parse_ts(m.group("ts")),
                    "timestamp_raw": m.group("ts"),
                    "event_id": "4625",
                    "user": m.group("user"),
                    "src_ip": m.group("ip"),
                    "status": "FAILED",
                    "message": "Failed password (sshd)",
                    "raw": line,
                })
                continue
            m = SSHD_ACCEPTED_RE.search(line)
            if m:
                records.append({
                    "timestamp": _parse_ts(m.group("ts")),
                    "timestamp_raw": m.group("ts"),
                    "event_id": "4624",
                    "user": m.group("user"),
                    "src_ip": m.group("ip"),
                    "status": "SUCCESS",
                    "message": "Accepted password (sshd)",
                    "raw": line,
                })
    return records


def parse_log_file(path: str):
    """Auto-detects format and returns normalized list of records."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        first_line = f.readline()

    if _looks_like_csv(first_line):
        records = parse_csv_log(path)
    else:
        records = parse_sshd_log(path)

    # Sort chronologically where possible (None timestamps go last, stable order preserved)
    records.sort(key=lambda r: (r["timestamp"] is None, r["timestamp"] or datetime.min))
    return records
