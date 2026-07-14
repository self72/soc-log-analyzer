"""
live_monitor.py
Live log monitoring: watches a log file for new lines (tail -f style) and
runs brute-force / failed-login detection incrementally, printing alerts
as they occur in real time.

Uses simple polling (portable, no OS-specific dependencies). For very
high-volume logs, consider swapping to 'watchdog' filesystem events.
"""

import time
from datetime import datetime

from log_parser import parse_csv_log, parse_sshd_log, _looks_like_csv
from detectors import detect_brute_force, detect_failed_logins
from console import console, print_status


def _tail_new_lines(path, last_pos):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(last_pos)
        new_lines = f.readlines()
        new_pos = f.tell()
    return new_lines, new_pos


def watch_log(path, poll_seconds=3, brute_force_threshold=5, window_minutes=10):
    """
    Polls `path` for newly appended lines and re-runs brute-force detection
    on the accumulated in-memory record buffer. Press Ctrl+C to stop.
    """
    print_status(f"👁  Live monitoring started on {path} (poll every {poll_seconds}s). Ctrl+C to stop.", "green")

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        first_line = f.readline()
        last_pos = f.tell()

    is_csv = _looks_like_csv(first_line)
    buffer = []
    seen_alert_keys = set()

    try:
        while True:
            time.sleep(poll_seconds)
            new_lines, last_pos = _tail_new_lines(path, last_pos)
            if not new_lines:
                continue

            # Reuse the parser logic by writing new lines to a temp buffer approach:
            # simplest robust method is to re-parse whole file each poll for correctness,
            # but for large files we parse only new lines directly here.
            if is_csv:
                import csv
                import io
                for row in csv.reader(io.StringIO("".join(new_lines))):
                    if not row or len(row) < 5:
                        continue
                    row = [c.strip() for c in row] + [""] * (6 - len(row))
                    ts_raw, event_id, user, src_ip, status, message = row[:6]
                    from log_parser import _parse_ts
                    buffer.append({
                        "timestamp": _parse_ts(ts_raw), "timestamp_raw": ts_raw,
                        "event_id": event_id or "UNKNOWN", "user": user or "unknown",
                        "src_ip": src_ip or "0.0.0.0", "status": (status or "UNKNOWN").upper(),
                        "message": message, "raw": ",".join(row),
                    })
            else:
                from log_parser import SSHD_FAILED_RE, SSHD_ACCEPTED_RE, _parse_ts
                for line in new_lines:
                    m = SSHD_FAILED_RE.search(line)
                    if m:
                        buffer.append({
                            "timestamp": _parse_ts(m.group("ts")), "timestamp_raw": m.group("ts"),
                            "event_id": "4625", "user": m.group("user"), "src_ip": m.group("ip"),
                            "status": "FAILED", "message": "Failed password (sshd)", "raw": line,
                        })

            findings = detect_brute_force(buffer, threshold=brute_force_threshold,
                                           window_minutes=window_minutes)
            for f in findings:
                key = (f["user"], f["src_ip"], f["attempt_count"])
                if key not in seen_alert_keys:
                    seen_alert_keys.add(key)
                    console.print(
                        f"[bold red]🔴 LIVE ALERT[/bold red] Brute force: "
                        f"{f['user']} from {f['src_ip']} — {f['attempt_count']} attempts "
                        f"[{datetime.now().strftime('%H:%M:%S')}]"
                    )
    except KeyboardInterrupt:
        print_status("\n⏹  Live monitoring stopped.", "yellow")
