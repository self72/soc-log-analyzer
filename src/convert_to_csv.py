#!/usr/bin/env python3
"""
convert_to_csv.py
Converts a raw log file (Linux sshd auth.log, Windows .evtx event log,
generic delimited text, or a Windows Event Log CSV export with different
column names) into the analyzer's standard CSV format:

    timestamp,event_id,user,src_ip,status,message

Usage:
  # Auto-detect sshd-style syslog and convert:
  python src/convert_to_csv.py --input /var/log/auth.log --output sample_logs/converted.csv

  # Convert a raw Windows .evtx file (e.g. Security.evtx) directly:
  python src/convert_to_csv.py --input Security.evtx --output sample_logs/converted.csv
  # (requires: pip install python-evtx)

  # Convert a Windows Event Log CSV export, mapping its column names:
  python src/convert_to_csv.py --input winlogs.csv --output sample_logs/converted.csv \
      --col-timestamp "TimeCreated" --col-event-id "EventID" \
      --col-user "TargetUserName" --col-ip "IpAddress" --col-status "Keywords"

  # If it's already in a CSV with columns in a different order, just
  # remap the column names - no need to touch the data by hand.
"""

import argparse
import csv
import sys
import os
import re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from log_parser import parse_sshd_log, _looks_like_csv, _parse_ts  # noqa: E402

WINDOWS_FAILED_EVENT_IDS = {"4625", "4771", "4776"}
WINDOWS_SUCCESS_EVENT_IDS = {"4624", "4768", "4769"}
WINDOWS_LOGON_EVENT_IDS = {"4624", "4625", "4634", "4648", "4672", "4771", "4776", "4768", "4769"}


def infer_status(event_id, raw_status_value):
    """Best-effort status inference when the source doesn't have a clean status column."""
    if raw_status_value:
        v = raw_status_value.strip().upper()
        if any(k in v for k in ("FAIL", "DENIED", "ERROR", "AUDIT FAILURE")):
            return "FAILED"
        if any(k in v for k in ("SUCCESS", "OK", "ACCEPTED", "AUDIT SUCCESS")):
            return "SUCCESS"
    if event_id in WINDOWS_FAILED_EVENT_IDS:
        return "FAILED"
    if event_id in WINDOWS_SUCCESS_EVENT_IDS:
        return "SUCCESS"
    return "UNKNOWN"


def convert_evtx(input_path, output_path, event_ids=None):
    """
    Parses a raw Windows .evtx file (e.g. exported from Event Viewer or
    copied from C:\\Windows\\System32\\winevt\\Logs\\Security.evtx) and
    converts logon-related events into the standard CSV format.

    Requires the optional 'python-evtx' package:
        pip install python-evtx
    """
    try:
        import Evtx.Evtx as evtx
    except ImportError:
        print("[!] .evtx parsing requires the 'python-evtx' package.")
        print("    Install it with: pip install python-evtx")
        sys.exit(1)

    import xml.etree.ElementTree as ET

    event_ids = event_ids or WINDOWS_LOGON_EVENT_IDS
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    records = []

    with evtx.Evtx(input_path) as log:
        for record in log.records():
            try:
                root = ET.fromstring(record.xml())
            except ET.ParseError:
                continue

            system = root.find("e:System", ns)
            if system is None:
                continue
            eid_el = system.find("e:EventID", ns)
            if eid_el is None or eid_el.text is None:
                continue
            event_id = eid_el.text.strip()
            if event_id not in event_ids:
                continue

            time_el = system.find("e:TimeCreated", ns)
            ts_raw = time_el.get("SystemTime") if time_el is not None else ""
            ts = _parse_ts(ts_raw.replace("T", " ").split(".")[0]) if ts_raw else None
            ts_display = ts.strftime("%Y-%m-%d %H:%M:%S") if ts else ts_raw

            field_values = {}
            event_data = root.find("e:EventData", ns)
            if event_data is not None:
                for data_el in event_data.findall("e:Data", ns):
                    name = data_el.get("Name")
                    if name:
                        field_values[name] = (data_el.text or "").strip()

            user = field_values.get("TargetUserName") or field_values.get("SubjectUserName") or "unknown"
            ip = field_values.get("IpAddress", "")
            if not ip or ip in ("-", "::1"):
                ip = "127.0.0.1"

            status = "FAILED" if event_id in WINDOWS_FAILED_EVENT_IDS else "SUCCESS"

            records.append({
                "timestamp_raw": ts_display,
                "event_id": event_id,
                "user": user,
                "src_ip": ip,
                "status": status,
                "message": f"Windows Security Event {event_id}",
            })

    _write_standard_csv(records, output_path, already_normalized=True)
    return len(records)


def convert_sshd(input_path, output_path):
    records = parse_sshd_log(input_path)
    _write_standard_csv(records, output_path)
    return len(records)


def convert_generic_csv(input_path, output_path, col_map):
    """
    col_map: dict with keys 'timestamp','event_id','user','ip','status','message'
    mapped to the ACTUAL column header names in the input file.
    Any mapping left as None will be filled with a sensible default/blank.
    """
    with open(input_path, "r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    records = []
    for row in rows:
        ts_raw = row.get(col_map["timestamp"], "") if col_map.get("timestamp") else ""
        event_id = row.get(col_map["event_id"], "") if col_map.get("event_id") else "UNKNOWN"
        user = row.get(col_map["user"], "") if col_map.get("user") else "unknown"
        ip = row.get(col_map["ip"], "") if col_map.get("ip") else "0.0.0.0"
        raw_status = row.get(col_map["status"], "") if col_map.get("status") else ""
        message = row.get(col_map["message"], "") if col_map.get("message") else ""

        status = infer_status(event_id, raw_status)
        records.append({
            "timestamp_raw": ts_raw,
            "event_id": event_id or "UNKNOWN",
            "user": user or "unknown",
            "src_ip": ip or "0.0.0.0",
            "status": status,
            "message": message or raw_status,
        })

    _write_standard_csv(records, output_path, already_normalized=True)
    return len(records)


def _write_standard_csv(records, output_path, already_normalized=False):
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "event_id", "user", "src_ip", "status", "message"])
        for r in records:
            ts = r.get("timestamp_raw") or r.get("timestamp") or ""
            writer.writerow([ts, r["event_id"], r["user"], r["src_ip"], r["status"], r["message"]])


def parse_args():
    p = argparse.ArgumentParser(
        description="Convert raw log files into the SOC analyzer's standard CSV format")
    p.add_argument("--input", required=True, help="Path to the raw input log file")
    p.add_argument("--output", required=True, help="Path to write the standardized CSV")
    p.add_argument("--format", choices=["auto", "sshd", "csv", "evtx"], default="auto",
                   help="Force input format instead of auto-detecting (default: auto)")
    p.add_argument("--col-timestamp", help="Column name for timestamp (generic CSV input)")
    p.add_argument("--col-event-id", help="Column name for event ID (generic CSV input)")
    p.add_argument("--col-user", help="Column name for username (generic CSV input)")
    p.add_argument("--col-ip", help="Column name for source IP (generic CSV input)")
    p.add_argument("--col-status", help="Column name for status/result (generic CSV input)")
    p.add_argument("--col-message", help="Column name for message/description (generic CSV input)")
    return p.parse_args()


def main():
    args = parse_args()

    if not os.path.exists(args.input):
        print(f"[!] Input file not found: {args.input}")
        sys.exit(1)

    fmt = args.format
    if fmt == "auto":
        if args.input.lower().endswith(".evtx"):
            fmt = "evtx"
        else:
            with open(args.input, "r", encoding="utf-8", errors="replace") as f:
                first_line = f.readline()
            fmt = "csv" if _looks_like_csv(first_line) else "sshd"

    if fmt == "evtx":
        count = convert_evtx(args.input, args.output)
        print(f"✔ Converted {count} Windows event log entries -> {args.output}")
        return

    if fmt == "sshd":
        count = convert_sshd(args.input, args.output)
        print(f"✔ Converted {count} sshd events -> {args.output}")
        return

    # generic CSV path — needs column mapping
    if not any([args.col_timestamp, args.col_event_id, args.col_user, args.col_ip]):
        # Try the already-standard column names first
        with open(args.input, "r", encoding="utf-8", errors="replace") as f:
            header = f.readline().lower()
        if "timestamp" in header and "event_id" in header and "user" in header:
            col_map = {"timestamp": "timestamp", "event_id": "event_id", "user": "user",
                       "ip": "src_ip", "status": "status", "message": "message"}
        else:
            print("[!] Generic CSV input detected but no column mapping supplied.")
            print("    Pass --col-timestamp/--col-event-id/--col-user/--col-ip/--col-status/--col-message")
            print(f"    Detected header: {header.strip()}")
            sys.exit(1)
    else:
        col_map = {
            "timestamp": args.col_timestamp, "event_id": args.col_event_id,
            "user": args.col_user, "ip": args.col_ip,
            "status": args.col_status, "message": args.col_message,
        }

    count = convert_generic_csv(args.input, args.output, col_map)
    print(f"✔ Converted {count} events -> {args.output}")


if __name__ == "__main__":
    main()
