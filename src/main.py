#!/usr/bin/env python3
"""
SOC Threat Detection & Log Analyzer
Main CLI entry point.

Usage:
  python main.py --log sample_logs/sample_auth.csv
  python main.py --log sample_logs/sample_auth.csv --html reports/dashboard.html --pdf reports/report.pdf
  python main.py --log sample_logs/sample_auth.csv --live
  python main.py --log sample_logs/sample_auth.csv --sigma-rules rules/sigma --yara-rules rules/yara
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from log_parser import parse_log_file
from detectors import (
    detect_failed_logins, detect_brute_force, detect_multiple_ips,
    detect_successful_after_failures, count_event_ids, timestamp_analysis,
)
from reporter_csv import write_csv_report
from reporter_html import build_dashboard
from reporter_pdf import build_pdf_report
from alerting import build_alert_messages, send_email_alert
from sigma_rules import run_sigma_rules
from yara_scan import scan_file, YARA_AVAILABLE
from threat_intel import enrich_ips
from console import (
    print_banner, print_summary, print_alerts, print_event_counts,
    print_sigma_results, print_status, console,
)


def parse_args():
    p = argparse.ArgumentParser(description="SOC Threat Detection & Log Analyzer")
    p.add_argument("--log", required=True, help="Path to the log file to analyze")
    p.add_argument("--brute-force-threshold", type=int, default=5,
                   help="Failed attempts within window to flag brute force (default: 5)")
    p.add_argument("--window-minutes", type=int, default=10,
                   help="Rolling time window in minutes for brute force detection (default: 10)")
    p.add_argument("--ip-threshold", type=int, default=3,
                   help="Distinct IPs per user to flag as suspicious (default: 3)")
    p.add_argument("--csv", help="Path to write CSV report")
    p.add_argument("--html", help="Path to write HTML dashboard")
    p.add_argument("--pdf", help="Path to write PDF report")
    p.add_argument("--sigma-rules", help="Directory containing Sigma-style YAML rules")
    p.add_argument("--yara-rules", help="Directory containing YARA .yar rules to scan the log file with")
    p.add_argument("--vt-api-key", help="VirusTotal API key for IP reputation lookups (or set VT_API_KEY env var)")
    p.add_argument("--email-alert", action="store_true", help="Send email alert for findings")
    p.add_argument("--smtp-host")
    p.add_argument("--smtp-port", type=int, default=587)
    p.add_argument("--smtp-user")
    p.add_argument("--smtp-pass")
    p.add_argument("--email-from")
    p.add_argument("--email-to", nargs="*", default=[])
    p.add_argument("--live", action="store_true", help="Live-monitor the log file for new brute force activity")
    p.add_argument("--live-poll-seconds", type=int, default=3)
    return p.parse_args()


def main():
    args = parse_args()
    print_banner()

    if args.live:
        from live_monitor import watch_log
        watch_log(args.log, poll_seconds=args.live_poll_seconds,
                   brute_force_threshold=args.brute_force_threshold,
                   window_minutes=args.window_minutes)
        return

    print_status(f"📄 Reading log file: {args.log}")
    records = parse_log_file(args.log)
    print_status(f"✔ Parsed {len(records)} events\n", "green")

    failed_logins = detect_failed_logins(records)
    brute_force_findings = detect_brute_force(
        records, threshold=args.brute_force_threshold, window_minutes=args.window_minutes)
    multi_ip_findings = detect_multiple_ips(records, ip_threshold=args.ip_threshold)
    success_after_fail = detect_successful_after_failures(records)
    event_id_counts = count_event_ids(records)
    ts_analysis = timestamp_analysis(records)

    print_summary(len(records), len(failed_logins), len(brute_force_findings), len(multi_ip_findings))
    print_event_counts(event_id_counts)

    if ts_analysis["off_hours_count"]:
        print_status(
            f"⏰ {ts_analysis['off_hours_count']} event(s) occurred during off-hours (00:00-05:00)",
            "yellow")

    alerts = build_alert_messages(brute_force_findings, multi_ip_findings, success_after_fail)
    print_alerts(alerts)

    # Sigma rules
    if args.sigma_rules:
        print_status(f"\n🔎 Running Sigma-style rules from {args.sigma_rules} ...")
        sigma_results = run_sigma_rules(args.sigma_rules, records)
        print_sigma_results(sigma_results)

    # YARA scan
    if args.yara_rules:
        print_status(f"\n🧬 Running YARA scan on {args.log} using rules from {args.yara_rules} ...")
        if not YARA_AVAILABLE:
            print_status("⚠ yara-python is not installed. Run: pip install yara-python", "yellow")
        else:
            result = scan_file(args.log, args.yara_rules)
            if result["available"] and result["matches"]:
                for m in result["matches"]:
                    console.print(f"[bold red]YARA MATCH:[/bold red] {m['rule']} tags={m['tags']}")
            elif result["available"]:
                print_status("✔ No YARA matches.", "green")
            else:
                print_status(f"⚠ YARA scan unavailable: {result['reason']}", "yellow")

    # Threat intel (VirusTotal)
    flagged_ips = list({f["src_ip"] for f in brute_force_findings})
    if flagged_ips and (args.vt_api_key or os.environ.get("VT_API_KEY")):
        print_status(f"\n🌐 Looking up {len(flagged_ips)} flagged IP(s) on VirusTotal ...")
        vt_results = enrich_ips(flagged_ips, api_key=args.vt_api_key)
        for ip, info in vt_results.items():
            if "error" in info:
                console.print(f"  {ip}: [dim]lookup failed ({info['error']})[/dim]")
            else:
                console.print(
                    f"  {ip}: [red]{info['malicious']} malicious[/red], "
                    f"[yellow]{info['suspicious']} suspicious[/yellow], "
                    f"{info['harmless']} harmless")

    # Reports
    if args.csv:
        write_csv_report(args.csv, brute_force_findings, multi_ip_findings, success_after_fail, event_id_counts)
        print_status(f"\n📊 CSV report written to {args.csv}", "green")

    if args.html:
        build_dashboard(args.html, records, brute_force_findings, multi_ip_findings,
                         event_id_counts, ts_analysis["hourly_distribution"], log_source=args.log)
        print_status(f"🖥  HTML dashboard written to {args.html}", "green")

    if args.pdf:
        build_pdf_report(args.pdf, records, brute_force_findings, multi_ip_findings,
                          success_after_fail, event_id_counts, log_source=args.log)
        print_status(f"📕 PDF report written to {args.pdf}", "green")

    # Email alert
    if args.email_alert:
        if not (args.smtp_host and args.email_from and args.email_to):
            print_status("⚠ --email-alert requires --smtp-host, --email-from, and --email-to", "yellow")
        else:
            ok = send_email_alert(
                args.smtp_host, args.smtp_port, args.smtp_user, args.smtp_pass,
                args.email_from, args.email_to, alerts)
            if ok:
                print_status(f"📧 Email alert sent to {', '.join(args.email_to)}", "green")

    console.print("\n[bold cyan]Analysis complete.[/bold cyan]")


if __name__ == "__main__":
    main()
