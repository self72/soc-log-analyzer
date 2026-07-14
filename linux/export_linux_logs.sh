#!/usr/bin/env bash
#
# export_linux_logs.sh
# Exports real Linux authentication logs (SSH logins) directly into the
# SOC Threat Detection & Log Analyzer's standard CSV format:
#   timestamp,event_id,user,src_ip,status,message
#
# Auto-detects the log source in this order:
#   1. /var/log/auth.log        (Debian, Ubuntu)
#   2. /var/log/secure          (RHEL, CentOS, Fedora, Amazon Linux)
#   3. journalctl -u sshd       (systemd-only systems with no log file, e.g. some
#                                 minimal/containerized distros)
#
# Usage:
#   ./linux/export_linux_logs.sh                       # writes ./linux_auth_log.csv
#   ./linux/export_linux_logs.sh -o my_export.csv       # custom output path
#   ./linux/export_linux_logs.sh -d 3                   # only last 3 days (journalctl mode only)
#
# Reading /var/log/auth.log or /var/log/secure typically requires root,
# so run with sudo if you get a permission error:
#   sudo ./linux/export_linux_logs.sh
#
# Then analyze it:
#   python3 src/main.py --log linux_auth_log.csv --html reports/dashboard.html

set -euo pipefail

OUTPUT_PATH="linux_auth_log.csv"
DAYS_BACK=7

usage() {
    echo "Usage: $0 [-o output.csv] [-d days_back]"
    echo "  -o   Output CSV path (default: linux_auth_log.csv)"
    echo "  -d   Days of history to pull when using journalctl fallback (default: 7)"
    exit 1
}

while getopts "o:d:h" opt; do
    case "$opt" in
        o) OUTPUT_PATH="$OPTARG" ;;
        d) DAYS_BACK="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CONVERTER="$PROJECT_ROOT/src/convert_to_csv.py"

if [ ! -f "$CONVERTER" ]; then
    echo "[!] Could not find src/convert_to_csv.py relative to this script. Run from the project root." >&2
    exit 1
fi

TMP_LOG=""
cleanup() { [ -n "$TMP_LOG" ] && rm -f "$TMP_LOG"; }
trap cleanup EXIT

if [ -r /var/log/auth.log ]; then
    echo "Found /var/log/auth.log (Debian/Ubuntu style). Converting..."
    python3 "$CONVERTER" --input /var/log/auth.log --output "$OUTPUT_PATH" --format sshd

elif [ -r /var/log/secure ]; then
    echo "Found /var/log/secure (RHEL/CentOS/Fedora style). Converting..."
    python3 "$CONVERTER" --input /var/log/secure --output "$OUTPUT_PATH" --format sshd

elif command -v journalctl >/dev/null 2>&1; then
    echo "No log file found - falling back to 'journalctl -u sshd' (last $DAYS_BACK day(s))..."
    TMP_LOG="$(mktemp)"
    if journalctl -u sshd --since "-${DAYS_BACK}days" --no-pager > "$TMP_LOG" 2>/dev/null && [ -s "$TMP_LOG" ]; then
        python3 "$CONVERTER" --input "$TMP_LOG" --output "$OUTPUT_PATH" --format sshd
    elif journalctl -u ssh --since "-${DAYS_BACK}days" --no-pager > "$TMP_LOG" 2>/dev/null && [ -s "$TMP_LOG" ]; then
        python3 "$CONVERTER" --input "$TMP_LOG" --output "$OUTPUT_PATH" --format sshd
    else
        echo "[!] journalctl returned no sshd/ssh unit logs. Try: sudo journalctl -u sshd" >&2
        exit 1
    fi

else
    echo "[!] No readable auth log found (/var/log/auth.log, /var/log/secure) and journalctl is unavailable." >&2
    echo "    If you have permission issues, try running this script with sudo." >&2
    exit 1
fi

echo ""
echo "Export complete -> $OUTPUT_PATH"
echo ""
echo "Next step:"
echo "  python3 src/main.py --log \"$OUTPUT_PATH\" --html reports/dashboard.html --csv reports/report.csv"
