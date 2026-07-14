# 🛡️ SOC Threat Detection & Log Analyzer

A Python-based SOC log analysis tool for detecting brute force attacks, suspicious
authentication patterns, and generating analyst-ready reports (CSV / HTML dashboard / PDF).

## Features (Phase 1)

- 📄 Read log files (CSV format or raw Linux `sshd` auth.log, auto-detected)
- ❌ Detect failed logins
- 🔴 Detect brute force (N+ failed logins within a rolling time window)
- 🌍 Detect multiple source IPs per user account
- 🔢 Count events by Event ID
- 📊 Generate CSV report
- 🚨 Generate console alerts
- 🎨 Colorful terminal output (via `rich`)
- ⏰ Timestamp / off-hours activity analysis

## Features (Phase 2)

| Feature | Status |
|---|---|
| 🔴 Brute Force Detection (5+ failed logins = Alert) | ✅ |
| 🟡 Severity Levels (INFO / WARNING / ERROR / CRITICAL) | ✅ |
| 🟢 MITRE ATT&CK Technique Mapping | ✅ |
| 🔵 Threat Intelligence (VirusTotal API integration) | ✅ (needs your API key) |
| 🟣 Email Alerts | ✅ (needs your SMTP credentials) |
| 🟠 HTML Dashboard | ✅ |
| ⚫ PDF Report Generation | ✅ |
| 🟤 Interactive Charts | ✅ (Chart.js, embedded in HTML dashboard) |
| ⚪ Live Log Monitoring | ✅ |
| 🟢 Sigma Rule Support | ✅ (simplified Sigma-style YAML engine) |
| 🔵 YARA Rule Scanning | ✅ (optional, requires `yara-python`) |
| 🟣 SIEM-style Dashboard | ✅ (same as HTML dashboard) |
| 🟠 Docker Support | ✅ |
| ⚫ GitHub Actions (CI/CD) | ✅ |

## Project Structure

```
soc-log-analyzer/
├── src/
│   ├── main.py           # CLI entry point
│   ├── log_parser.py     # CSV + sshd log parsing
│   ├── detectors.py      # Brute force / multi-IP / event-count detection
│   ├── severity.py       # INFO/WARNING/ERROR/CRITICAL classification
│   ├── mitre_mapping.py  # MITRE ATT&CK technique mapping
│   ├── alerting.py       # Console + email alerts
│   ├── sigma_rules.py    # Simplified Sigma rule engine
│   ├── yara_scan.py      # Optional YARA scanning
│   ├── threat_intel.py   # VirusTotal IP reputation lookups
│   ├── reporter_csv.py   # CSV report writer
│   ├── reporter_html.py  # HTML/SIEM dashboard writer
│   ├── reporter_pdf.py   # PDF report writer
│   ├── console.py        # Colorful terminal output (rich)
│   ├── live_monitor.py   # Live log tailing + real-time alerts
│   ├── generate_logs.py  # Synthetic test log generator
│   └── convert_to_csv.py # Converts raw/real logs into standard CSV format
├── rules/
│   ├── sigma/             # Sigma-style detection rules (YAML)
│   └── yara/               # YARA rules for log string scanning
├── sample_logs/           # Example CSV and sshd logs for testing
├── windows/
│   └── export_windows_logs.ps1  # Pulls real Windows Security log -> standard CSV
├── linux/
│   └── export_linux_logs.sh     # Pulls real Linux auth.log/journalctl -> standard CSV
├── reports/                # Generated CSV/HTML/PDF reports land here
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── .github/workflows/ci.yml
```

## 🆕 Generate Test Logs / Convert Real Logs to CSV

Two helper scripts were added alongside the main analyzer:

### 1. `generate_logs.py` — create realistic synthetic logs for testing

Generates a mix of normal logins, isolated typos, brute-force bursts, and
password-spray/multi-IP patterns — no real data involved, purely synthetic.

```bash
# Basic: 300 normal events + 3 brute-force bursts + 2 spray patterns
python src/generate_logs.py --output sample_logs/generated.csv --events 300 \
  --brute-force-bursts 3 --spray-users 2 --seed 42

# Generate in raw sshd auth.log format instead
python src/generate_logs.py --output sample_logs/generated.log --format sshd --events 300

# Then analyze it like any other log
python src/main.py --log sample_logs/generated.csv --html reports/dashboard.html
```

| Flag | Purpose |
|---|---|
| `--events` | Number of normal background events |
| `--brute-force-bursts` | Number of injected brute-force attack bursts |
| `--spray-users` | Number of injected password-spray / multi-IP patterns |
| `--days-back` | Spread events over this many past days |
| `--seed` | Fixed seed for reproducible output |
| `--format` | `csv` (default) or `sshd` |

### 2. `convert_to_csv.py` — convert real/raw logs into the analyzer's standard CSV

Converts a raw `sshd` auth.log, or any CSV export with differently-named
columns (e.g. a Windows Event Log export), into the standard
`timestamp,event_id,user,src_ip,status,message` format the analyzer expects.

```bash
# Convert a raw Linux sshd auth.log
python src/convert_to_csv.py --input /var/log/auth.log --output sample_logs/converted.csv

# Convert a Windows Event Log CSV export with custom column names
python src/convert_to_csv.py --input winlogs.csv --output sample_logs/converted.csv \
  --col-timestamp "TimeCreated" --col-event-id "EventID" \
  --col-user "TargetUserName" --col-ip "IpAddress" \
  --col-status "Keywords" --col-message "Description"

# Then run the analyzer on the converted file
python src/main.py --log sample_logs/converted.csv --html reports/dashboard.html
```

If input format isn't specified, it's auto-detected (`--format auto` is the default);
force it with `--format sshd` or `--format csv` if detection guesses wrong.

### 3. `windows/export_windows_logs.ps1` — pull REAL logs directly from Windows

This is the one you want if you're on a Windows machine and want your
**actual Security event log** (real logon activity), not a sample. Run
PowerShell **as Administrator**:

```powershell
cd soc-log-analyzer
.\windows\export_windows_logs.ps1 -OutputPath windows_auth_log.csv -DaysBack 7
```

It queries the Windows Security log directly (`Get-WinEvent`) for logon-related
events — 4624 (success), 4625 (failure), 4634 (logoff), 4648, 4672, 4771, 4776 —
extracts the real username and source IP from each event, and writes them
straight into the analyzer's standard CSV format. No manual conversion needed.

```powershell
python src\main.py --log windows_auth_log.csv --html reports\dashboard.html --csv reports\report.csv
```

| Parameter | Purpose |
|---|---|
| `-OutputPath` | Where to save the CSV (default: `windows_auth_log.csv`) |
| `-DaysBack` | How many days of history to pull (default: 7) |
| `-MaxEvents` | Safety cap on events exported (default: 5000) |

**Note:** reading the Security log requires Administrator privileges — that's
a Windows restriction, not something this script can bypass.

### 4. `linux/export_linux_logs.sh` — pull REAL logs directly from Linux

The Linux equivalent of the script above. Auto-detects your log source and
converts it straight to the standard CSV format in one step:

```bash
cd soc-log-analyzer
chmod +x linux/export_linux_logs.sh
sudo ./linux/export_linux_logs.sh -o linux_auth_log.csv -d 7
```

It checks, in order:
1. `/var/log/auth.log` (Debian, Ubuntu)
2. `/var/log/secure` (RHEL, CentOS, Fedora, Amazon Linux)
3. `journalctl -u sshd` / `journalctl -u ssh` (systemd-only systems with no log file)

Then analyze it:

```bash
python3 src/main.py --log linux_auth_log.csv --html reports/dashboard.html --csv reports/report.csv
```

| Flag | Purpose |
|---|---|
| `-o` | Output CSV path (default: `linux_auth_log.csv`) |
| `-d` | Days of history to pull, used only in the `journalctl` fallback (default: 7) |

**Note:** reading `/var/log/auth.log` or `/var/log/secure` requires root — run
with `sudo` if you hit a permission error.

### 5. Already have an exported `.evtx` file? Convert it with `convert_to_csv.py`

If someone already exported a `.evtx` file (e.g. via Event Viewer → "Save All
Events As...", or copied `Security.evtx` from `C:\Windows\System32\winevt\Logs\`),
convert it directly — this works cross-platform, including on Linux/Mac:

```bash
pip install python-evtx
python src/convert_to_csv.py --input Security.evtx --output sample_logs/converted.csv
python src/main.py --log sample_logs/converted.csv --html reports/dashboard.html
```

## Installation

### Linux / macOS

```bash
git clone <your-repo-url>
cd soc-log-analyzer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Windows (PowerShell)

```powershell
git clone <your-repo-url>
cd soc-log-analyzer
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

If PowerShell blocks the venv activation script or `.ps1` scripts in this repo
with an "UnauthorizedAccess" / "not digitally signed" error, unblock and allow
them for your session:

```powershell
Unblock-File -Path .\windows\export_windows_logs.ps1
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Optional (for YARA scanning): `pip install yara-python` (requires build tools on some platforms).

## Usage

### Basic analysis

```bash
python src/main.py --log sample_logs/sample_auth.csv
```

### Full report generation

```bash
python src/main.py --log sample_logs/sample_auth.csv \
  --csv reports/report.csv \
  --html reports/dashboard.html \
  --pdf reports/report.pdf
```

### With Sigma + YARA rules

```bash
python src/main.py --log sample_logs/sample_auth.csv \
  --sigma-rules rules/sigma \
  --yara-rules rules/yara
```

### Threat intelligence (VirusTotal)

```bash
export VT_API_KEY=your_api_key_here
python src/main.py --log sample_logs/sample_auth.csv
```

### Email alerts

```bash
python src/main.py --log sample_logs/sample_auth.csv \
  --email-alert \
  --smtp-host smtp.gmail.com --smtp-port 587 \
  --smtp-user you@example.com --smtp-pass "app-password" \
  --email-from you@example.com --email-to soc-team@example.com
```

### Live monitoring (tail -f style)

```bash
python src/main.py --log /var/log/auth.log --live
```

### Tuning detection thresholds

```bash
python src/main.py --log sample_logs/sample_auth.csv \
  --brute-force-threshold 5 --window-minutes 10 --ip-threshold 3
```

## Log Format

The tool auto-detects between two formats:

**1. CSV (recommended)** — `timestamp,event_id,user,src_ip,status,message`
```
2026-07-10 08:15:01,4625,admin,203.0.113.55,FAILED,Failed password for admin
```

**2. Raw Linux `sshd` auth.log** (regex-parsed fallback)
```
Jul 10 08:15:01 webserver sshd[1234]: Failed password for admin from 203.0.113.55 port 51515 ssh2
```

## Docker

```bash
docker build -t soc-log-analyzer .
docker run --rm -v $(pwd)/reports:/app/reports soc-log-analyzer

# or with docker-compose
docker-compose up --build
```

Mount your own logs and point `--log` at the mounted path:

```bash
docker run --rm \
  -v $(pwd)/mylogs:/app/logs \
  -v $(pwd)/reports:/app/reports \
  soc-log-analyzer \
  --log /app/logs/auth.log --html /app/reports/dashboard.html
```

## MITRE ATT&CK Mapping

| Finding | Technique | Tactic |
|---|---|---|
| Failed login | T1110.001 Password Guessing | Credential Access |
| Brute force | T1110 Brute Force | Credential Access |
| Multiple IPs per user | T1078 Valid Accounts | Defense Evasion / Persistence / Initial Access |
| Successful login after failures | T1078 Valid Accounts | Initial Access |

## CI/CD

GitHub Actions (`.github/workflows/ci.yml`) runs on every push/PR:
- Installs dependencies across Python 3.10–3.12
- Lints with flake8
- Runs smoke tests against both sample log formats
- Builds and smoke-tests the Docker image
- Uploads generated reports as build artifacts

## Notes & Limitations

- VirusTotal free-tier API is rate-limited (4 req/min) — the tool paces lookups accordingly.
- Email alerting requires your own SMTP credentials; none are bundled or hardcoded.
- YARA scanning requires the optional `yara-python` package; the tool degrades gracefully if it's absent.
- Sigma rule support here is a simplified subset (equality / contains / startswith on a single
  selection block) intended for quick SOC triage rules, not full Sigma spec compliance.
