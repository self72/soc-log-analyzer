"""
reporter_html.py
Generates a self-contained HTML SIEM-style dashboard using Jinja2 + Chart.js (via CDN).
"""

import json
from datetime import datetime
from jinja2 import Template

TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SOC Threat Detection Dashboard</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
  :root {
    --bg: #0d1117; --panel: #161b22; --border: #30363d;
    --text: #c9d1d9; --muted: #8b949e;
    --info: #58a6ff; --warning: #d29922; --error: #f0883e; --critical: #f85149;
  }
  * { box-sizing: border-box; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 24px; }
  h1 { font-size: 22px; margin-bottom: 4px; }
  .subtitle { color: var(--muted); margin-bottom: 24px; font-size: 13px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 16px; }
  .card .num { font-size: 28px; font-weight: 700; }
  .card .label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .05em; }
  .charts { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px; }
  @media (max-width: 900px) { .charts { grid-template-columns: 1fr; } }
  table { width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
  th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); font-size: 13px; }
  th { color: var(--muted); text-transform: uppercase; font-size: 11px; letter-spacing: .04em; }
  tr:last-child td { border-bottom: none; }
  .sev { padding: 2px 8px; border-radius: 6px; font-weight: 600; font-size: 11px; }
  .sev-INFO { background: rgba(88,166,255,.15); color: var(--info); }
  .sev-WARNING { background: rgba(210,153,34,.15); color: var(--warning); }
  .sev-ERROR { background: rgba(240,136,62,.15); color: var(--error); }
  .sev-CRITICAL { background: rgba(248,81,73,.15); color: var(--critical); }
  h2 { font-size: 15px; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; margin: 32px 0 12px; }
  canvas { max-height: 280px; }
</style>
</head>
<body>
  <h1>🛡️ SOC Threat Detection Dashboard</h1>
  <div class="subtitle">Generated {{ generated_at }} &middot; Source: {{ log_source }}</div>

  <div class="grid">
    <div class="card"><div class="num">{{ total_events }}</div><div class="label">Total Events</div></div>
    <div class="card"><div class="num">{{ failed_logins }}</div><div class="label">Failed Logins</div></div>
    <div class="card"><div class="num">{{ brute_force_count }}</div><div class="label">Brute Force Findings</div></div>
    <div class="card"><div class="num">{{ multi_ip_count }}</div><div class="label">Multi-IP Findings</div></div>
    <div class="card"><div class="num">{{ critical_count }}</div><div class="label">Critical Alerts</div></div>
  </div>

  <div class="charts">
    <div class="card"><canvas id="eventChart"></canvas></div>
    <div class="card"><canvas id="hourChart"></canvas></div>
  </div>

  <h2>Brute Force Findings</h2>
  <table>
    <tr><th>Severity</th><th>User</th><th>Source IP</th><th>Attempts</th><th>MITRE</th><th>First Seen</th><th>Last Seen</th></tr>
    {% for f in brute_force %}
    <tr>
      <td><span class="sev sev-{{ f.severity }}">{{ f.severity }}</span></td>
      <td>{{ f.user }}</td><td>{{ f.src_ip }}</td><td>{{ f.attempt_count }}</td>
      <td>{{ f.mitre }}</td><td>{{ f.first_seen }}</td><td>{{ f.last_seen }}</td>
    </tr>
    {% endfor %}
  </table>

  <h2>Multiple Source IP Findings</h2>
  <table>
    <tr><th>Severity</th><th>User</th><th>Distinct IPs</th><th>IP List</th><th>MITRE</th></tr>
    {% for f in multi_ip %}
    <tr>
      <td><span class="sev sev-{{ f.severity }}">{{ f.severity }}</span></td>
      <td>{{ f.user }}</td><td>{{ f.ip_count }}</td><td>{{ f.ips }}</td><td>{{ f.mitre }}</td>
    </tr>
    {% endfor %}
  </table>

  <h2>Event ID Breakdown</h2>
  <table>
    <tr><th>Event ID</th><th>Count</th></tr>
    {% for eid, count in event_counts %}
    <tr><td>{{ eid }}</td><td>{{ count }}</td></tr>
    {% endfor %}
  </table>

<script>
new Chart(document.getElementById('eventChart'), {
  type: 'bar',
  data: {
    labels: {{ event_labels | safe }},
    datasets: [{ label: 'Event Count', data: {{ event_values | safe }}, backgroundColor: '#58a6ff' }]
  },
  options: { plugins: { title: { display: true, text: 'Events by ID', color: '#c9d1d9' }, legend: { display: false } },
    scales: { x: { ticks: { color: '#8b949e' } }, y: { ticks: { color: '#8b949e' } } } }
});
new Chart(document.getElementById('hourChart'), {
  type: 'line',
  data: {
    labels: {{ hour_labels | safe }},
    datasets: [{ label: 'Events per Hour', data: {{ hour_values | safe }}, borderColor: '#f0883e', backgroundColor: 'rgba(240,136,62,.2)', fill: true, tension: .3 }]
  },
  options: { plugins: { title: { display: true, text: 'Activity by Hour of Day', color: '#c9d1d9' }, legend: { display: false } },
    scales: { x: { ticks: { color: '#8b949e' } }, y: { ticks: { color: '#8b949e' } } } }
});
</script>
</body>
</html>
"""


def build_dashboard(path, records, brute_force_findings, multi_ip_findings,
                     event_id_counts, hourly_distribution, log_source="log file"):
    from severity import severity_for_finding
    from mitre_mapping import get_mitre_info

    bf_rows = []
    for f in brute_force_findings:
        bf_rows.append({
            "severity": severity_for_finding("brute_force", attempt_count=f["attempt_count"]),
            "user": f["user"], "src_ip": f["src_ip"], "attempt_count": f["attempt_count"],
            "mitre": get_mitre_info("brute_force")["technique_id"],
            "first_seen": str(f["first_seen"] or ""), "last_seen": str(f["last_seen"] or ""),
        })

    mi_rows = []
    for f in multi_ip_findings:
        mi_rows.append({
            "severity": severity_for_finding("multiple_ips", ip_count=f["ip_count"]),
            "user": f["user"], "ip_count": f["ip_count"], "ips": ", ".join(f["ips"]),
            "mitre": get_mitre_info("multiple_ips")["technique_id"],
        })

    critical_count = sum(1 for r in bf_rows + mi_rows if r["severity"] == "CRITICAL")
    failed_count = sum(1 for r in records if r["status"].upper() in
                        {"FAILED", "FAIL", "FAILURE", "DENIED"} or r["event_id"] == "4625")

    event_labels = list(event_id_counts.keys())
    event_values = list(event_id_counts.values())
    hour_labels = [f"{h:02d}:00" for h in hourly_distribution.keys()]
    hour_values = list(hourly_distribution.values())

    html = Template(TEMPLATE).render(
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        log_source=log_source,
        total_events=len(records),
        failed_logins=failed_count,
        brute_force_count=len(bf_rows),
        multi_ip_count=len(mi_rows),
        critical_count=critical_count,
        brute_force=bf_rows,
        multi_ip=mi_rows,
        event_counts=event_id_counts.most_common(),
        event_labels=json.dumps(event_labels),
        event_values=json.dumps(event_values),
        hour_labels=json.dumps(hour_labels),
        hour_values=json.dumps(hour_values),
    )

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path
