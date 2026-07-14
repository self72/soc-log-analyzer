"""
alerting.py
Generates alerts for detected findings. Supports console output (via console.py)
and optional email alerts (SMTP) for CRITICAL/ERROR severity findings.
"""

import smtplib
import ssl
from email.mime.text import MIMEText


def build_alert_messages(brute_force_findings, multi_ip_findings, success_after_fail_findings):
    from severity import severity_for_finding
    from mitre_mapping import get_mitre_info

    alerts = []
    for f in brute_force_findings:
        sev = severity_for_finding("brute_force", attempt_count=f["attempt_count"])
        mitre = get_mitre_info("brute_force")
        alerts.append({
            "severity": sev,
            "title": f'Brute Force Detected: {f["user"]} from {f["src_ip"]}',
            "detail": f'{f["attempt_count"]} failed login attempts between '
                      f'{f["first_seen"]} and {f["last_seen"]}',
            "mitre": f'{mitre["technique_id"]} - {mitre["technique_name"]}',
        })

    for f in multi_ip_findings:
        sev = severity_for_finding("multiple_ips", ip_count=f["ip_count"])
        mitre = get_mitre_info("multiple_ips")
        alerts.append({
            "severity": sev,
            "title": f'Multiple Source IPs for {f["user"]}',
            "detail": f'{f["ip_count"]} distinct IPs: {", ".join(f["ips"])}',
            "mitre": f'{mitre["technique_id"]} - {mitre["technique_name"]}',
        })

    for f in success_after_fail_findings:
        mitre = get_mitre_info("successful_login_after_failures")
        alerts.append({
            "severity": "ERROR",
            "title": f'Login Succeeded After Failures: {f["user"]} from {f["src_ip"]}',
            "detail": f'{f["failed_attempts"]} failed attempts before success at {f["success_time"]}',
            "mitre": f'{mitre["technique_id"]} - {mitre["technique_name"]}',
        })

    from severity import rank
    alerts.sort(key=lambda a: rank(a["severity"]), reverse=True)
    return alerts


def send_email_alert(smtp_host, smtp_port, username, password, from_addr, to_addrs, alerts,
                      use_tls=True):
    """
    Sends a single email summarizing all alerts. Caller must supply valid SMTP
    credentials (e.g. via environment variables / CLI args) - none are hardcoded here.
    Returns True on success, False otherwise (and prints the error).
    """
    if not alerts:
        return False

    lines = [f'[{a["severity"]}] {a["title"]} — {a["detail"]} (MITRE {a["mitre"]})'
              for a in alerts]
    body = "SOC Threat Detection Alert Summary\n\n" + "\n".join(lines)
    msg = MIMEText(body)
    msg["Subject"] = f"[SOC ALERT] {len(alerts)} finding(s) detected"
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs)

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            if use_tls:
                server.starttls(context=context)
            if username and password:
                server.login(username, password)
            server.sendmail(from_addr, to_addrs, msg.as_string())
        return True
    except Exception as exc:  # noqa: BLE001
        print(f"[!] Email alert failed: {exc}")
        return False
