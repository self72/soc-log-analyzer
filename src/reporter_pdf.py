"""
reporter_pdf.py
Generates a PDF summary report using reportlab.
"""

from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                 TableStyle, PageBreak)

SEV_COLORS = {
    "INFO": colors.HexColor("#58a6ff"),
    "WARNING": colors.HexColor("#d29922"),
    "ERROR": colors.HexColor("#f0883e"),
    "CRITICAL": colors.HexColor("#f85149"),
}


def build_pdf_report(path, records, brute_force_findings, multi_ip_findings,
                      success_after_fail_findings, event_id_counts, log_source="log file"):
    from severity import severity_for_finding
    from mitre_mapping import get_mitre_info

    doc = SimpleDocTemplate(path, pagesize=A4,
                             topMargin=1.5 * cm, bottomMargin=1.5 * cm)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleX", parent=styles["Title"], fontSize=20)
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], spaceBefore=14, spaceAfter=6)
    normal = styles["Normal"]

    story = []
    story.append(Paragraph("🛡 SOC Threat Detection Report", title_style))
    story.append(Paragraph(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp; "
        f"Source: {log_source} &nbsp;|&nbsp; Total events analyzed: {len(records)}", normal))
    story.append(Spacer(1, 12))

    # Summary table
    failed_count = sum(1 for r in records if r["status"].upper() in
                        {"FAILED", "FAIL", "FAILURE", "DENIED"} or r["event_id"] == "4625")
    summary_data = [
        ["Metric", "Value"],
        ["Total Events", str(len(records))],
        ["Failed Logins", str(failed_count)],
        ["Brute Force Findings", str(len(brute_force_findings))],
        ["Multiple-IP Findings", str(len(multi_ip_findings))],
        ["Successful Login After Failures", str(len(success_after_fail_findings))],
    ]
    t = Table(summary_data, colWidths=[8 * cm, 6 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#161b22")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f2f2")]),
    ]))
    story.append(t)

    # Brute force findings
    story.append(Paragraph("Brute Force Findings", h2))
    if brute_force_findings:
        rows = [["Severity", "User", "Source IP", "Attempts", "MITRE", "First Seen", "Last Seen"]]
        for f in brute_force_findings:
            sev = severity_for_finding("brute_force", attempt_count=f["attempt_count"])
            mitre = get_mitre_info("brute_force")["technique_id"]
            rows.append([sev, f["user"], f["src_ip"], str(f["attempt_count"]), mitre,
                         str(f["first_seen"] or ""), str(f["last_seen"] or "")])
        bt = Table(rows, repeatRows=1, colWidths=[2.2 * cm, 2.4 * cm, 2.8 * cm, 1.8 * cm, 2 * cm, 3 * cm, 3 * cm])
        bt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#161b22")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ]))
        story.append(bt)
    else:
        story.append(Paragraph("No brute force activity detected.", normal))

    # Multi-IP findings
    story.append(Paragraph("Multiple Source IP Findings", h2))
    if multi_ip_findings:
        rows = [["Severity", "User", "Distinct IPs", "IP List", "MITRE"]]
        for f in multi_ip_findings:
            sev = severity_for_finding("multiple_ips", ip_count=f["ip_count"])
            mitre = get_mitre_info("multiple_ips")["technique_id"]
            rows.append([sev, f["user"], str(f["ip_count"]), ", ".join(f["ips"]), mitre])
        mt = Table(rows, repeatRows=1, colWidths=[2.2 * cm, 2.4 * cm, 2.2 * cm, 7 * cm, 2 * cm])
        mt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#161b22")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ]))
        story.append(mt)
    else:
        story.append(Paragraph("No multiple-IP anomalies detected.", normal))

    # Event ID breakdown
    story.append(Paragraph("Event ID Breakdown", h2))
    rows = [["Event ID", "Count"]] + [[eid, str(c)] for eid, c in event_id_counts.most_common()]
    et = Table(rows, colWidths=[6 * cm, 4 * cm])
    et.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#161b22")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
    ]))
    story.append(et)

    doc.build(story)
    return path
