"""
reporter_csv.py
Generates a CSV report summarizing all findings.
"""

import csv


def write_csv_report(path, brute_force_findings, multi_ip_findings,
                      success_after_fail_findings, event_id_counts):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["finding_type", "severity", "user", "src_ip",
                          "detail", "mitre_technique", "first_seen", "last_seen"])

        from severity import severity_for_finding
        from mitre_mapping import get_mitre_info

        for bf in brute_force_findings:
            sev = severity_for_finding("brute_force", attempt_count=bf["attempt_count"])
            mitre = get_mitre_info("brute_force")
            writer.writerow([
                "brute_force", sev, bf["user"], bf["src_ip"],
                f'{bf["attempt_count"]} failed attempts',
                mitre["technique_id"],
                bf["first_seen"], bf["last_seen"],
            ])

        for mi in multi_ip_findings:
            sev = severity_for_finding("multiple_ips", ip_count=mi["ip_count"])
            mitre = get_mitre_info("multiple_ips")
            writer.writerow([
                "multiple_ips", sev, mi["user"], "; ".join(mi["ips"]),
                f'{mi["ip_count"]} distinct source IPs',
                mitre["technique_id"], "", "",
            ])

        for sf in success_after_fail_findings:
            mitre = get_mitre_info("successful_login_after_failures")
            writer.writerow([
                "successful_login_after_failures", "ERROR", sf["user"], sf["src_ip"],
                f'Login succeeded after {sf["failed_attempts"]} failed attempts',
                mitre["technique_id"], "", sf["success_time"],
            ])

        writer.writerow([])
        writer.writerow(["event_id", "count"])
        for eid, count in event_id_counts.most_common():
            writer.writerow([eid, count])

    return path
