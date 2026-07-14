"""
mitre_mapping.py
Maps detection finding types to MITRE ATT&CK techniques.
Reference: https://attack.mitre.org/
"""

MITRE_MAP = {
    "failed_login": {
        "technique_id": "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
    },
    "brute_force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
    },
    "multiple_ips": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Defense Evasion / Persistence / Initial Access",
    },
    "password_spraying": {
        "technique_id": "T1110.003",
        "technique_name": "Brute Force: Password Spraying",
        "tactic": "Credential Access",
    },
    "successful_login_after_failures": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts (post-brute-force success)",
        "tactic": "Initial Access",
    },
}


def get_mitre_info(finding_type: str):
    return MITRE_MAP.get(finding_type, {
        "technique_id": "N/A",
        "technique_name": "Unmapped",
        "tactic": "N/A",
    })
