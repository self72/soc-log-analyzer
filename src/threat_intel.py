"""
threat_intel.py
Optional VirusTotal integration: looks up reputation for source IPs
flagged by the brute force / multi-IP detectors.

Requires a VirusTotal API key (set via --vt-api-key or the VT_API_KEY
environment variable). Free-tier VT API has a strict rate limit
(4 req/min) - this module sleeps between calls accordingly.

If no API key is supplied, this module is skipped gracefully.
"""

import os
import time
import requests

VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"


def lookup_ip_reputation(ip, api_key):
    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(VT_URL.format(ip=ip), headers=headers, timeout=10)
        if resp.status_code != 200:
            return {"ip": ip, "error": f"HTTP {resp.status_code}"}
        data = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {
            "ip": ip,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        }
    except requests.RequestException as exc:
        return {"ip": ip, "error": str(exc)}


def enrich_ips(ip_list, api_key=None, rate_limit_seconds=15):
    """
    Looks up each IP against VirusTotal. Returns dict ip -> result.
    api_key defaults to the VT_API_KEY environment variable.
    Skips entirely (returns {}) if no key is available.
    """
    api_key = api_key or os.environ.get("VT_API_KEY")
    if not api_key:
        return {}

    results = {}
    for i, ip in enumerate(sorted(set(ip_list))):
        results[ip] = lookup_ip_reputation(ip, api_key)
        if i < len(ip_list) - 1:
            time.sleep(rate_limit_seconds)  # respect free-tier rate limits
    return results
