import requests
import config

# ── VirusTotal ──────────────────────────────────────────────
def check_virustotal(ioc):
    """
    Queries VirusTotal for any IOC type — IP, domain, or file hash.
    VirusTotal uses different endpoints for each type, so we detect
    the type first and route accordingly.
    """
    headers = {"x-apikey": config.VIRUSTOTAL_API_KEY}

    # Detect IOC type and build the correct endpoint
    if len(ioc) in [32, 40, 64]:  # MD5, SHA1, SHA256 hash lengths
        url = f"https://www.virustotal.com/api/v3/files/{ioc}"
    elif any(c.isalpha() for c in ioc) and "." in ioc:  # domain
        url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
    else:  # IP address
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values())
        return {
            "source": "VirusTotal",
            "malicious_engines": malicious,
            "suspicious_engines": suspicious,
            "total_engines": total,
            "raw_stats": stats
        }
    else:
        return {"source": "VirusTotal", "error": f"Status {response.status_code}"}


# ── AbuseIPDB ───────────────────────────────────────────────
def check_abuseipdb(ip):
    """
    Queries AbuseIPDB for IP reputation. Only works on IPs —
    we skip this check for domains and hashes.
    """
    # Skip if not an IP address
    if any(c.isalpha() for c in ip):
        return {"source": "AbuseIPDB", "skipped": "Not an IP address"}

    headers = {"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    response = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers=headers,
        params=params
    )

    if response.status_code == 200:
        data = response.json()["data"]
        return {
            "source": "AbuseIPDB",
            "abuse_confidence_score": data["abuseConfidenceScore"],
            "total_reports": data["totalReports"],
            "country": data["countryCode"],
            "isp": data["isp"],
            "is_tor": data.get("isTor", False)
        }
    else:
        return {"source": "AbuseIPDB", "error": f"Status {response.status_code}"}


# ── Scoring ─────────────────────────────────────────────────
def score_ioc(vt_result, abuse_result):
    """
    Takes results from both sources and produces a single
    verdict: MALICIOUS, SUSPICIOUS, or CLEAN.

    Logic:
    - MALICIOUS: 3+ VT engines flag it, or AbuseIPDB score >= 50
    - SUSPICIOUS: 1-2 VT engines flag it, or AbuseIPDB score 10-49
    - CLEAN: nothing flags it
    """
    score = 0

    if "error" not in vt_result:
        score += vt_result.get("malicious_engines", 0) * 2
        score += vt_result.get("suspicious_engines", 0) * 1

    if "error" not in abuse_result and "skipped" not in abuse_result:
        abuse_score = abuse_result.get("abuse_confidence_score", 0)
        if abuse_score >= 50:
            score += 10
        elif abuse_score >= 10:
            score += 3

    if score >= 6:
        return "MALICIOUS"
    elif score >= 1:
        return "SUSPICIOUS"
    else:
        return "CLEAN"