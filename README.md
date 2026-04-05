# IOC Enrichment & Alert Triage Automation

A Python tool that automates the enrichment and triage of Indicators of Compromise (IOCs) — IPs, domains, and file hashes — by querying VirusTotal and AbuseIPDB in parallel and producing a scored, color-coded triage report.

Built to replicate the manual enrichment workflow a SOC analyst performs on every alert, and compress it into a single automated run.

## What It Does

- Accepts a mixed list of IOCs from `iocs.txt` — IPs, domains, MD5/SHA1/SHA256 hashes
- Automatically detects IOC type and routes to the correct VirusTotal endpoint
- Queries AbuseIPDB for IP reputation, confidence score, and abuse history
- Scores each IOC using a weighted logic model and returns a verdict: MALICIOUS, SUSPICIOUS, or CLEAN
- Prints a color-coded triage report to the terminal
- Saves a full timestamped JSON report for SIEM ingestion or case documentation

## Why This Matters

Manual IOC lookups are one of the highest-volume, lowest-value tasks in Tier 1 SOC work. This tool eliminates that overhead — an analyst drops IOCs from an alert into `iocs.txt`, runs the script, and gets a prioritized triage report in seconds instead of minutes.

## Tech Stack

- **Language:** Python 3
- **APIs:** VirusTotal v3 · AbuseIPDB v2
- **Libraries:** `requests`

## Setup

1. Clone the repo:
```bash
git clone https://github.com/iDea82/ioc-enrichment-tool.git
cd ioc-enrichment-tool
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Mac/Linux
```

3. Install dependencies:
```bash
pip install requests
```

4. Create a `config.py` file in the project root:
```python
VIRUSTOTAL_API_KEY = "your_virustotal_api_key"
ABUSEIPDB_API_KEY  = "your_abuseipdb_api_key"
```

5. Add your IOCs to `iocs.txt` — one per line:

185.220.101.45
44d88612fea8a8f36de82e1278abb02f
malware.wicar.org

6. Run:
```bash
python main.py
```

## Sample Output

============================================================
IOC ENRICHMENT TRIAGE REPORT
Generated: 2026-04-05 14:18:04
IOC      : 185.220.101.45
VERDICT  : MALICIOUS
VT       : 17 malicious, 3 suspicious out of 94 engines
AbuseIPDB: Confidence score 100%, 97 reports, ISP: Network for Tor-Exit traffic., Country: DE
IOC      : 8.8.8.8
VERDICT  : CLEAN
VT       : 0 malicious, 0 suspicious out of 94 engines
AbuseIPDB: Confidence score 0%, 29 reports, ISP: Google LLC, Country: US


## File Structure

| File | Description |
|------|-------------|
| `main.py` | Entry point — loads IOCs, runs enrichment, prints and saves report |
| `enricher.py` | Core logic — VirusTotal and AbuseIPDB API queries and IOC scoring |
| `iocs.txt` | Input file — one IOC per line |
| `.gitignore` | Excludes API keys, venv, and generated reports |
| `config.py` | API keys — created locally, never committed |

## Author

Adesina Tijani — Security Operations Analyst  
[linkedin.com/in/adesina-tijani-6372693b5](https://linkedin.com/in/adesina-tijani-6372693b5)