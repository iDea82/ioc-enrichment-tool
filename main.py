import json
import datetime
from enricher import check_virustotal, check_abuseipdb, score_ioc

def load_iocs(filepath):
    """
    Reads iocs.txt and returns a clean list of IOCs,
    skipping any blank lines or comments starting with #
    """
    with open(filepath, "r") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def run_enrichment(iocs):
    """
    Loops through every IOC, queries both sources,
    scores each one, and builds a structured results list.
    """
    results = []

    for ioc in iocs:
        print(f"  [*] Checking {ioc}...")

        vt_result = check_virustotal(ioc)
        abuse_result = check_abuseipdb(ioc)
        verdict = score_ioc(vt_result, abuse_result)

        results.append({
            "ioc": ioc,
            "verdict": verdict,
            "virustotal": vt_result,
            "abuseipdb": abuse_result
        })

    return results


def print_report(results):
    """
    Prints a clean human-readable summary to the terminal.
    Color-codes each verdict so MALICIOUS jumps out immediately.
    """
    # ANSI color codes for terminal output
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    RESET  = "\033[0m"

    print("\n" + "="*60)
    print("  IOC ENRICHMENT TRIAGE REPORT")
    print(f"  Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60 + "\n")

    for r in results:
        verdict = r["verdict"]

        if verdict == "MALICIOUS":
            color = RED
        elif verdict == "SUSPICIOUS":
            color = YELLOW
        else:
            color = GREEN

        print(f"IOC      : {r['ioc']}")
        print(f"VERDICT  : {color}{verdict}{RESET}")

        # VirusTotal summary
        vt = r["virustotal"]
        if "error" in vt:
            print(f"VT       : Error — {vt['error']}")
        else:
            print(f"VT       : {vt['malicious_engines']} malicious, "
                  f"{vt['suspicious_engines']} suspicious "
                  f"out of {vt['total_engines']} engines")

        # AbuseIPDB summary
        ab = r["abuseipdb"]
        if "skipped" in ab:
            print(f"AbuseIPDB: Skipped — {ab['skipped']}")
        elif "error" in ab:
            print(f"AbuseIPDB: Error — {ab['error']}")
        else:
            print(f"AbuseIPDB: Confidence score {ab['abuse_confidence_score']}%, "
                  f"{ab['total_reports']} reports, "
                  f"ISP: {ab['isp']}, "
                  f"Country: {ab['country']}")

        print("-" * 60)


def save_report(results):
    """
    Saves the full results as a JSON file for archiving,
    further analysis, or feeding into a SIEM/SOAR pipeline.
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"triage_report_{timestamp}.json"

    with open(filename, "w") as f:
        json.dump(results, f, indent=4)

    print(f"\n  [+] Full report saved to {filename}")


# ── Entry point ─────────────────────────────────────────────
if __name__ == "__main__":
    print("\n  [+] Loading IOCs...")
    iocs = load_iocs("iocs.txt")
    print(f"  [+] Found {len(iocs)} IOCs to enrich\n")

    print("  [+] Running enrichment...\n")
    results = run_enrichment(iocs)

    print_report(results)
    save_report(results)