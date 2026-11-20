#!/usr/bin/env python3
"""
triage.py - IOC triage tool for SOC analysts.

Checks IPs, domains, URLs and file hashes against VirusTotal and AbuseIPDB,
gives each one a verdict, and saves a CSV report.

Usage:
    python triage.py 8.8.8.8
    python triage.py evil[.]com hxxp://bad[.]site/login 44d88612fea8a8f36de82e1278abb02f
    python triage.py -f iocs.txt
"""

import argparse
import base64
import csv
import ipaddress
import os
import re
import sys
import time
from datetime import datetime

import requests
from dotenv import load_dotenv

load_dotenv()
VT_KEY = os.getenv("VT_API_KEY")
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")

VT_DELAY = 15  # VirusTotal free tier allows 4 requests per minute
TIMEOUT = 20

# ---------------------------------------------------------------------------
# Tuning - change these numbers to make the tool stricter or looser
# ---------------------------------------------------------------------------
VT_MALICIOUS_MIN = 3      # this many VT engines flagging it = MALICIOUS
ABUSE_MALICIOUS_MIN = 75  # AbuseIPDB score at or above this = MALICIOUS
ABUSE_SUSPICIOUS_MIN = 25 # AbuseIPDB score at or above this = SUSPICIOUS
FP_HARMLESS_MIN = 20      # a single VT hit is treated as a false positive
                          # when at least this many engines say "harmless"
_last_vt_call = 0.0

# Terminal colors
RED, YELLOW, GREEN, GREY, BOLD, RESET = (
    "\033[91m", "\033[93m", "\033[92m", "\033[90m", "\033[1m", "\033[0m"
)
VERDICT_COLOR = {"MALICIOUS": RED, "SUSPICIOUS": YELLOW, "CLEAN": GREEN}


# ---------------------------------------------------------------------------
# Indicator handling
# ---------------------------------------------------------------------------
def refang(ioc: str) -> str:
    """Turn defanged indicators (hxxp, [.], (dot)) back into normal ones."""
    ioc = ioc.strip().strip('"\'')
    ioc = re.sub(r"^hxxp", "http", ioc, flags=re.I)
    ioc = re.sub(r"\[\.\]|\(\.\)|\[dot\]|\(dot\)", ".", ioc, flags=re.I)
    ioc = ioc.replace("[:]", ":").replace("[://]", "://")
    return ioc


def classify(ioc: str) -> str:
    """Return the indicator type: ip, url, domain, md5, sha1, sha256 or unknown."""
    try:
        ipaddress.ip_address(ioc)
        return "ip"
    except ValueError:
        pass
    if re.match(r"^https?://", ioc, re.I):
        return "url"
    if re.fullmatch(r"[a-fA-F0-9]{32}", ioc):
        return "md5"
    if re.fullmatch(r"[a-fA-F0-9]{40}", ioc):
        return "sha1"
    if re.fullmatch(r"[a-fA-F0-9]{64}", ioc):
        return "sha256"
    if re.fullmatch(r"(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}", ioc):
        return "domain"
    return "unknown"


# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------
def vt_lookup(ioc: str, kind: str) -> dict:
    global _last_vt_call
    if not VT_KEY:
        return {"vt_error": "no API key"}

    if kind == "ip":
        endpoint = f"ip_addresses/{ioc}"
    elif kind == "domain":
        endpoint = f"domains/{ioc}"
    elif kind == "url":
        url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
        endpoint = f"urls/{url_id}"
    else:  # hashes
        endpoint = f"files/{ioc}"

    # Respect the free-tier rate limit
    wait = VT_DELAY - (time.time() - _last_vt_call)
    if _last_vt_call and wait > 0:
        print(f"{GREY}  waiting {wait:.0f}s for VirusTotal rate limit...{RESET}")
        time.sleep(wait)
    _last_vt_call = time.time()

    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/{endpoint}",
            headers={"x-apikey": VT_KEY},
            timeout=TIMEOUT,
        )
    except requests.RequestException as e:
        return {"vt_error": f"request failed: {e.__class__.__name__}"}

    if r.status_code == 404:
        return {"vt_error": "not found in VirusTotal"}
    if r.status_code == 401:
        return {"vt_error": "bad API key"}
    if r.status_code == 429:
        return {"vt_error": "rate limit / daily quota hit"}
    if r.status_code != 200:
        return {"vt_error": f"HTTP {r.status_code}"}

    attrs = r.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    result = {
        "vt_malicious": stats.get("malicious", 0),
        "vt_suspicious": stats.get("suspicious", 0),
        "vt_harmless": stats.get("harmless", 0),
        "vt_undetected": stats.get("undetected", 0),
        "vt_reputation": attrs.get("reputation", ""),
    }
    if kind in ("md5", "sha1", "sha256"):
        result["vt_name"] = attrs.get("meaningful_name", "")
        result["vt_type"] = attrs.get("type_description", "")
        label = attrs.get("popular_threat_classification", {}).get("suggested_threat_label")
        result["vt_threat_label"] = label or ""
    if kind == "ip":
        result["vt_country"] = attrs.get("country", "")
        result["vt_owner"] = attrs.get("as_owner", "")
    return result


# ---------------------------------------------------------------------------
# AbuseIPDB (IPs only)
# ---------------------------------------------------------------------------
def abuseipdb_lookup(ip: str) -> dict:
    if not ABUSE_KEY:
        return {"abuse_error": "no API key"}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSE_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=TIMEOUT,
        )
    except requests.RequestException as e:
        return {"abuse_error": f"request failed: {e.__class__.__name__}"}

    if r.status_code == 401:
        return {"abuse_error": "bad API key"}
    if r.status_code == 429:
        return {"abuse_error": "daily quota hit"}
    if r.status_code != 200:
        return {"abuse_error": f"HTTP {r.status_code}"}

    d = r.json().get("data", {})
    return {
        "abuse_score": d.get("abuseConfidenceScore", 0),
        "abuse_reports": d.get("totalReports", 0),
        "abuse_country": d.get("countryCode", ""),
        "abuse_isp": d.get("isp", ""),
        "abuse_usage": d.get("usageType", ""),
        "abuse_last_reported": d.get("lastReportedAt", ""),
        "abuse_whitelisted": bool(d.get("isWhitelisted")),
    }


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------
def verdict(res: dict) -> tuple:
    """Return (verdict, reason). Rules are checked from most to least serious."""
    vt_mal = res.get("vt_malicious", 0) or 0
    vt_sus = res.get("vt_suspicious", 0) or 0
    harmless = res.get("vt_harmless", 0) or 0
    abuse = res.get("abuse_score", 0) or 0
    hits = vt_mal + vt_sus

    # Rule 1: strong evidence -> MALICIOUS
    if vt_mal >= VT_MALICIOUS_MIN:
        return "MALICIOUS", f"{vt_mal} VirusTotal engines flagged it as malicious"
    if abuse >= ABUSE_MALICIOUS_MIN:
        return "MALICIOUS", f"AbuseIPDB confidence score {abuse}/100"

    # Rule 2: known legitimate services (e.g. Google DNS) -> CLEAN
    if res.get("abuse_whitelisted") and abuse < ABUSE_SUSPICIOUS_MIN:
        return "CLEAN", "whitelisted by AbuseIPDB as a known legitimate service"

    # Rule 3: one lone detection outvoted by many harmless votes -> CLEAN
    if hits == 1 and harmless >= FP_HARMLESS_MIN and abuse < ABUSE_SUSPICIOUS_MIN:
        return "CLEAN", f"likely false positive: 1 engine flagged it, {harmless} rated it harmless"

    # Rule 4: weak evidence -> SUSPICIOUS (an analyst should look)
    if hits >= 1 or abuse >= ABUSE_SUSPICIOUS_MIN:
        reasons = []
        if hits:
            reasons.append(f"{hits} VirusTotal engine(s) flagged it")
        if abuse >= ABUSE_SUSPICIOUS_MIN:
            reasons.append(f"AbuseIPDB score {abuse}/100")
        return "SUSPICIOUS", "; ".join(reasons)

    # Rule 5: results came back with nothing flagged -> CLEAN
    if "vt_malicious" in res or "abuse_score" in res:
        return "CLEAN", "no detections"

    # Rule 6: no data (e.g. a new file VirusTotal has never seen) -> UNKNOWN
    return "UNKNOWN", res.get("vt_error") or res.get("abuse_error") or "no results"


def triage(raw: str) -> dict:
    ioc = refang(raw)
    kind = classify(ioc)
    res = {"input": raw, "indicator": ioc, "type": kind}

    if kind == "unknown":
        res["verdict"] = "UNKNOWN"
        res["note"] = "could not recognise indicator type"
        return res

    if kind == "ip" and not ipaddress.ip_address(ioc).is_global:
        res["verdict"] = "INTERNAL"
        res["note"] = "private/reserved IP - investigate internally"
        return res

    res.update(vt_lookup(ioc, kind))
    if kind == "ip":
        res.update(abuseipdb_lookup(ioc))
    res["verdict"], res["reason"] = verdict(res)
    return res


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def print_result(res: dict) -> None:
    v = res["verdict"]
    color = VERDICT_COLOR.get(v, GREY)
    print(f"\n{BOLD}{res['indicator']}{RESET}  ({res['type']})  ->  {color}{BOLD}{v}{RESET}")

    if "note" in res:
        print(f"  {res['note']}")
    if "reason" in res:
        print(f"  Reason     : {res['reason']}")
    if "vt_malicious" in res:
        print(f"  VirusTotal : {res['vt_malicious']} malicious, {res['vt_suspicious']} suspicious, "
              f"{res['vt_harmless']} harmless, {res['vt_undetected']} undetected")
        if res.get("vt_threat_label"):
            print(f"  Threat     : {res['vt_threat_label']}")
        if res.get("vt_name"):
            print(f"  File       : {res['vt_name']} ({res.get('vt_type', '')})")
        if res.get("vt_owner"):
            print(f"  Owner      : {res['vt_owner']} ({res.get('vt_country', '')})")
    elif "vt_error" in res:
        print(f"  VirusTotal : {GREY}{res['vt_error']}{RESET}")

    if "abuse_score" in res:
        print(f"  AbuseIPDB  : score {res['abuse_score']}/100, {res['abuse_reports']} reports, "
              f"{res['abuse_isp']} ({res['abuse_country']}), {res['abuse_usage']}")
    elif "abuse_error" in res:
        print(f"  AbuseIPDB  : {GREY}{res['abuse_error']}{RESET}")

    if res["verdict"] not in ("INTERNAL", "UNKNOWN"):
        print(f"  {GREY}VT link    : https://www.virustotal.com/gui/search/{res['indicator']}{RESET}")


def save_csv(results: list, folder: str = "reports") -> str:
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, f"triage_{datetime.now():%Y%m%d_%H%M%S}.csv")
    fields = []
    for r in results:
        for k in r:
            if k not in fields:
                fields.append(k)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(results)
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description="Triage IOCs against VirusTotal and AbuseIPDB")
    parser.add_argument("iocs", nargs="*", help="IPs, domains, URLs or hashes")
    parser.add_argument("-f", "--file", help="text file with one indicator per line")
    parser.add_argument("--no-report", action="store_true", help="don't save a CSV report")
    args = parser.parse_args()

    iocs = list(args.iocs)
    if args.file:
        with open(args.file, encoding="utf-8") as f:
            iocs += [line.strip() for line in f if line.strip() and not line.startswith("#")]
    iocs = list(dict.fromkeys(iocs))  # remove duplicates, keep order

    if not iocs:
        parser.print_help()
        sys.exit(1)
    if not VT_KEY:
        print(f"{YELLOW}Warning: VT_API_KEY not set in .env{RESET}")
    if not ABUSE_KEY:
        print(f"{YELLOW}Warning: ABUSEIPDB_API_KEY not set in .env{RESET}")

    print(f"Triaging {len(iocs)} indicator(s)...")
    results = []
    for ioc in iocs:
        res = triage(ioc)
        print_result(res)
        results.append(res)

    counts = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    print(f"\n{BOLD}Summary:{RESET} " + ", ".join(f"{k}: {v}" for k, v in counts.items()))

    if not args.no_report:
        print(f"Report saved to {save_csv(results)}")


if __name__ == "__main__":
    main()
