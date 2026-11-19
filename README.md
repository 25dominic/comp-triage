# IOC Triage Tool

A Python command-line tool that automates the first step of SOC alert triage: checking indicators of compromise (IOCs) against threat intelligence sources and returning a verdict in seconds.

Paste in an IP address, domain, URL or file hash, and the tool queries **VirusTotal** and **AbuseIPDB**, scores the results, and saves a CSV report you can attach to a ticket.

![Sample output](screenshot.png)

---

## Why I built this

Tier 1 SOC analysts check the same kinds of indicators many times a day: a suspicious IP in a firewall alert, a sender domain in a phishing email, a file hash from an EDR detection. Doing this by hand means copying each value into several websites one at a time.

This tool does those lookups automatically, so the analyst can spend their time on the investigation instead of the copy-pasting.

---

## Features

- **Detects indicator type automatically**: IPv4/IPv6, domains, URLs, and MD5 / SHA-1 / SHA-256 hashes
- **Handles defanged indicators**: `hxxp://evil[.]com` is converted back to `http://evil.com` before lookup
- **Multiple intel sources**: VirusTotal for every indicator type, plus AbuseIPDB for IPs
- **Clear verdicts**: MALICIOUS, SUSPICIOUS, CLEAN, INTERNAL or UNKNOWN, color-coded in the terminal
- **Skips private IPs**: internal addresses (e.g. `192.168.x.x`) are flagged for internal investigation instead of being sent to external services
- **Bulk mode**: triage a whole list of indicators from a text file
- **CSV reports**: every run is saved with a timestamp for documentation
- **Respects API rate limits**: built-in throttling for the VirusTotal free tier (4 requests/minute)
- **Secure key handling**: API keys are loaded from a `.env` file and never stored in the code

---

## Verdict logic

| Verdict | Rule |
|---|---|
| **MALICIOUS** | 3+ VirusTotal engines flag it as malicious, **or** AbuseIPDB confidence score ≥ 75 |
| **SUSPICIOUS** | 1+ VirusTotal engine flags it as malicious or suspicious, **or** AbuseIPDB score ≥ 25 |
| **CLEAN** | Results returned and nothing was flagged |
| **INTERNAL** | Private or reserved IP address; not sent to external services |
| **UNKNOWN** | Indicator type not recognized, or no results available |

A single engine detection can be a false positive, so one hit is treated as suspicious, not malicious. Requiring three or more detections for a MALICIOUS verdict reduces alert noise while still escalating clear threats.

---

## Setup

Tested on Ubuntu with Python 3.

```bash
git clone https://github.com/25dominic/ioc-triage.git
cd ioc-triage
python3 -m venv venv
source venv/bin/activate
pip install requests python-dotenv
```

Create a `.env` file with your free API keys from [VirusTotal](https://www.virustotal.com) and [AbuseIPDB](https://www.abuseipdb.com):

```
VT_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
```

---

## Usage

```bash
# Single indicator
python triage.py 8.8.8.8

# Several at once (defanged indicators are supported)
python triage.py google.com hxxp://bad[.]site/login 44d88612fea8a8f36de82e1278abb02f

# Bulk mode: one indicator per line
python triage.py -f iocs.txt

# Skip saving the CSV report
python triage.py 8.8.8.8 --no-report
```

Reports are saved to `reports/triage_YYYYMMDD_HHMMSS.csv`.

---

## Skills demonstrated

- **Threat intelligence enrichment**: using VirusTotal and AbuseIPDB the way a SOC analyst does during triage
- **Python scripting**: REST API requests, JSON parsing, regex, argument parsing, CSV output
- **Security best practices**: API keys kept out of source code and version control; private IPs never sent to third parties
- **Working within API limits**: rate limiting and error handling for quotas, bad keys and missing results
- **Linux**: built and tested on Ubuntu in a VMware virtual machine

---

## Planned improvements

- [ ] Add AlienVault OTX as a third intelligence source
- [ ] Extract indicators automatically from phishing email headers
- [ ] Generate an HTML report
- [ ] Cache results to avoid repeat lookups of the same indicator

---

## Disclaimer

This tool is for educational and defensive security purposes. Free API tiers have daily limits, and results from threat intelligence services should support an analyst's judgment, not replace it.
