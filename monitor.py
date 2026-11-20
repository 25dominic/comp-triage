#!/usr/bin/env python3
"""
monitor.py - watches this machine for downloads and visited links, triages
each one with triage.py, and stores the results for the dashboard.

What it watches:
  * Downloads  - new files in ~/Downloads are hashed (SHA-256) and checked
  * Links      - new websites visited in Firefox are checked by domain

Usage:
    python monitor.py                       # start monitoring
    python monitor.py --simulate-link evil.example      # test without visiting
    python monitor.py --simulate-file /path/to/file     # test a file directly
"""

import argparse
import glob
import hashlib
import ipaddress
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
import time
from datetime import datetime
from urllib.parse import urlparse

from triage import triage

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "events.db")
DOWNLOADS = os.path.expanduser("~/Downloads")
POLL_SECONDS = 5
CACHE_HOURS = 24

# Temporary files browsers create while a download is still in progress
TEMP_EXTENSIONS = (".part", ".crdownload", ".tmp", ".download")

# Domains not worth spending API lookups on (VirusTotal free tier = 4/min)
ALLOWLIST = {
    "google.com", "youtube.com", "gmail.com", "github.com", "githubusercontent.com",
    "mozilla.org", "mozilla.com", "firefox.com", "ubuntu.com", "microsoft.com",
    "virustotal.com", "abuseipdb.com", "claude.ai", "anthropic.com",
    "wikipedia.org", "stackoverflow.com", "linkedin.com",
}


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, source TEXT, detail TEXT, indicator TEXT, type TEXT,
            verdict TEXT, vt_malicious INTEGER, vt_total INTEGER,
            abuse_score INTEGER, threat_label TEXT, raw TEXT
        );
        CREATE TABLE IF NOT EXISTS cache (indicator TEXT PRIMARY KEY, result TEXT, ts REAL);
        CREATE TABLE IF NOT EXISTS seen_files (path TEXT PRIMARY KEY, mtime REAL);
        CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT);
        """)


def get_state(key, default=None):
    with db() as conn:
        row = conn.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def set_state(key, value):
    with db() as conn:
        conn.execute("INSERT OR REPLACE INTO state VALUES (?, ?)", (key, str(value)))


# ---------------------------------------------------------------------------
# Triage + recording
# ---------------------------------------------------------------------------
def cached_triage(indicator):
    """Avoid looking up the same indicator twice within CACHE_HOURS."""
    with db() as conn:
        row = conn.execute("SELECT result, ts FROM cache WHERE indicator=?", (indicator,)).fetchone()
    if row and time.time() - row["ts"] < CACHE_HOURS * 3600:
        return json.loads(row["result"])

    result = triage(indicator)
    # Don't cache failures (rate limit, network) so they get retried later
    if not str(result.get("vt_error", "")).startswith(("rate", "request")):
        with db() as conn:
            conn.execute("INSERT OR REPLACE INTO cache VALUES (?, ?, ?)",
                         (indicator, json.dumps(result), time.time()))
    return result


def record(source, detail, indicator):
    res = cached_triage(indicator)
    vt_total = sum(res.get(k, 0) or 0 for k in
                   ("vt_malicious", "vt_suspicious", "vt_harmless", "vt_undetected"))
    with db() as conn:
        conn.execute(
            "INSERT INTO events (ts, source, detail, indicator, type, verdict, vt_malicious,"
            " vt_total, abuse_score, threat_label, raw) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), source, detail, indicator,
             res.get("type"), res.get("verdict"), res.get("vt_malicious"), vt_total or None,
             res.get("abuse_score"), res.get("vt_threat_label") or res.get("reason") or res.get("note"),
             json.dumps(res)),
        )
    verdict = res.get("verdict")
    print(f"[{source}] {detail} -> {verdict}")
    if verdict in ("MALICIOUS", "SUSPICIOUS"):
        notify(f"{verdict}: {source}", detail)


def notify(title, message):
    """Desktop pop-up on Ubuntu (does nothing if notify-send isn't available)."""
    if shutil.which("notify-send"):
        urgency = "critical" if title.startswith("MALICIOUS") else "normal"
        subprocess.run(["notify-send", "-u", urgency, title, message[:200]], check=False)


# ---------------------------------------------------------------------------
# Download watcher
# ---------------------------------------------------------------------------
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def list_downloads():
    if not os.path.isdir(DOWNLOADS):
        return []
    files = []
    for name in os.listdir(DOWNLOADS):
        path = os.path.join(DOWNLOADS, name)
        if os.path.isfile(path) and not name.lower().endswith(TEMP_EXTENSIONS):
            files.append(path)
    return files


def baseline_downloads():
    """Mark files already in Downloads as seen, so only NEW downloads alert."""
    with db() as conn:
        for path in list_downloads():
            conn.execute("INSERT OR IGNORE INTO seen_files VALUES (?, ?)",
                         (path, os.path.getmtime(path)))


def check_downloads():
    for path in list_downloads():
        try:
            mtime = os.path.getmtime(path)
        except FileNotFoundError:
            continue
        if time.time() - mtime < 3:  # still being written
            continue
        with db() as conn:
            row = conn.execute("SELECT mtime FROM seen_files WHERE path=?", (path,)).fetchone()
            if row and row["mtime"] == mtime:
                continue
            conn.execute("INSERT OR REPLACE INTO seen_files VALUES (?, ?)", (path, mtime))
        record("download", os.path.basename(path), sha256_file(path))


# ---------------------------------------------------------------------------
# Firefox link watcher
# ---------------------------------------------------------------------------
def find_firefox_history():
    """Firefox on Ubuntu is usually a snap; check both locations."""
    patterns = [
        os.path.expanduser("~/snap/firefox/common/.mozilla/firefox/*/places.sqlite"),
        os.path.expanduser("~/.mozilla/firefox/*/places.sqlite"),
    ]
    found = [p for pat in patterns for p in glob.glob(pat)]
    return max(found, key=os.path.getmtime) if found else None


def read_new_visits(since_us):
    """Return (url, visit_time) for visits after since_us (microseconds)."""
    src = find_firefox_history()
    if not src:
        return []
    # Firefox locks its database, so read a copy (plus its write-ahead log)
    tmp = tempfile.mkdtemp()
    try:
        for suffix in ("", "-wal"):
            if os.path.exists(src + suffix):
                shutil.copy2(src + suffix, os.path.join(tmp, "places.sqlite" + suffix))
        conn = sqlite3.connect(os.path.join(tmp, "places.sqlite"))
        rows = conn.execute(
            "SELECT p.url, v.visit_date FROM moz_historyvisits v "
            "JOIN moz_places p ON p.id = v.place_id "
            "WHERE v.visit_date > ? ORDER BY v.visit_date", (since_us,)
        ).fetchall()
        conn.close()
        return rows
    except sqlite3.Error as e:
        print(f"Could not read Firefox history: {e}")
        return []
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def domain_of(url):
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    host = parsed.hostname.lower()
    if host.startswith("www."):
        host = host[4:]
    try:
        if not ipaddress.ip_address(host).is_global:
            return None
    except ValueError:
        if host == "localhost":
            return None
    if any(host == d or host.endswith("." + d) for d in ALLOWLIST):
        return None
    return host


def check_links():
    since = int(get_state("last_visit_us", "0"))
    visits = read_new_visits(since)
    checked = set()
    for url, visit_us in visits:
        domain = domain_of(url)
        if domain and domain not in checked:
            checked.add(domain)
            record("link", url[:300], domain)
        since = max(since, visit_us)
    set_state("last_visit_us", since)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Monitor downloads and visited links")
    parser.add_argument("--simulate-link", help="record a link/domain without visiting it")
    parser.add_argument("--simulate-file", help="record a file as if it was downloaded")
    args = parser.parse_args()

    init_db()

    if args.simulate_link:
        url = args.simulate_link
        record("link (simulated)", url, domain_of(url if "://" in url else "http://" + url) or url)
        return
    if args.simulate_file:
        record("download (simulated)", os.path.basename(args.simulate_file),
               sha256_file(args.simulate_file))
        return

    baseline_downloads()
    if get_state("last_visit_us") is None:  # first run: start from now
        set_state("last_visit_us", int(time.time() * 1_000_000))

    print(f"Monitoring {DOWNLOADS} and Firefox history every {POLL_SECONDS}s. Ctrl+C to stop.")
    if not find_firefox_history():
        print("Note: Firefox history not found - link monitoring is off until Firefox is used.")
    try:
        while True:
            check_downloads()
            check_links()
            time.sleep(POLL_SECONDS)
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
