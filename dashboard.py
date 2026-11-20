#!/usr/bin/env python3
"""
dashboard.py - web dashboard for events recorded by monitor.py.

Usage:
    python dashboard.py
Then open http://127.0.0.1:5000 in Firefox.
"""

import os
import sqlite3

from flask import Flask, jsonify, render_template_string, request

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "events.db")
app = Flask(__name__)

PAGE = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="10">
<title>SOC Monitor</title>
<style>
  body { font-family: system-ui, sans-serif; background:#0f172a; color:#e2e8f0; margin:0; padding:24px; }
  h1 { margin:0 0 4px; font-size:22px; }
  .sub { color:#94a3b8; margin-bottom:20px; font-size:14px; }
  .cards { display:flex; gap:12px; flex-wrap:wrap; margin-bottom:20px; }
  .card { background:#1e293b; border-radius:10px; padding:14px 18px; min-width:130px;
          text-decoration:none; color:inherit; border:2px solid transparent; }
  .card.active { border-color:#64748b; }
  .card .n { font-size:28px; font-weight:700; }
  .card .l { font-size:12px; color:#94a3b8; text-transform:uppercase; letter-spacing:.05em; }
  .alert { background:#7f1d1d; border:1px solid #ef4444; padding:12px 16px; border-radius:8px; margin-bottom:20px; }
  table { width:100%; border-collapse:collapse; background:#1e293b; border-radius:10px; overflow:hidden; font-size:14px; }
  th, td { padding:10px 12px; text-align:left; border-bottom:1px solid #334155; vertical-align:top; }
  th { background:#334155; font-size:12px; text-transform:uppercase; color:#cbd5e1; }
  td.detail { max-width:420px; word-break:break-all; }
  .badge { padding:3px 8px; border-radius:999px; font-size:12px; font-weight:700; }
  .MALICIOUS { background:#dc2626; color:white; }
  .SUSPICIOUS { background:#f59e0b; color:#1f2937; }
  .CLEAN { background:#16a34a; color:white; }
  .INTERNAL, .UNKNOWN { background:#475569; color:white; }
  a { color:#93c5fd; }
  .empty { padding:30px; text-align:center; color:#94a3b8; }
</style>
</head>
<body>
  <h1>SOC Monitor &mdash; Downloads &amp; Links</h1>
  <div class="sub">Auto-refreshes every 10 seconds &middot; {{ total }} events recorded</div>

  {% if recent_bad %}
  <div class="alert">
    <strong>&#9888; {{ recent_bad|length }} MALICIOUS event(s) in the last hour:</strong>
    {% for e in recent_bad %} {{ e.detail[:80] }}{% if not loop.last %},{% endif %}{% endfor %}
  </div>
  {% endif %}

  <div class="cards">
    <a class="card {% if not current %}active{% endif %}" href="/">
      <div class="n">{{ total }}</div><div class="l">All</div></a>
    {% for v in ["MALICIOUS", "SUSPICIOUS", "CLEAN", "UNKNOWN"] %}
    <a class="card {% if current == v %}active{% endif %}" href="/?verdict={{ v }}">
      <div class="n">{{ counts.get(v, 0) }}</div><div class="l">{{ v }}</div></a>
    {% endfor %}
    <div class="card"><div class="n">{{ downloads }}</div><div class="l">Downloads</div></div>
    <div class="card"><div class="n">{{ links }}</div><div class="l">Links</div></div>
  </div>

  {% if events %}
  <table>
    <tr><th>Time</th><th>Source</th><th>What</th><th>Verdict</th><th>VirusTotal</th><th>AbuseIPDB</th><th>Notes</th></tr>
    {% for e in events %}
    <tr>
      <td>{{ e.ts }}</td>
      <td>{{ e.source }}</td>
      <td class="detail">{{ e.detail }}<br>
        <a href="https://www.virustotal.com/gui/search/{{ e.indicator }}" target="_blank" rel="noopener">{{ e.indicator[:20] }}{% if e.indicator|length > 20 %}&hellip;{% endif %}</a></td>
      <td><span class="badge {{ e.verdict }}">{{ e.verdict }}</span></td>
      <td>{% if e.vt_total %}{{ e.vt_malicious }}/{{ e.vt_total }}{% else %}&ndash;{% endif %}</td>
      <td>{% if e.abuse_score is not none %}{{ e.abuse_score }}/100{% else %}&ndash;{% endif %}</td>
      <td>{{ e.threat_label or "" }}</td>
    </tr>
    {% endfor %}
  </table>
  {% else %}
  <div class="empty">No events yet. Start monitor.py, then download a file or visit a website.</div>
  {% endif %}
</body>
</html>
"""


def query(sql, args=()):
    if not os.path.exists(DB_PATH):
        return []
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute(sql, args).fetchall()]
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()


@app.route("/")
def index():
    verdict = request.args.get("verdict")
    if verdict:
        events = query("SELECT * FROM events WHERE verdict=? ORDER BY id DESC LIMIT 200", (verdict,))
    else:
        events = query("SELECT * FROM events ORDER BY id DESC LIMIT 200")

    counts = {r["verdict"]: r["n"] for r in
              query("SELECT verdict, COUNT(*) AS n FROM events GROUP BY verdict")}
    sources = query("SELECT source, COUNT(*) AS n FROM events GROUP BY source")
    downloads = sum(r["n"] for r in sources if r["source"].startswith("download"))
    links = sum(r["n"] for r in sources if r["source"].startswith("link"))
    recent_bad = query("SELECT detail FROM events WHERE verdict='MALICIOUS' "
                       "AND ts >= datetime('now', 'localtime', '-1 hour') ORDER BY id DESC")

    return render_template_string(
        PAGE, events=events, counts=counts, total=sum(counts.values()),
        downloads=downloads, links=links, recent_bad=recent_bad, current=verdict,
    )


@app.route("/api/events")
def api_events():
    return jsonify(query("SELECT id, ts, source, detail, indicator, type, verdict, vt_malicious,"
                         " vt_total, abuse_score, threat_label FROM events ORDER BY id DESC LIMIT 500"))


if __name__ == "__main__":
    # 127.0.0.1 = only reachable from this machine
    app.run(host="127.0.0.1", port=5000, debug=False)
