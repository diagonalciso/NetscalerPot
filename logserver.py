#!/usr/bin/env python3
"""
NetScaler Honeypot — Log Dashboard
Serves a web UI for browsing events and watching the live feed.
Default port: 8084
"""

import json
import os
import time
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from flask import Flask, render_template, request, jsonify, Response, stream_with_context

app = Flask(__name__, template_folder="templates")

LOG_FILE = os.path.join(os.path.dirname(__file__), "logs", "honeypot.json")

ALERT_ORDER = {"CRITICAL": 0, "HIGH": 1, "LOW": 2, "": 3}

_geo_cache: dict[str, str] = {}  # ip -> country_code


def _fetch_country(ip: str) -> tuple[str, str]:
    try:
        url = f"https://ipwho.is/{ip}"
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read())
        return ip, data.get("country_code", "")
    except Exception:
        return ip, ""


def geo_lookup(ips: list[str]) -> dict[str, str]:
    """Resolve country codes via ipwho.is, parallel, cached. Returns {ip: country_code}."""
    uncached = [ip for ip in ips if ip not in _geo_cache]
    if uncached:
        with ThreadPoolExecutor(max_workers=20) as pool:
            futures = {pool.submit(_fetch_country, ip): ip for ip in uncached}
            for future in as_completed(futures):
                ip, code = future.result()
                _geo_cache[ip] = code
    return {ip: _geo_cache.get(ip, "") for ip in ips}


# ── Helpers ───────────────────────────────────────────────────────────────────

def parse_log_line(raw: str):
    raw = raw.strip()
    if not raw:
        return None
    if raw.startswith("INFO:"):
        raw = raw.split(":", 2)[-1]
    try:
        return json.loads(raw)
    except Exception:
        return None


def _is_local(ip):
    return not ip or ip.startswith(('127.', '192.'))


def load_events():
    events = []
    if not os.path.exists(LOG_FILE):
        return events
    with open(LOG_FILE, errors="replace") as f:
        for line in f:
            e = parse_log_line(line)
            if e and not _is_local(e.get('src_ip', '')):
                events.append(e)
    return events


def compute_stats(events):
    total = len(events)
    by_type  = Counter(e.get("event_type", "") for e in events)
    by_ip    = Counter(e.get("src_ip", "")    for e in events)
    by_cve   = Counter(e.get("cve", "")       for e in events if e.get("cve"))
    by_alert = Counter(e.get("alert", "")     for e in events)
    creds    = [e for e in events if e.get("event_type") == "CREDENTIAL_ATTEMPT"]
    uniq_u   = list({e.get("username", "") for e in creds if e.get("username")})

    # activity over last 60 minutes (1-min buckets)
    now_ts = time.time()
    buckets = [0] * 60
    for e in events:
        try:
            ts = datetime.fromisoformat(e["timestamp"]).timestamp()
            mins_ago = int((now_ts - ts) / 60)
            if 0 <= mins_ago < 60:
                buckets[59 - mins_ago] += 1
        except Exception:
            pass

    return {
        "total":        total,
        "by_type":      dict(by_type.most_common(10)),
        "by_alert":     dict(by_alert),
        "top_ips":      dict(by_ip.most_common(10)),
        "by_cve":       dict(by_cve.most_common()),
        "cred_count":   len(creds),
        "unique_users": uniq_u,
        "activity":     buckets,
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/docs/user-manual")
def user_manual():
    manual_path = os.path.join(os.path.dirname(__file__), "HONEYPOT_MANUAL.html")
    if os.path.exists(manual_path):
        with open(manual_path, "r") as f:
            return f.read()
    return "Manual not found", 404


@app.route("/live")
def live_page():
    return render_template("live.html")


@app.route("/events")
def events_page():
    return render_template("events.html")


@app.route("/unique-ips")
def unique_ips_page():
    return render_template("unique_ips.html")


@app.route("/api/unique-ips")
def api_unique_ips():
    events = load_events()
    exclude = {"127.0.0.1", ""}
    seen = set()
    ips = []
    for e in events:
        ip = e.get("src_ip", "")
        if ip and ip not in exclude and not ip.startswith("192.") and ip not in seen:
            seen.add(ip)
            ips.append(ip)
    countries = geo_lookup(ips)
    return jsonify({"ips": [{"ip": ip, "country": countries.get(ip, "")} for ip in ips], "total": len(ips)})


# ── API ───────────────────────────────────────────────────────────────────────

@app.route("/api/stats")
def api_stats():
    events = load_events()
    return jsonify(compute_stats(events))


@app.route("/api/events")
def api_events():
    events = load_events()

    # filters
    ftype  = request.args.get("type", "")
    falert = request.args.get("alert", "")
    fip    = request.args.get("ip", "")
    fcve   = request.args.get("cve", "")
    fsearch= request.args.get("q", "").lower()
    page   = max(1, int(request.args.get("page", 1)))
    per    = min(200, int(request.args.get("per", 50)))

    if ftype:
        events = [e for e in events if e.get("event_type") == ftype]
    if falert:
        events = [e for e in events if e.get("alert") == falert]
    if fip:
        events = [e for e in events if fip in e.get("src_ip", "")]
    if fcve:
        events = [e for e in events if e.get("cve") == fcve]
    if fsearch:
        def match(e):
            return any(fsearch in str(v).lower() for v in e.values())
        events = [e for e in events if match(e)]

    events = list(reversed(events))  # newest first
    total = len(events)
    start = (page - 1) * per
    page_events = events[start:start + per]

    return jsonify({
        "total": total,
        "page": page,
        "per": per,
        "pages": max(1, (total + per - 1) // per),
        "events": page_events,
    })


@app.route("/api/stream")
def api_stream():
    """Server-Sent Events — streams new log lines as they arrive."""
    def generate():
        # Send an immediate comment so the browser fires onopen right away
        yield ": connected\n\n"

        if not os.path.exists(LOG_FILE):
            while not os.path.exists(LOG_FILE):
                time.sleep(1)

        with open(LOG_FILE, errors="replace") as f:
            f.seek(0, 2)  # jump to end
            last_keepalive = time.time()
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.2)
                    # Send a keepalive comment every 15 s to prevent browser timeout
                    if time.time() - last_keepalive >= 15:
                        yield ": keepalive\n\n"
                        last_keepalive = time.time()
                    continue
                e = parse_log_line(line)
                if e:
                    yield f"data: {json.dumps(e)}\n\n"
                    last_keepalive = time.time()

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="NetScaler Honeypot Log Dashboard")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8084)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    print(f"[*] Log dashboard on http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)
