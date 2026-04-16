#!/usr/bin/env python3
"""
Citrix NetScaler / ADC Honeypot
Emulates Citrix NetScaler Gateway login interface and known vulnerable endpoints.
Logs all interactions as structured JSON for Wazuh/SIEM ingestion.
"""

import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, render_template, redirect, url_for, make_response, jsonify

app = Flask(__name__)

# ── Logging ──────────────────────────────────────────────────────────────────

LOG_FILE = os.path.join(os.path.dirname(__file__), "logs", "honeypot.json")

os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

json_handler = logging.FileHandler(LOG_FILE)
json_handler.setLevel(logging.INFO)

stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(logging.INFO)

logger = logging.getLogger("netscaler_honeypot")
logger.setLevel(logging.INFO)
logger.addHandler(json_handler)
logger.addHandler(stdout_handler)


def log_event(event_type: str, extra: dict = None):
    """Emit a structured JSON log entry."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_id": str(uuid.uuid4()),
        "event_type": event_type,
        "src_ip": request.headers.get("X-Forwarded-For", request.remote_addr),
        "src_port": request.environ.get("REMOTE_PORT", ""),
        "method": request.method,
        "path": request.full_path.rstrip("?"),
        "user_agent": request.headers.get("User-Agent", ""),
        "referer": request.headers.get("Referer", ""),
        "content_type": request.headers.get("Content-Type", ""),
        "host_header": request.headers.get("Host", ""),
        "honeypot": "netscaler",
    }
    if extra:
        entry.update(extra)
    logger.info(json.dumps(entry))


# ── NetScaler response headers ────────────────────────────────────────────────

NS_HEADERS = {
    "Server": "Apache",
    "X-Frame-Options": "SAMEORIGIN",
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-cache, no-store, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
    "Set-Cookie": "NSC_AAAC=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; expires=Thu, 01 Jan 2099 00:00:00 GMT; path=/; HttpOnly",
}


def ns_response(response):
    for k, v in NS_HEADERS.items():
        response.headers[k] = v
    return response


# ── CVE / exploit probe classification ───────────────────────────────────────

EXPLOIT_SIGNATURES = {
    # CVE-2023-3519 – unauthenticated RCE via NSPPE
    "CVE-2023-3519": [
        "/cgi/../../vpns/portal/scripts/newbm.pl",
        "/vpns/portal/scripts/newbm.pl",
        "/vpns/",
        "/cgi/",
    ],
    # CVE-2023-4966 – Citrix Bleed (session token leak)
    "CVE-2023-4966": [
        "/oauth/idp/.well-known/openid-configuration",
        "/oauth/idp/",
        "/oauth/",
    ],
    # CVE-2022-27518 – unauthenticated RCE (SAML)
    "CVE-2022-27518": [
        "/saml/login",
        "/saml/",
    ],
    # CVE-2022-27510 / CVE-2022-27513 – auth bypass
    "CVE-2022-27510": [
        "/nf/auth/doAuthentication.do",
        "/nf/auth/",
    ],
    # Generic scan / recon
    "SCAN": [
        "/.env",
        "/wp-admin",
        "/admin",
        "/phpmyadmin",
        "/actuator",
        "/.git",
        "/config",
    ],
}


def classify_path(path: str) -> str:
    path_lower = path.lower()
    for cve, patterns in EXPLOIT_SIGNATURES.items():
        for p in patterns:
            if p.lower() in path_lower:
                return cve
    return "PROBE"


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    log_event("RECON")
    resp = make_response(redirect("/vpn/index.html"))
    return ns_response(resp)


@app.route("/vpn/index.html")
@app.route("/vpn/")
@app.route("/logon/LogonPoint/index.html")
@app.route("/logon/LogonPoint/")
@app.route("/gwtest/formlogin")
def login_page():
    log_event("LOGIN_PAGE_VIEW")
    resp = make_response(render_template("login.html"))
    return ns_response(resp)


@app.route("/nf/auth/doAuthentication.do", methods=["GET", "POST"])
@app.route("/cgi/login", methods=["GET", "POST"])
@app.route("/vpn/login", methods=["GET", "POST"])
@app.route("/logon/LogonPoint/Authentication/GetAuthentication", methods=["POST"])
def auth_endpoint():
    json_body = request.get_json(silent=True) or {}
    username = (
        request.form.get("login")
        or request.form.get("username")
        or request.form.get("user")
        or json_body.get("username")
        or ""
    )
    password = (
        request.form.get("passwd")
        or request.form.get("password")
        or request.form.get("pass")
        or json_body.get("password")
        or ""
    )
    domain = (
        request.form.get("domain")
        or request.form.get("Domain")
        or ""
    )
    log_event(
        "CREDENTIAL_ATTEMPT",
        {
            "username": username,
            "password": password,
            "domain": domain,
            "alert": "HIGH",
        },
    )
    # Always return auth failure after a realistic delay
    time.sleep(1.5)
    resp = make_response(render_template("login.html", error="Incorrect credentials."))
    return ns_response(resp)


@app.route("/vpns/", defaults={"subpath": ""})
@app.route("/vpns/<path:subpath>")
def vpns_probe(subpath):
    cve = classify_path(request.path)
    log_event(
        "EXPLOIT_PROBE",
        {
            "cve": cve,
            "alert": "CRITICAL",
            "subpath": subpath,
            "post_data": request.get_data(as_text=True)[:512],
        },
    )
    return ns_response(make_response("", 404))


@app.route("/cgi/<path:subpath>")
def cgi_probe(subpath):
    cve = classify_path(request.path)
    log_event(
        "EXPLOIT_PROBE",
        {
            "cve": cve,
            "alert": "CRITICAL",
            "subpath": subpath,
            "post_data": request.get_data(as_text=True)[:512],
        },
    )
    return ns_response(make_response("", 404))


@app.route("/oauth/", defaults={"subpath": ""})
@app.route("/oauth/<path:subpath>")
def oauth_probe(subpath):
    # CVE-2023-4966 – Citrix Bleed
    if ".well-known/openid-configuration" in request.path:
        log_event(
            "EXPLOIT_PROBE",
            {
                "cve": "CVE-2023-4966",
                "alert": "CRITICAL",
                "note": "Citrix Bleed session token leak attempt",
                "post_data": request.get_data(as_text=True)[:512],
            },
        )
        # Return a plausible but harmless OIDC discovery document
        payload = {
            "issuer": f"https://{request.host}",
            "authorization_endpoint": f"https://{request.host}/oauth/idp/connect/authorize",
            "token_endpoint": f"https://{request.host}/oauth/idp/connect/token",
            "userinfo_endpoint": f"https://{request.host}/oauth/idp/connect/userinfo",
            "jwks_uri": f"https://{request.host}/oauth/idp/.well-known/jwks",
            "scopes_supported": ["openid", "profile", "email"],
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
        }
        resp = make_response(jsonify(payload), 200)
        return ns_response(resp)
    log_event(
        "EXPLOIT_PROBE",
        {
            "cve": "CVE-2023-4966",
            "alert": "CRITICAL",
            "subpath": subpath,
        },
    )
    return ns_response(make_response("", 404))


@app.route("/saml/", defaults={"subpath": ""})
@app.route("/saml/<path:subpath>", methods=["GET", "POST"])
def saml_probe(subpath):
    log_event(
        "EXPLOIT_PROBE",
        {
            "cve": "CVE-2022-27518",
            "alert": "CRITICAL",
            "subpath": subpath,
            "post_data": request.get_data(as_text=True)[:512],
        },
    )
    return ns_response(make_response("", 404))


@app.route("/nf/auth/", defaults={"subpath": ""})
@app.route("/nf/auth/<path:subpath>", methods=["GET", "POST"])
def nf_auth_probe(subpath):
    if "doAuthentication" not in request.path:
        log_event(
            "EXPLOIT_PROBE",
            {
                "cve": "CVE-2022-27510",
                "alert": "HIGH",
                "subpath": subpath,
                "post_data": request.get_data(as_text=True)[:512],
            },
        )
        return ns_response(make_response("", 403))
    # Handled by auth_endpoint above
    return auth_endpoint()


# ── Catch-all ─────────────────────────────────────────────────────────────────

@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
def catch_all(path):
    cve = classify_path(request.path)
    event = "EXPLOIT_PROBE" if cve != "PROBE" else "RECON"
    log_event(
        event,
        {
            "cve": cve if cve != "PROBE" else None,
            "alert": "HIGH" if cve != "PROBE" else "LOW",
            "post_data": request.get_data(as_text=True)[:512],
        },
    )
    return ns_response(make_response("", 404))


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    import ssl

    BASE = os.path.dirname(__file__)

    parser = argparse.ArgumentParser(description="Citrix NetScaler Honeypot")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address")
    parser.add_argument("--port", type=int, default=443, help="Bind port")
    parser.add_argument("--cert", default=os.path.join(BASE, "certs/server.crt"), help="TLS certificate")
    parser.add_argument("--key",  default=os.path.join(BASE, "certs/server.key"), help="TLS private key")
    parser.add_argument("--debug", action="store_true", help="Flask debug mode")
    args = parser.parse_args()

    ssl_ctx = None
    if os.path.exists(args.cert) and os.path.exists(args.key):
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(args.cert, args.key)
        print(f"[*] TLS enabled ({args.cert})")
    else:
        print("[!] Cert/key not found — running HTTP only")

    print(f"[*] NetScaler honeypot starting on {'https' if ssl_ctx else 'http'}://{args.host}:{args.port}")
    print(f"[*] Logging to {LOG_FILE}")
    app.run(host=args.host, port=args.port, debug=args.debug, ssl_context=ssl_ctx)
