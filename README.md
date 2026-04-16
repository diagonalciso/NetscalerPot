# NetScaler Honeypot

A low-interaction honeypot that emulates a Citrix NetScaler / ADC Gateway. It mimics the login interface and known vulnerable endpoints to capture attacker behavior, credential attempts, and exploit probes — logging everything as structured JSON for SIEM ingestion.

## What it captures

- Credential attempts against the NetScaler login portal
- Exploit probes targeting known CVEs:
  - **CVE-2023-3519** — unauthenticated RCE via NSPPE
  - **CVE-2023-4966** — Citrix Bleed (session token leak)
  - **CVE-2022-27518** — unauthenticated RCE via SAML
  - **CVE-2022-27510 / CVE-2022-27513** — authentication bypass
- General recon and path scanning
- All source IPs, user agents, headers, and payloads

## Components

| File | Purpose |
|------|---------|
| `honeypot.py` | Flask app running on port 443 (TLS), emulates NetScaler |
| `logserver.py` | Flask dashboard on port 8084, serves the web UI |
| `logs/honeypot.json` | Structured JSON log (one event per line) |

## Dashboard

The log dashboard at `http://<host>:8084` has four pages:

- **Dashboard** — live stats, top IPs, CVE hit counts, activity graph
- **Events** — filterable/searchable event table
- **Live Feed** — real-time event stream via SSE
- **Unique IPs** — deduplicated attacker IPs with country flags, each linking to [AbuseIPDB](https://www.abuseipdb.com)

## Setup

```bash
pip install -r requirements.txt
```

Generate a self-signed cert if you don't have one:
```bash
openssl req -x509 -newkey rsa:2048 -keyout certs/server.key -out certs/server.crt -days 365 -nodes
```

Run manually:
```bash
sudo python3 honeypot.py --port 443
python3 logserver.py --port 8084
```

Or install as systemd services:
```bash
sudo cp netscaler-honeypot.service /etc/systemd/system/
sudo cp netscaler-logserver.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now netscaler-honeypot netscaler-logserver
```

## Log format

Each event is a JSON line:

```json
{
  "timestamp": "2026-04-16T10:23:01+00:00",
  "event_id": "uuid",
  "event_type": "CREDENTIAL_ATTEMPT",
  "src_ip": "1.2.3.4",
  "method": "POST",
  "path": "/vpn/login",
  "user_agent": "...",
  "alert": "HIGH",
  "cve": null,
  "username": "admin",
  "honeypot": "netscaler"
}
```

Alert levels: `CRITICAL` (CVE exploit probe) · `HIGH` (credential attempt / known path) · `LOW` (recon)

## Disclaimer

For defensive research and threat intelligence purposes only. Deploy in an isolated network segment or DMZ. Do not expose on production infrastructure.
