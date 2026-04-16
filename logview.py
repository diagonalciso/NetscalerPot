#!/usr/bin/env python3
"""
Quick CLI log viewer for the NetScaler honeypot.
Usage:
  python3 logview.py              # last 50 events
  python3 logview.py --creds      # credential attempts only
  python3 logview.py --critical   # CRITICAL alerts only
  python3 logview.py --tail       # follow log in real-time
  python3 logview.py --stats      # summary stats
"""

import argparse
import json
import os
import sys
import time
from collections import Counter, defaultdict

LOG_FILE = os.path.join(os.path.dirname(__file__), "logs", "honeypot.json")


def load_events(path):
    events = []
    if not os.path.exists(path):
        return events
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                # Each log line is a JSON object preceded by a log level prefix
                # strip "INFO:netscaler_honeypot:" prefix if present
                if line.startswith("INFO:"):
                    line = line.split(":", 2)[-1]
                events.append(json.loads(line))
            except Exception:
                pass
    return events


COLORS = {
    "CRITICAL": "\033[91m",   # bright red
    "HIGH":     "\033[93m",   # yellow
    "LOW":      "\033[96m",   # cyan
    "NONE":     "\033[0m",    # reset
    "RESET":    "\033[0m",
    "BOLD":     "\033[1m",
    "DIM":      "\033[2m",
}


def color(level):
    return COLORS.get(level, COLORS["NONE"])


def fmt_event(e):
    ts  = e.get("timestamp", "")[:19].replace("T", " ")
    ip  = e.get("src_ip", "?").ljust(16)
    et  = e.get("event_type", "?").ljust(20)
    mth = e.get("method", "GET").ljust(6)
    pth = e.get("path", "/")
    alr = e.get("alert", "")
    cve = e.get("cve", "")
    usr = e.get("username", "")
    pwd = e.get("password", "")

    c = color(alr)
    r = COLORS["RESET"]

    line = f"{COLORS['DIM']}{ts}{r}  {ip}  {c}{et}{r}  {mth} {pth}"
    if cve:
        line += f"  {COLORS['BOLD']}[{cve}]{r}"
    if usr:
        line += f"  user={COLORS['BOLD']}{usr}{r}"
    if pwd:
        line += f" pass={COLORS['BOLD']}{pwd}{r}"
    return line


def cmd_stats(events):
    total = len(events)
    by_type  = Counter(e.get("event_type") for e in events)
    by_ip    = Counter(e.get("src_ip") for e in events)
    by_cve   = Counter(e.get("cve") for e in events if e.get("cve"))
    creds    = [e for e in events if e.get("event_type") == "CREDENTIAL_ATTEMPT"]
    uniq_u   = set(e.get("username") for e in creds if e.get("username"))

    print(f"\n{COLORS['BOLD']}=== NetScaler Honeypot Stats ==={COLORS['RESET']}")
    print(f"  Total events:  {total}")
    print(f"  Unique IPs:    {len(by_ip)}")
    print(f"  Cred attempts: {len(creds)} ({len(uniq_u)} unique usernames)")
    print(f"\n{COLORS['BOLD']}Event types:{COLORS['RESET']}")
    for k, v in by_type.most_common():
        print(f"  {k:<30} {v}")
    print(f"\n{COLORS['BOLD']}CVE probes:{COLORS['RESET']}")
    for k, v in by_cve.most_common():
        print(f"  {k:<20} {v}")
    print(f"\n{COLORS['BOLD']}Top source IPs:{COLORS['RESET']}")
    for ip, cnt in by_ip.most_common(10):
        print(f"  {ip:<20} {cnt}")
    if uniq_u:
        print(f"\n{COLORS['BOLD']}Usernames attempted:{COLORS['RESET']}")
        for u in sorted(uniq_u):
            print(f"  {u}")


def tail_log(path, args):
    print(f"[*] Tailing {path}  (Ctrl-C to stop)\n")
    with open(path) as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.25)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                if line.startswith("INFO:"):
                    line = line.split(":", 2)[-1]
                e = json.loads(line)
                if args.creds and e.get("event_type") != "CREDENTIAL_ATTEMPT":
                    continue
                if args.critical and e.get("alert") != "CRITICAL":
                    continue
                print(fmt_event(e))
            except Exception:
                pass


def main():
    parser = argparse.ArgumentParser(description="NetScaler honeypot log viewer")
    parser.add_argument("--creds",    action="store_true", help="Credential attempts only")
    parser.add_argument("--critical", action="store_true", help="CRITICAL alerts only")
    parser.add_argument("--tail",     action="store_true", help="Follow log in real-time")
    parser.add_argument("--stats",    action="store_true", help="Summary statistics")
    parser.add_argument("-n", type=int, default=50, help="Lines to show (default 50)")
    parser.add_argument("--log", default=LOG_FILE, help="Log file path")
    args = parser.parse_args()

    if args.tail:
        tail_log(args.log, args)
        return

    events = load_events(args.log)

    if args.creds:
        events = [e for e in events if e.get("event_type") == "CREDENTIAL_ATTEMPT"]
    if args.critical:
        events = [e for e in events if e.get("alert") == "CRITICAL"]

    if args.stats:
        cmd_stats(events)
        return

    for e in events[-args.n:]:
        print(fmt_event(e))

    print(f"\n{COLORS['DIM']}({len(events)} matching events){COLORS['RESET']}")


if __name__ == "__main__":
    main()
