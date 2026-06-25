#!/usr/bin/env python3
"""Ship Suricata IDS alerts (eve.json) into the audit ingest API as findings.

Tails Suricata's eve.json, turns each 'alert' event into a schema-valid finding,
and pushes it (bearer token + HMAC). De-duplicates by (signature, src, dst, port)
within a window so noisy rules / scans don't flood the dashboard. Stdlib only.

  export INGEST_URL=http://127.0.0.1:8001/v1/findings INGEST_TOKEN=... INGEST_HMAC_KEY=...
  ./suricata_to_findings.py --follow /var/log/suricata/eve.json
  ./suricata_to_findings.py --once  /var/log/suricata/eve.json     # batch existing, exit
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

_SEV = {1: "high", 2: "medium", 3: "low"}
_CRIT = re.compile(r"trojan|ransomware|exploit kit|cobalt strike|\bc2\b|command and control|malware|backdoor", re.I)
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
_TS_RE = re.compile(r"(.*T\d{2}:\d{2}:\d{2})(?:\.\d+)?([+-]\d{2}):?(\d{2})$")


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).version == 4 and ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _norm_ts(ts: str | None) -> str:
    if ts:
        m = _TS_RE.match(ts)
        if m:
            return f"{m.group(1)}{m.group(2)}:{m.group(3)}"
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _finding(ev: dict, collector: str, zone: str | None) -> dict | None:
    if ev.get("event_type") != "alert":
        return None
    a = ev.get("alert") or {}
    src, dst = ev.get("src_ip", ""), ev.get("dest_ip", "")
    asset = dst if _is_private(dst) else (src if _is_private(src) else "")
    if not asset:
        return None  # schema needs an ipv4 internal asset
    proto = (ev.get("proto") or "").lower()
    sig = a.get("signature", "")
    cat_txt = a.get("category", "")
    sev = _SEV.get(a.get("severity"), "low")
    if sev == "high" and _CRIT.search(f"{sig} {cat_txt}"):
        sev = "critical"
    cves = sorted(set(_CVE_RE.findall(f"{sig} {json.dumps(a.get('metadata', {}))}")))

    finding = {
        "schema_version": "1.0",
        "source": {"collector": collector, "method": "suricata"},
        "asset": {"ip": asset},
        "category": "intrusion",
        "severity": sev,
        "status": "open",
        "evidence": (f"Suricata IDS: {sig} (cat: {cat_txt}) "
                     f"{src}:{ev.get('src_port', '')} -> {dst}:{ev.get('dest_port', '')} "
                     f"[sid {a.get('signature_id', '')}]")[:4096],
        "detected_at": _norm_ts(ev.get("timestamp")),
    }
    port = ev.get("dest_port")
    if isinstance(port, int) and proto in ("tcp", "udp"):
        finding["service"] = {"name": (ev.get("app_proto") or proto)[:64], "port": port, "transport": proto}
    if zone:
        finding["asset"]["zone"] = zone[:64]
    if cves:
        finding["cve"] = cves[:50]
    return finding


def _push(url, token, key, finding) -> tuple[int, str]:
    body = json.dumps(finding, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(key.encode("utf-8"), body, hashlib.sha256).hexdigest()
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Authorization": f"Bearer {token}",
        "X-Signature": f"sha256={sig}",
        "Content-Type": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, ""
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")[:160]
    except urllib.error.URLError as e:
        return 0, str(e)


def main() -> int:
    ap = argparse.ArgumentParser(description="Ship Suricata eve.json alerts to the ingest API.")
    ap.add_argument("eve", help="path to eve.json")
    ap.add_argument("--collector", default="suricata")
    ap.add_argument("--zone", default=os.environ.get("IDS_ZONE") or None)
    ap.add_argument("--follow", action="store_true", help="tail the file (default for service use)")
    ap.add_argument("--once", action="store_true", help="process current contents and exit")
    ap.add_argument("--from-start", action="store_true", help="with --follow, start at file beginning")
    ap.add_argument("--dedup-window", type=int, default=int(os.environ.get("IDS_DEDUP_WINDOW", "3600")),
                    help="seconds to suppress a repeated (sig,src,dst,port) alert")
    args = ap.parse_args()

    url = os.environ.get("INGEST_URL", "http://127.0.0.1:8001/v1/findings")
    token, key = os.environ.get("INGEST_TOKEN"), os.environ.get("INGEST_HMAC_KEY")
    if not token or not key:
        print("ERROR: set INGEST_TOKEN and INGEST_HMAC_KEY", file=sys.stderr)
        return 2

    seen: dict[tuple, float] = {}

    def handle(line: str, counters: list[int]):
        line = line.strip()
        if not line or '"event_type":"alert"' not in line.replace(" ", ""):
            return
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            return
        f = _finding(ev, args.collector, args.zone)
        if not f:
            return
        a = ev.get("alert") or {}
        k = (a.get("signature_id"), ev.get("src_ip"), ev.get("dest_ip"), ev.get("dest_port"))
        now = time.time()
        if k in seen and now - seen[k] < args.dedup_window:
            counters[1] += 1
            return
        seen[k] = now
        code, msg = _push(url, token, key, f)
        if code == 201:
            counters[0] += 1
        else:
            print(f"  push failed [{code}] {f['asset']['ip']} {msg}", file=sys.stderr)

    counters = [0, 0]  # pushed, deduped
    if args.once:
        try:
            with open(args.eve) as fh:
                for line in fh:
                    handle(line, counters)
        except FileNotFoundError:
            print(f"ERROR: {args.eve} not found", file=sys.stderr)
            return 2
        print(f"pushed {counters[0]} findings ({counters[1]} de-duplicated)", file=sys.stderr)
        return 0

    # follow mode
    print(f"following {args.eve} (dedup window {args.dedup_window}s)", file=sys.stderr)
    while not os.path.exists(args.eve):
        time.sleep(2)
    fh = open(args.eve)
    if not args.from_start:
        fh.seek(0, os.SEEK_END)
    inode = os.fstat(fh.fileno()).st_ino
    while True:
        line = fh.readline()
        if line:
            handle(line, counters)
            continue
        time.sleep(1)
        try:  # handle log rotation/truncation
            if os.stat(args.eve).st_ino != inode or os.stat(args.eve).st_size < fh.tell():
                fh.close()
                fh = open(args.eve)
                inode = os.fstat(fh.fileno()).st_ino
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
