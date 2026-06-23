#!/usr/bin/env python3
"""Convert nmap XML output into audit findings and push them to the ingest API.

Standard library only — runs on any host with python3 that can reach the ingest
API. Each open port becomes one finding; cleartext/legacy management services are
flagged at higher severity, everything else is recorded as an informational
open-port (so the dashboard reflects real attack surface).

Usage:
    # 1. scan (SYN+UDP needs root; -sT works unprivileged)
    sudo nmap -sS -sV -O -Pn -oX scan.xml 10.10.173.0/24

    # 2. convert + push
    export INGEST_URL=http://127.0.0.1:8001/v1/findings
    export INGEST_TOKEN=<the plaintext bearer token>
    export INGEST_HMAC_KEY=<INGEST_HMAC_KEY from deploy/docker/.env>
    ./nmap_to_findings.py scan.xml --zone core --collector kcus

    # preview without sending
    ./nmap_to_findings.py scan.xml --dry-run
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import hmac
import json
import os
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

# service-name / (transport, port) -> (category, severity, note). Name match wins.
_BY_NAME = {
    "telnet": ("legacy-protocol", "high", "Telnet — cleartext remote management. Replace with SSHv2."),
    "ftp": ("legacy-protocol", "medium", "FTP — cleartext credentials/data. Use SFTP/FTPS."),
    "rlogin": ("legacy-protocol", "high", "rlogin — cleartext r-service. Disable."),
    "rsh": ("legacy-protocol", "high", "rsh — cleartext r-service. Disable."),
    "exec": ("legacy-protocol", "high", "rexec — cleartext r-service. Disable."),
    "tftp": ("legacy-protocol", "medium", "TFTP — no auth, cleartext. Restrict/disable."),
    "snmp": ("unencrypted-mgmt", "medium", "SNMP — likely v1/v2c cleartext community strings. Use SNMPv3."),
    "http": ("unencrypted-mgmt", "low", "HTTP — unencrypted. If this is device management, move to HTTPS."),
    "vnc": ("unencrypted-mgmt", "medium", "VNC — frequently unencrypted remote desktop."),
    "ldap": ("unencrypted-mgmt", "low", "LDAP — cleartext directory access. Prefer LDAPS."),
    "pop3": ("legacy-protocol", "low", "POP3 — cleartext mail retrieval."),
    "imap": ("legacy-protocol", "low", "IMAP — cleartext mail retrieval."),
    "smtp": ("legacy-protocol", "low", "SMTP — verify STARTTLS is enforced."),
}
_BY_PORT = {
    ("tcp", 23): _BY_NAME["telnet"],
    ("tcp", 21): _BY_NAME["ftp"],
    ("tcp", 512): _BY_NAME["exec"],
    ("tcp", 513): _BY_NAME["rlogin"],
    ("tcp", 514): _BY_NAME["rsh"],
    ("udp", 69): _BY_NAME["tftp"],
    ("udp", 161): _BY_NAME["snmp"],
    ("tcp", 80): _BY_NAME["http"],
    ("tcp", 5900): _BY_NAME["vnc"],
    ("tcp", 389): _BY_NAME["ldap"],
}


def _classify(name: str, transport: str, port: int):
    if name and name.lower() in _BY_NAME:
        return _BY_NAME[name.lower()]
    if (transport, port) in _BY_PORT:
        return _BY_PORT[(transport, port)]
    return ("open-port", "info", "Open port observed; review whether it should be exposed.")


def _load_root(path: str):
    """Parse nmap XML, salvaging a truncated file (interrupted scan with no
    closing </nmaprun>) by cutting to the last complete <host> element."""
    with open(path, "rb") as fh:
        data = fh.read()
    try:
        return ET.fromstring(data)
    except ET.ParseError:
        text = data.decode("utf-8", "replace")
        idx = text.rfind("</host>")
        if idx == -1:
            raise SystemExit(
                f"ERROR: {path} has no complete <host> elements — the scan didn't "
                "finish (no closing </nmaprun>). Re-run nmap and let it complete."
            )
        sys.stderr.write(
            f"WARNING: {path} was truncated (interrupted scan); "
            "salvaging up to the last complete host.\n"
        )
        return ET.fromstring(text[: idx + len("</host>")] + "\n</nmaprun>\n")


def _findings_from_xml(path: str, collector: str, zone: str | None):
    root = _load_root(path)
    default_ts = _iso(root.get("start"))
    out = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        ipv4 = next((a.get("addr") for a in host.findall("address")
                     if a.get("addrtype") == "ipv4"), None)
        if not ipv4:
            continue  # schema requires an ipv4 asset.ip
        hn = host.find("hostnames/hostname")
        hostname = hn.get("name") if hn is not None else None
        ts = _iso(host.get("starttime")) or default_ts
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            transport = port.get("protocol", "tcp")
            portid = int(port.get("portid"))
            svc = port.find("service")
            name = svc.get("name") if svc is not None else None
            product = " ".join(filter(None, [
                svc.get("product") if svc is not None else None,
                svc.get("version") if svc is not None else None,
            ])).strip() if svc is not None else ""
            category, severity, note = _classify(name or "", transport, portid)
            evidence = f"{transport.upper()}/{portid} open"
            if name:
                evidence += f" ({name})"
            if product:
                evidence += f" — {product}"
            evidence += f". {note}"
            finding = {
                "schema_version": "1.0",
                "source": {"collector": collector, "method": "nmap"},
                "asset": {"ip": ipv4},
                "category": category,
                "service": {"name": (name or "unknown")[:64], "port": portid, "transport": transport},
                "severity": severity,
                "status": "open",
                "evidence": evidence[:4096],
                "detected_at": ts,
            }
            if hostname:
                finding["asset"]["hostname"] = hostname[:253]
            if zone:
                finding["asset"]["zone"] = zone[:64]
            out.append(finding)
    return out


def _iso(epoch: str | None) -> str:
    if epoch and epoch.isdigit():
        return dt.datetime.fromtimestamp(int(epoch), dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _push(url: str, token: str, hmac_key: str, finding: dict) -> tuple[int, str]:
    body = json.dumps(finding, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(hmac_key.encode("utf-8"), body, hashlib.sha256).hexdigest()
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Authorization": f"Bearer {token}",
        "X-Signature": f"sha256={sig}",
        "Content-Type": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except urllib.error.URLError as e:
        return 0, str(e)


def main() -> int:
    ap = argparse.ArgumentParser(description="Push nmap XML findings to the ingest API.")
    ap.add_argument("xml", help="nmap -oX output file")
    ap.add_argument("--collector", default=os.uname().nodename, help="source.collector name")
    ap.add_argument("--zone", default=None, help="tag all findings with this asset zone")
    ap.add_argument("--dry-run", action="store_true", help="print findings, don't push")
    args = ap.parse_args()

    findings = _findings_from_xml(args.xml, args.collector, args.zone)
    print(f"parsed {len(findings)} open-port finding(s) from {args.xml}", file=sys.stderr)
    if args.dry_run:
        json.dump(findings, sys.stdout, indent=2)
        print()
        return 0

    url = os.environ.get("INGEST_URL", "http://127.0.0.1:8001/v1/findings")
    token = os.environ.get("INGEST_TOKEN")
    key = os.environ.get("INGEST_HMAC_KEY")
    if not token or not key:
        print("ERROR: set INGEST_TOKEN and INGEST_HMAC_KEY env vars", file=sys.stderr)
        return 2

    ok = 0
    for f in findings:
        code, msg = _push(url, token, key, f)
        if code == 201:
            ok += 1
        else:
            print(f"  push failed [{code}] {f['asset']['ip']}:{f['service']['port']} -> {msg[:160]}",
                  file=sys.stderr)
    print(f"pushed {ok}/{len(findings)} findings to {url}", file=sys.stderr)
    return 0 if ok == len(findings) else 1


if __name__ == "__main__":
    raise SystemExit(main())
