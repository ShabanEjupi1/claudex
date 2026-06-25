#!/usr/bin/env python3
"""Convert nmap XML into risk-classified audit findings and push them to ingest.

Standard library only. Each open port becomes a finding with a real-world risk
rationale (why it's unsafe), severity derived from the service AND any CVSS the
scan turned up, and CVEs extracted from nmap NSE scripts.

To get real vulnerability evidence (not just open ports), scan with version +
vuln scripts, e.g.:
    sudo nmap -sS -sV --script "default,vuln" -T4 --top-ports 1000 -Pn -oX scan.xml 10.10.173.0/24
    # or, version->CVE lookup (needs internet from the scanner; sends versions to vulners.com):
    sudo nmap -sV --script vulners -T4 --top-ports 1000 -Pn -oX scan.xml 10.10.173.0/24

Then:
    export INGEST_URL=http://127.0.0.1:8001/v1/findings INGEST_TOKEN=... INGEST_HMAC_KEY=...
    ./nmap_to_findings.py scan.xml --zone core --collector "$(hostname)"
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

_SEV = ["info", "low", "medium", "high", "critical"]


def _max_sev(a: str, b: str) -> str:
    return a if _SEV.index(a) >= _SEV.index(b) else b


def _cvss_to_sev(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


# service-name -> (category, base severity, why-it's-unsafe rationale)
_RISK = {
    "telnet": ("legacy-protocol", "high", "Cleartext remote management — credentials and sessions are sniffable on the wire. Replace with SSHv2."),
    "ftp": ("legacy-protocol", "medium", "Cleartext credentials and data; check for anonymous login. Use SFTP/FTPS."),
    "tftp": ("legacy-protocol", "medium", "No authentication, cleartext (UDP) — commonly abused to pull device configs."),
    "rlogin": ("legacy-protocol", "high", "Cleartext r-service with trust-based auth. Disable."),
    "rsh": ("legacy-protocol", "high", "Cleartext r-service. Disable."),
    "exec": ("legacy-protocol", "high", "rexec cleartext remote execution. Disable."),
    "snmp": ("unencrypted-mgmt", "medium", "SNMP v1/v2c uses cleartext community strings (often 'public'/'private') — device enumeration and config change. Move to SNMPv3."),
    "microsoft-ds": ("vulnerability", "high", "SMB exposed — file-share and NTLM auth surface; historically EternalBlue (MS17-010), NTLM relay, null-session enumeration. Restrict to mgmt, patch, disable SMBv1."),
    "netbios-ssn": ("legacy-protocol", "medium", "Legacy NetBIOS session service — share/name enumeration and NTLM relay. Disable NetBIOS over TCP/IP."),
    "netbios-ns": ("legacy-protocol", "medium", "NetBIOS name service — NBT-NS/LLMNR poisoning captures credentials. Disable."),
    "msrpc": ("open-port", "medium", "MS RPC endpoint mapper — exposes DCOM/admin services used for lateral movement. Restrict to mgmt subnets."),
    "ms-wbt-server": ("unencrypted-mgmt", "high", "RDP exposed — brute-force and BlueKeep (CVE-2019-0708) target this. Require NLA, restrict to VPN/mgmt."),
    "rdp": ("unencrypted-mgmt", "high", "RDP exposed — brute-force/BlueKeep. Require NLA, restrict to VPN/mgmt."),
    "vnc": ("unencrypted-mgmt", "high", "VNC remote desktop — frequently unencrypted/weak auth. Tunnel over SSH/VPN only."),
    "ldap": ("unencrypted-mgmt", "low", "Cleartext directory queries — credential and structure disclosure. Prefer LDAPS."),
    "http": ("unencrypted-mgmt", "low", "Unencrypted web; if this is a device/admin UI, credentials are sniffable — move to HTTPS."),
    "pop3": ("legacy-protocol", "low", "Cleartext mail retrieval. Enforce TLS."),
    "imap": ("legacy-protocol", "low", "Cleartext mail retrieval. Enforce TLS."),
    "smtp": ("legacy-protocol", "low", "Verify STARTTLS is enforced; cleartext auth / open relay are risks."),
    "mysql": ("vulnerability", "high", "Database exposed to the network — should be bound to the app tier only. Brute-force and data-theft surface."),
    "ms-sql-s": ("vulnerability", "high", "MSSQL exposed — brute-force, xp_cmdshell abuse. Restrict to the app tier."),
    "postgresql": ("vulnerability", "high", "PostgreSQL exposed to the network. Restrict to the app tier."),
    "mongodb": ("vulnerability", "high", "MongoDB exposed — historically unauthenticated by default; mass-data-theft target."),
    "redis": ("vulnerability", "high", "Redis exposed — often unauthenticated; allows RCE via config/keys. Bind to localhost + auth."),
    "elasticsearch": ("vulnerability", "high", "Elasticsearch exposed — unauthenticated data exposure. Restrict to the app tier."),
}
# port fallback when nmap didn't name the service
_PORT_RISK = {
    ("tcp", 23): "telnet", ("tcp", 21): "ftp", ("udp", 69): "tftp", ("tcp", 512): "exec",
    ("tcp", 513): "rlogin", ("tcp", 514): "rsh", ("udp", 161): "snmp", ("tcp", 445): "microsoft-ds",
    ("tcp", 139): "netbios-ssn", ("udp", 137): "netbios-ns", ("tcp", 135): "msrpc",
    ("tcp", 3389): "ms-wbt-server", ("tcp", 5900): "vnc", ("tcp", 389): "ldap", ("tcp", 80): "http",
    ("tcp", 110): "pop3", ("tcp", 143): "imap", ("tcp", 25): "smtp", ("tcp", 3306): "mysql",
    ("tcp", 1433): "ms-sql-s", ("tcp", 5432): "postgresql", ("tcp", 27017): "mongodb",
    ("tcp", 6379): "redis", ("tcp", 9200): "elasticsearch",
}

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
_CVE_CVSS_RE = re.compile(r"(CVE-\d{4}-\d{4,})\s+(\d{1,2}(?:\.\d)?)")


def _classify(name: str, transport: str, port: int, version: str):
    key = name.lower() if name and name.lower() in _RISK else _PORT_RISK.get((transport, port))
    # SSH that still offers protocol v1 (e.g. "protocol 1.99") is a real weakness.
    if (name or "").lower() == "ssh" and re.search(r"protocol 1\b|1\.99", version or ""):
        return ("weak-crypto", "medium", "SSH offers legacy protocol v1 (insecure) — disable SSHv1, keep only v2.")
    if key and key in _RISK:
        return _RISK[key]
    return ("open-port", "info", "Open port observed — review whether it should be reachable from this network.")


def _parse_scripts(elem):
    """Pull CVEs, max CVSS, a VULNERABLE flag and a short summary from <script>s."""
    cves, max_cvss, vuln, lines = set(), 0.0, False, []
    if elem is None:
        return cves, max_cvss, vuln, ""
    for s in elem.findall("script"):
        out = s.get("output") or ""
        sid = s.get("id") or ""
        if not out:
            continue
        if "VULNERABLE" in out or sid.startswith("smb-vuln") or "exploit" in out.lower():
            vuln = True
        for m in _CVE_CVSS_RE.finditer(out):
            try:
                max_cvss = max(max_cvss, float(m.group(2)))
            except ValueError:
                pass
        cves.update(_CVE_RE.findall(out))
        head = out.strip().splitlines()[0][:200] if out.strip() else ""
        lines.append(f"[{sid}] {head}")
    return cves, max_cvss, vuln, " | ".join(lines)[:1500]


def _load_root(path: str):
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
        sys.stderr.write(f"WARNING: {path} was truncated; salvaging up to the last complete host.\n")
        return ET.fromstring(text[: idx + len("</host>")] + "\n</nmaprun>\n")


def _iso(epoch) -> str:
    if epoch and str(epoch).isdigit():
        return dt.datetime.fromtimestamp(int(epoch), dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _findings_from_xml(path: str, collector: str, zone: str | None):
    root = _load_root(path)
    default_ts = _iso(root.get("start"))
    out = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        ipv4 = next((a.get("addr") for a in host.findall("address") if a.get("addrtype") == "ipv4"), None)
        if not ipv4:
            continue
        hn = host.find("hostnames/hostname")
        hostname = hn.get("name") if hn is not None else None
        ts = _iso(host.get("starttime")) or default_ts
        # host-level scripts (e.g. smb-vuln-*) apply to SMB/RPC findings on the host
        h_cves, h_cvss, h_vuln, h_sum = _parse_scripts(host.find("hostscript"))
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            transport = port.get("protocol", "tcp")
            portid = int(port.get("portid"))
            svc = port.find("service")
            name = svc.get("name") if svc is not None else None
            version = " ".join(filter(None, [
                svc.get("product") if svc is not None else None,
                svc.get("version") if svc is not None else None,
                svc.get("extrainfo") if svc is not None else None,
            ])).strip() if svc is not None else ""

            category, severity, note = _classify(name or "", transport, portid, version)
            p_cves, p_cvss, p_vuln, p_sum = _parse_scripts(port)
            cves = sorted(p_cves | (h_cves if name and name.lower() in ("microsoft-ds", "netbios-ssn", "msrpc") else set()))
            cvss = max(p_cvss, h_cvss if cves and h_cves else 0.0)
            vuln = p_vuln or (h_vuln and bool(cves))

            if cvss > 0:
                severity = _max_sev(severity, _cvss_to_sev(cvss))
            if vuln:
                severity = _max_sev(severity, "high")
            if cves or vuln:
                category = "vulnerability"

            evidence = f"{transport.upper()}/{portid} open"
            if name:
                evidence += f" ({name})"
            if version:
                evidence += f" — {version}"
            evidence += f". {note}"
            if cvss > 0:
                evidence += f" Highest CVSS {cvss}."
            script_sum = p_sum or (h_sum if vuln or cves else "")
            if script_sum:
                evidence += f" Scan evidence: {script_sum}"

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
            if cves:
                finding["cve"] = cves[:50]
            out.append(finding)
    return out


def _push(url: str, token: str, hmac_key: str, finding: dict):
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
    ap = argparse.ArgumentParser(description="Push risk-classified nmap findings to the ingest API.")
    ap.add_argument("xml", help="nmap -oX output file")
    ap.add_argument("--collector", default=os.uname().nodename, help="source.collector name")
    ap.add_argument("--zone", default=None, help="tag all findings with this asset zone")
    ap.add_argument("--dry-run", action="store_true", help="print findings, don't push")
    args = ap.parse_args()

    findings = _findings_from_xml(args.xml, args.collector, args.zone)
    by_sev = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    print(f"parsed {len(findings)} finding(s) from {args.xml}: "
          + ", ".join(f"{k}={by_sev[k]}" for k in _SEV if k in by_sev), file=sys.stderr)
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
            print(f"  push failed [{code}] {f['asset']['ip']}:{f['service']['port']} -> {msg[:160]}", file=sys.stderr)
    print(f"pushed {ok}/{len(findings)} findings to {url}", file=sys.stderr)
    return 0 if ok == len(findings) else 1


if __name__ == "__main__":
    raise SystemExit(main())
