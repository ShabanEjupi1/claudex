"""Remediation playbooks — turn a detection into actionable 'how to fix' guidance.

Pure data + a lookup function (no DB/IO), so it is unit-testable. A finding is
matched first by its service name (most specific), then by category, then a
sensible default. Any CVEs add NVD advisory links.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Playbook:
    title: str
    summary: str
    steps: tuple[str, ...]
    references: tuple[tuple[str, str], ...] = ()


_DEFAULT = Playbook(
    title="Review and reduce exposure",
    summary="Confirm whether this service/finding is required, and reduce its reachability.",
    steps=(
        "Confirm the service is intentional and owned; if not, disable it.",
        "Restrict access to the smallest necessary source network (mgmt/jump hosts).",
        "Track to closure and re-scan to verify.",
    ),
)

_BY_CATEGORY: dict[str, Playbook] = {
    "legacy-protocol": Playbook(
        "Retire the cleartext/legacy protocol",
        "Legacy protocols expose credentials and data in cleartext and lack modern auth.",
        ("Replace with the encrypted equivalent (Telnet→SSHv2, FTP→SFTP/FTPS, SNMPv1/2c→SNMPv3).",
         "Disable the legacy service on the device once the replacement is verified.",
         "Restrict any remaining management to the mgmt VLAN; block at the firewall elsewhere.",
         "Confirm no automation/monitoring still depends on the old protocol before disabling."),
        (("CIS Controls v8 4.8 (secure mgmt protocols)", "https://www.cisecurity.org/controls"),),
    ),
    "unencrypted-mgmt": Playbook(
        "Encrypt and lock down management access",
        "Management interfaces must be encrypted and reachable only from trusted hosts.",
        ("Move the admin interface to TLS/HTTPS (or SSH) and disable the cleartext port.",
         "Require strong authentication + MFA; remove shared/local accounts.",
         "Allow access only from jump hosts / the mgmt subnet."),
        (),
    ),
    "weak-crypto": Playbook(
        "Disable weak protocol versions and ciphers",
        "Outdated crypto (SSHv1, SSLv3, TLS<1.2, weak ciphers) is broken or brute-forceable.",
        ("Disable legacy versions: SSHv1, SSLv3/TLS1.0/1.1; require TLS 1.2+.",
         "Enforce modern cipher suites; disable RC4/3DES/export ciphers.",
         "Rotate any keys/certs that were used under the weak configuration."),
        (),
    ),
    "open-port": Playbook(
        "Validate and firewall the open port",
        "An exposed port is attack surface; it should be required, hardened, and scoped.",
        ("Identify the owning service and confirm it is required.",
         "If not required, stop the service / close the port.",
         "If required, restrict it at the host and network firewall to need-to-know sources."),
        (),
    ),
    "vulnerability": Playbook(
        "Patch and apply compensating controls",
        "A known-vulnerable or exposed service can lead to compromise or data loss.",
        ("Patch/upgrade to a fixed version (see CVE advisories below).",
         "Until patched, segment the host and limit exposure (firewall, IPS, WAF).",
         "For exposed databases/services, bind to the app tier only and require auth.",
         "Re-scan to confirm the fix."),
        (("NVD (CVE lookup)", "https://nvd.nist.gov/vuln/search"),),
    ),
    "default-credential": Playbook(
        "Remove default/weak credentials",
        "Default or weak credentials are trivially abused for full device takeover.",
        ("Change all default credentials immediately; use unique strong secrets.",
         "Enforce a password policy and centralize auth (TACACS+/RADIUS) where possible.",
         "Audit for reuse of the old credential elsewhere."),
        (),
    ),
    "config-drift": Playbook(
        "Restore the approved baseline",
        "The device configuration deviates from the hardened, change-controlled baseline.",
        ("Compare against the approved baseline and identify the drift.",
         "Investigate who/what changed it (unauthorized change?).",
         "Restore the baseline and enable configuration monitoring (e.g. Oxidized)."),
        (),
    ),
    "intrusion": Playbook(
        "Triage and contain the intrusion alert",
        "An IDS signature fired — verify, contain if real, and tune if false positive.",
        ("Review the signature, source, and destination; confirm whether it is a true positive.",
         "If confirmed: isolate the affected host and check for lateral movement / persistence.",
         "Preserve logs/PCAP for investigation; follow the incident-response runbook.",
         "If a false positive, tune or suppress the rule and document why."),
        (),
    ),
}

# Most-specific overrides by nmap service name.
_BY_SERVICE: dict[str, Playbook] = {
    "telnet": Playbook(
        "Disable Telnet, use SSHv2",
        "Telnet sends credentials and sessions in cleartext.",
        ("Enable SSHv2 on the device and verify connectivity.",
         "Disable the Telnet server (`no telnet` / `transport input ssh`).",
         "Restrict VTY/management access to the mgmt subnet."),
        (("CIS Controls v8 4.8", "https://www.cisecurity.org/controls"),),
    ),
    "microsoft-ds": Playbook(
        "Harden / restrict SMB",
        "Exposed SMB is a primary lateral-movement and ransomware vector (EternalBlue, NTLM relay).",
        ("Patch the OS (MS17-010 and later SMB CVEs).",
         "Disable SMBv1 entirely; require SMB signing to stop NTLM relay.",
         "Block 445/139 at network boundaries; allow only required file servers.",
         "Disable null sessions and audit share permissions."),
        (("MS17-010 (EternalBlue)", "https://nvd.nist.gov/vuln/detail/CVE-2017-0143"),),
    ),
    "ms-wbt-server": Playbook(
        "Lock down RDP",
        "Exposed RDP is brute-forced and was targeted by BlueKeep (CVE-2019-0708).",
        ("Require Network Level Authentication (NLA).",
         "Do not expose RDP to untrusted networks — put it behind VPN/jump host.",
         "Patch (BlueKeep and later); enforce account lockout + MFA."),
        (("BlueKeep", "https://nvd.nist.gov/vuln/detail/CVE-2019-0708"),),
    ),
    "snmp": Playbook(
        "Move to SNMPv3",
        "SNMP v1/v2c uses cleartext community strings that allow device enumeration/changes.",
        ("Migrate to SNMPv3 with authPriv (auth + encryption).",
         "Remove default community strings ('public'/'private').",
         "Restrict SNMP to the monitoring server's IP only."),
        (),
    ),
}


def playbook_for(category: str | None, service_name: str | None,
                 cves: list[str] | None) -> Playbook:
    pb = (_BY_SERVICE.get((service_name or "").lower())
          or _BY_CATEGORY.get(category or "")
          or _DEFAULT)
    if cves:
        refs = list(pb.references)
        have = {u for _, u in refs}
        for cve in cves:
            url = f"https://nvd.nist.gov/vuln/detail/{cve}"
            if url not in have:
                refs.append((cve, url))
        pb = Playbook(pb.title, pb.summary, pb.steps, tuple(refs))
    return pb
