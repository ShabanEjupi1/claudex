# Network Audit & Secure Reporting — Runbook

**Scope:** internal network infrastructure (routers, switches, firewalls, WLCs).
**Destination dashboard:** `10.10.173.22`.
**Standards:** CIS Controls v8, CIS Benchmarks (device-specific), NIST SP 800-53
(AC/AU/SC families), NIST CSF.

---

## Phase 0 — Authorization & preparation

- [ ] Written authorization to scan; defined scope (IP ranges, devices, exclusions).
- [ ] Change ticket raised; **scan windows** agreed (active sweeps can disrupt
      fragile legacy gear — this is exactly what we're hunting for).
- [ ] Break-glass/rollback plan for any remediation.
- [ ] Read-only AAA account provisioned for credentialed config pulls.
- [ ] Time sync verified across devices (NTP) so audit timestamps correlate.

## Phase 1 — Asset inventory (CIS Controls v8 §1, §2)

You cannot disable what you cannot see. Build the inventory from multiple
sources and reconcile:

- [ ] ARP/MAC address tables
- [ ] CDP/LLDP neighbor data
- [ ] DHCP leases
- [ ] Routing tables / interface lists
- [ ] An authoritative active scan (Phase 3)

Record role, owner, zone, and management IP per asset.

## Phase 2 — Establish the authorized baseline (CIS Controls v8 §4)

For each device role, define what *should* be running (services, ports,
management protocols, crypto). Everything outside the baseline is a candidate
for removal. Capture the gold config in `Oxidized`/`RANCID` + git for drift
detection.

## Phase 3 — Discovery tooling

| Purpose | Tool | Representative command |
|---|---|---|
| TCP service/version | nmap | `nmap -sS -sV -p- --open -oA tcp <range>` |
| UDP (SNMP/TFTP/NTP/syslog) | nmap | `nmap -sU -p 69,123,161,162,514 --open <range>` |
| Weak SNMP communities | nmap | `nmap -sU -p161 --script snmp-brute <t>` |
| TLS/SSH cipher posture | nmap/sslscan | `--script ssl-enum-ciphers,ssh2-enum-algos` |
| Config compliance vs CIS | CIS-CAT Pro, Nipper (Titania) | credentialed run |
| Vulnerability data | Nessus / OpenVAS / Qualys | credentialed scans |
| Config backup + drift | Oxidized / RANCID | scheduled pulls into git |
| Ad-hoc config audit at scale | Ansible (`cisco.ios`) | `ansible/cis-network-audit.yml` |

Use `scripts/discovery/nmap-discovery.sh` for active discovery, and pair it with
**passive** sources (NetFlow/sFlow, span ports) so you don't miss services that
only talk to specific peers. (CIS Controls v8 §13 — Network Monitoring.)

## Phase 4 — CIS-based identification & remediation (Controls v8 §4, §12)

### Insecure protocols — eliminate or replace

| Service | Port | Risk | Required action |
|---|---|---|---|
| Telnet | TCP 23 | Cleartext creds/session | Disable; SSHv2 only |
| HTTP mgmt | TCP 80 | Cleartext admin | HTTPS (TLS 1.2+) or disable web mgmt |
| SNMP v1/v2c | UDP 161/162 | Cleartext, trivial auth | SNMPv3 **authPriv** (SHA + AES) |
| FTP / TFTP | TCP 21 / UDP 69 | Cleartext transfer | SCP/SFTP |
| SSHv1 | TCP 22 | Broken protocol | `ip ssh version 2` |
| rsh/rlogin/rexec | 512–514 | Cleartext, weak auth | Disable entirely |
| finger | TCP 79 | Info disclosure | Disable |
| small servers (echo/chargen/discard/daytime) | 7/9/13/19 | DoS amplification | Disable |
| BOOTP | UDP 67 | Unneeded service | Disable if unused |
| SSL v2/v3, TLS 1.0/1.1, RC4, DES/3DES, MD5 | — | Broken/deprecated | TLS 1.2 min, prefer 1.3 |

### Default-hardening checklist

- [ ] Unused switchports `shutdown`, access mode, blackhole VLAN; BPDU Guard + Port Security.
- [ ] Trunk only required VLANs; remove unused VLANs.
- [ ] No default/guessable SNMP communities (`public`/`private`) anywhere.
- [ ] VTY/SSH restricted by ACL to the jump-host subnet; `exec-timeout` set; AUX disabled.
- [ ] CDP/LLDP disabled on untrusted-facing interfaces.
- [ ] `no ip source-route`, `no ip directed-broadcast`, no Proxy ARP / ICMP redirects on untrusted ifaces.
- [ ] Centralized **AAA** (RADIUS/TACACS+); no local accounts except break-glass.
- [ ] Passwords stored as Cisco Type 8/9 (avoid reversible Type 7 / weak Type 5).
- [ ] Authenticated NTP; all config changes logged to a **TLS syslog** target + git backup.

### Representative Cisco IOS remediation

```
no ip http server
ip http secure-server
ip ssh version 2
line vty 0 15
 transport input ssh
 access-class MGMT-ACL in
 exec-timeout 10 0
no service tcp-small-servers
no service udp-small-servers
no service finger
no ip bootp server
no ip source-route
no cdp run                         ! or 'no cdp enable' per untrusted interface
service password-encryption
snmp-server group AUDIT v3 priv
! then define a v3 user with SHA auth + AES priv; remove all v1/v2c communities
```

**Deliverable:** a prioritized remediation register — each finding tagged with
device, service, CIS reference, severity, and status — emitted as JSON matching
`schemas/ingest-finding.schema.json`.

## Phase 5 — Secure data integration to the dashboard

Three sensitive data classes move toward `10.10.173.22`: discovery logs, asset/
config data, and vulnerability findings. Protect them **in transit, at rest, and
against poisoning** (scan output contains attacker-influenceable fields).

### Baseline mechanisms (apply regardless of push vs pull)

- **Transport:** mutual TLS (internal CA), TLS 1.3/1.2 only.
- **AuthN:** short-lived, **scoped, write-only** API tokens per source from a
  secrets manager (Vault/KMS). No hardcoded credentials. Client certs *and*
  tokens, so a stolen token alone is insufficient.
- **Integrity:** HMAC-sign each payload (+ timestamp/nonce) to reject tamper/replay.
- **Network ACLs:** only collector IPs may reach the ingest port; ingest port ≠ UI port.
- **Input validation:** strict JSON Schema validation at the boundary (anti-poisoning).
- **Endpoint segregation:** the *write* (ingest) path and *read* (dashboard) path
  are different services and identities. Collectors POST; they never GET.

Off-the-shelf reference channels: **Splunk HEC** (HTTPS + per-source token) or
**syslog over TLS (RFC 5425)** for log streams; a validating REST API for findings.

### Push vs. Pull — security comparison

| Dimension | Push (collectors → HTTPS POST + tokens) | Pull (web/DB tier queries sources) |
|---|---|---|
| Direction of trust | Higher→lower trust (good) | Lower-trust web tier reaches *into* higher-trust nodes (**risky**) |
| Credential location | Distributed (sprawl/rotation) | Centralized on puller (single high-value target) |
| Blast radius if exposed tier breached | Dashboard holds **no** inbound creds → no pivot | Puller's creds → lateral movement **into the network** |
| Firewalling | One hardened ingest endpoint, deny-by-default | Wide outbound reach to many nodes |
| Freshness | Event-driven / near real-time | Polling latency |
| Primary threat | Token theft + **payload poisoning** | Compromise of polling tier → pivot |

### Recommended hybrid (gets the directionality right)

1. **Collectors push** (mTLS + write-only token + HMAC, validated) into the
   Zone-B store — a TLS broker landing into an **encrypted-at-rest** database
   with a write-only role.
2. **The dashboard pulls (reads)** from that store using a **read-only** DB role
   over TLS — and *only* from the store, never from devices.

Worst case, a dashboard compromise yields read-only access to already-collected
data — bad, but not a foothold into live infrastructure. For the most sensitive
feeds (full topology/credentials), use a one-way/diode-style transfer.

## Phase 6 — Securing the dashboard host (`10.10.173.22`)

See `docs/dashboard-hardening-checklist.md`. Treat the dashboard as a **Tier-0
crown jewel**: it maps every weakness in the estate.

## Phase 7 — Remediate, retest, report

- [ ] Work the remediation register by severity; each change is ticketed.
- [ ] Re-scan to confirm closure; update finding `status` → `remediated`.
- [ ] Track trend (open vs. closed, by severity/zone) on the dashboard.
- [ ] Periodically pentest the dashboard itself — don't leave the auditor unaudited.

---

## Appendix — control mapping

| Activity | CIS Controls v8 | NIST 800-53 |
|---|---|---|
| Asset/software inventory | §1, §2 | CM-8 |
| Secure configuration | §4 | CM-2, CM-6, CM-7 |
| Network infra management | §12 | AC-3, SC-7 |
| Network monitoring | §13 | SI-4 |
| Access control (dashboard) | §5, §6 | AC family |
| Audit logging | §8 | AU family |
| Data protection | §3 | SC-12, SC-13, SC-28 |
