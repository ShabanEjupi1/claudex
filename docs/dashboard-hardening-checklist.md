# Dashboard Hardening Checklist — `10.10.173.22`

Threat model: the **insider** and the **lateral-mover**, not the internet. The
dashboard concentrates "where every weakness lives," so treat it as a Tier-0
crown-jewel asset.

## Host & network

- [ ] Dedicated, **CIS-hardened** minimal OS; no co-located services.
- [ ] Full patch/vulnerability management on the host itself.
- [ ] Placed in a restricted security/management VLAN.
- [ ] Firewalled so only authorized admin subnets / a **PAM-controlled jump host**
      can reach the UI. No flat-network reachability.
- [ ] Reverse proxy / WAF in front; server tokens and directory listing disabled.
- [ ] **TLS 1.2/1.3 only**, internal-CA cert, HSTS enabled.
- [ ] **mTLS client certificates** for admin access (network-layer second factor).

## Authentication

- [ ] Central IdP via **SAML/OIDC SSO** (Azure AD / Okta / AD FS).
- [ ] **No local or shared accounts**; service accounts separate, non-interactive,
      least-privilege.
- [ ] **MFA enforced** — ideally phishing-resistant **FIDO2/WebAuthn**.
- [ ] Hardened sessions: short idle timeout; `Secure`/`HttpOnly`/`SameSite` cookies;
      anti-CSRF tokens; account lockout + rate limiting.

## Authorization — RBAC (+ ABAC for crown jewels)

Least privilege, deny by default:

| Role | Can see | Cannot |
|---|---|---|
| **Viewer** | Aggregate posture, trends | Raw vuln detail, exports |
| **Analyst** | Full findings for *assigned segments* | Other segments, admin |
| **Auditor** | Read-only across scope + audit logs | Modify data/config |
| **Admin** | Platform/user/role management | (Separated from data-viewing) |

- [ ] Attribute/row-level **need-to-know**: restrict topology/blueprints by segment
      ownership and **data classification** labels (ABAC).
- [ ] **Separation of duties:** ingestion identity ≠ viewing identity ≠ platform admin.

## Data protection

- [ ] **Encryption at rest** (disk + DB).
- [ ] **Column/field-level encryption or tokenization** for the most sensitive
      items (topology, credentials, raw vuln detail). Keys in a vault/KMS.
- [ ] **Role-based masking/redaction** so lower roles see truncated data.
- [ ] **Export controls / DLP:** bulk download is the highest-risk action — gate
      behind elevated role + approval, watermark/log every export, alert on bulk pulls.
- [ ] **Treat ingested scan data as untrusted input.** A hostname or banner can
      carry a stored-XSS/injection payload. Enforce output encoding + strict CSP.

## Monitoring & assurance

- [ ] Comprehensive, **tamper-evident audit logging** of who viewed/exported what,
      shipped to the SIEM; alert on anomalous or bulk access.
- [ ] Encrypted, access-controlled backups.
- [ ] Periodic pentest of the dashboard application.
