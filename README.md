# UARecon

UARecon is an OPC UA security assessment toolkit for reconnaissance, security posture review, and production-safe exposure analysis.

## Setup

```bash
git clone https://github.com/SilviaMun/uarecon.git
cd uarecon
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 tools/build_cve_db.py
```

build_cve_db.py fetches OPC UA-related advisories from OPC Foundation and enriches them with NVD metadata.
Initial build may take a few minutes.

## Quick start

```bash
# List all available checks
python3 uarecon.py --list-checks

# List CVE database entries
python3 uarecon.py --list-cves

# Pre-auth recon only (no credentials)
python3 uarecon.py -t opc.tcp://target:4840 --endpoints-only

# Full scan
python3 uarecon.py -t opc.tcp://target:4840 -u user -p pass

# Production-safe scan
python3 uarecon.py -t opc.tcp://target:4840 -u user -p pass --prod

# Run specific checks
python3 uarecon.py -t opc.tcp://target:4840 --check anonymous lockout
python3 uarecon.py -t opc.tcp://target:4840 -u user -p pass --check nonce browse-acl

# Run by family
python3 uarecon.py -t opc.tcp://target:4840 -u user -p pass --family auth authz

# CVE matching only
python3 uarecon.py -t opc.tcp://target:4840 -u user -p pass --cve-only

# Brute-force credentials
python3 uarecon.py -t opc.tcp://target:4840 --wordlist users.txt --passlist passwords.txt

# Brute-force with delay between attempts
python3 uarecon.py -t opc.tcp://target:4840 --wordlist users.txt --passlist passwords.txt --delay 0.5
```

## Assessment Families (10)

Checks are organized into 10 families covering the full OPC UA attack surface.
Use `--family` to run only specific families.

| # | Family | Alias | Focus |
|---|--------|-------|-------|
| 1 | authentication_posture | `auth` | Identity and credential security |
| 2 | endpoint_security_posture | `endpoint` | Transport and endpoint configuration |
| 3 | certificate_posture | `cert` | PKI and certificate validation |
| 4 | secure_channel_posture | `channel` | Channel quality, nonces, session binding |
| 5 | authorization_posture | `authz` | Access control enforcement |
| 6 | information_disclosure | `disclosure` | Data exposure and fingerprinting |
| 7 | audit_posture | `audit` | Logging, diagnostics, time integrity |
| 8 | availability_posture | `availability` | Resource limits and DoS surface |
| 9 | deployment_posture | `deployment` | Network topology and architecture leaks |
| 10 | advisory_validation | — | CVE matching (via cve.py module) |

## Security Checks (40)

30 prod-safe + 10 testing-only.

| Slug | Check | Family | Mode |
|------|-------|--------|------|
| `anonymous` | Anonymous Access | auth | prod |
| `user-tokens` | User Token Policies | auth | prod |
| `default-creds` | Default Credentials | auth | testing |
| `provided-creds` | Provided Credentials Assessment | auth | prod |
| `lockout` | Account Lockout Detection | auth | testing |
| `security-policies` | Security Policy Analysis | endpoint | prod |
| `endpoint-url` | Endpoint URL Validation | endpoint | prod |
| `discovery` | Discovery Service Exposure | endpoint | prod |
| `server-cert` | Server Certificate Analysis | cert | prod |
| `cert-hostname` | Certificate Hostname Validation | cert | prod |
| `app-uri` | ApplicationUri Consistency | cert | prod |
| `gds-trust` | GDS / Trust List Access | cert | prod |
| `cert-bypass` | Certificate Trust Bypass | cert | testing |
| `nonce` | Server Nonce Quality | channel | prod |
| `secure-channel` | SecureChannel Token Lifetime | channel | prod |
| `session-timeout` | Session Timeout Policy | channel | prod |
| `session-limits` | Session Limits | channel | prod |
| `browse-acl` | Browse Access Control | authz | prod |
| `roles` | Role / Permission Model | authz | prod |
| `history` | History Read Access | authz | prod |
| `view-access` | View-Based Access Control | authz | prod |
| `method-access` | Method Access Control | authz | testing |
| `node-write` | Node Write Verification | authz | testing |
| `writable-config` | Server Config Write Access | authz | prod |
| `access-restrictions` | Access Restrictions Analysis | authz | prod |
| `transfer-sub` | Subscription Transfer Hijack | authz | testing |
| `buildinfo` | Build Information Exposure | disclosure | prod |
| `namespaces` | Namespace Exposure Analysis | disclosure | prod |
| `redundancy` | Redundancy Info Exposure | disclosure | prod |
| `sensitive-data` | Sensitive Data Exposure | disclosure | prod |
| `audit` | Audit Configuration | audit | prod |
| `timestamp` | Timestamp Accuracy | audit | prod |
| `diagnostics-consistency` | Diagnostics Consistency | audit | prod |
| `max-limits` | Server Limits (DoS Surface) | availability | prod |
| `max-response` | Response Size Amplification | availability | prod |
| `max-connections` | Max Connections (DoS) | availability | testing |
| `sub-abuse` | Subscription Limits | availability | testing |
| `publish-flood` | Publish Rate Abuse | availability | testing |
| `translate-dos` | TranslateBrowsePaths DoS | availability | testing |
| `gds-discovery` | FindServersOnNetwork | deployment | prod |

## Prod vs Testing

UARecon distinguishes between two check modes:

**Prod-safe** (`--prod`): 30 checks. Read-only operations only — no state changes, no write attempts, no resource pressure, no credential guessing. Safe for production OT/ICS systems. By default introduces a 1-second delay between checks to reduce load.

**Testing-only**: 10 checks. Active probing that may change server state: write attempts (`node-write`), credential attacks (`default-creds`, `lockout`), resource abuse (`sub-abuse`, `publish-flood`, `translate-dos`), cross-session tests (`transfer-sub`, `cert-bypass`), connection flooding (`max-connections`). Use only on systems you own or are explicitly authorized to test.

```bash
# Default prod mode (1s delay between checks)
python3 uarecon.py -t opc.tcp://target:4840 -u user -p pass --prod

# Slower for fragile systems
python3 uarecon.py -t opc.tcp://target:4840 -u user -p pass --prod --delay 3

# No inter-check delay (not recommended for production)
python3 uarecon.py -t opc.tcp://target:4840 -u user -p pass --prod --delay 0

# Full mode: all 40 checks (prod + testing)
python3 uarecon.py -t opc.tcp://target:4840 -u user -p pass
```

Brute-force (`--wordlist`/`--passlist`) is invoked separately from the check catalog and is not part of the prod/testing classification.

## Report Output

Each scan produces two report files in the `reports/` directory:

- **JSON** (`uarecon_report_TIMESTAMP.json`): machine-readable, includes all findings, evidence, endpoints, nodes, CVE matches, and connection context.
- **HTML** (`uarecon_report_TIMESTAMP.html`): visual report with severity breakdown, findings by category, observations, endpoint table, CVE database, and server details.

The vulnerability summary in both console and HTML separates **actionable findings** (with severity and category) from **observations** (informational posture notes). The connection context section shows which authentication strategy was used for the enumeration session.

Use `-o FILE` to specify a custom JSON output path.

## CLI Flags

```
-t, --target            opc.tcp://host:port
-u, --user              Username
-p, --password          Password
-c, --cert              Client certificate PEM
-k, --key               Client private key PEM
--uri                   Application URI (default: urn:UARecon)
--policy                Security policy (Basic256Sha256, Aes128Sha256RsaOaep, Aes256Sha256RsaPss)
--mode                  Security mode (Sign, SignAndEncrypt)
--prod                  Skip testing-only checks (delay 1s between checks)
--delay SEC             Delay between checks in seconds (default: 0, --prod: 1.0)
--check SLUG [SLUG ...] Run only specific check(s) by slug
--family NAME [NAME ...]Run only checks from specified families (auth, endpoint, cert, channel, authz, disclosure, audit, availability, deployment)
--list-checks           Show all available checks
--wordlist FILE         Username wordlist for brute-force (one per line)
--passlist FILE         Password wordlist for brute-force (one per line)
-o, --output            JSON report path
-q, --quiet             No banner
--no-color              No colors
--depth N               Node browsing depth (default 8)
--timeout N             Connection timeout (default 5)
--endpoints-only        Pre-auth scan only
--cve-only              CVE matching only
--list-cves             Print CVE database
--skip-deep             Skip deep node browsing
--skip-cve              Skip CVE check
--skip-security-checks  Skip security assessment
```

## Connection Strategy

UARecon tries to establish an authenticated session in this order:

1. **Provided certificate** (`-c`/`-k`): uses the supplied client certificate with the requested policy/mode.
2. **No security**: attempts SecurityPolicy None (if accepted, flagged as Critical).
3. **Auto-generated self-signed certificate**: generates a temporary certificate and tries all advertised secure endpoint combinations.

The successful connection strategy is recorded in the report as `connection_context`. When the connection succeeds via auto-generated certificate, the session may be application-authenticated but not necessarily user-authenticated with the provided credentials — the `provided-creds` check evaluates credential acceptance separately.

## Notes

- Some OPC UA deployments use hostnames in certificates and endpoint URLs while clients connect via VPN/IP. This is common and should not automatically be treated as a vulnerability.
- Self-signed OPC UA certificates are common in industrial environments and are reported as informational unless additional validation weaknesses are observed.
- Production-safe findings related to administrative or certificate-management objects are based on read-only exposure unless explicitly verified otherwise.
- The `provided-creds` check distinguishes between actual credential rejection (BadUserAccessDenied, BadIdentityTokenRejected) and application-layer gating (BadCertificateUriInvalid, BadCertificateUntrusted) where the credentials could not be validated because the session was blocked before user authentication.
- CVE matching separates confirmed matches (version-verified), possible matches (product-matched), and protocol-level advisory references (generic OPC UA ecosystem advisories with no product-specific match).

## Disclaimer

Use only on systems you own or are explicitly authorized to assess.
Testing-only checks may impact availability or behavior of production systems.
