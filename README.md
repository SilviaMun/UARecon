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
python3 uarecon.py -t opc.tcp://target:4840 -u user -p pass --cve-only
python3 uarecon.py -t opc.tcp://target:4840 -u user -p pass --check nonce browse-acl

# Brute-force credentials
python3 uarecon.py -t opc.tcp://target:4840 --wordlist users.txt --passlist passwords.txt

# Brute-force with delay between attempts
python3 uarecon.py -t opc.tcp://target:4840 --wordlist users.txt --passlist passwords.txt --delay 0.5

```

## Security checks (32)

| Slug | Check | OWASP Category | Type |
|------|-------|----------------|------|
| `anonymous` | Anonymous Access | Broken Authentication | safe |
| `default-creds` | Default Credentials | Broken Authentication | safe |
| `lockout` | Account Lockout Detection | Broken Authentication | safe |
| `security-policies` | Security Policy Analysis | Cryptographic Failures | safe |
| `user-tokens` | User Token Policies | Cryptographic Failures | safe |
| `server-cert` | Server Certificate Analysis | Cryptographic Failures | safe |
| `cert-hostname` | Certificate Hostname Validation | Cryptographic Failures | safe |
| `cert-bypass` | Certificate Trust Bypass | Cryptographic Failures | safe |
| `nonce` | Server Nonce Quality | Cryptographic Failures | safe |
| `discovery` | Discovery Service Exposure | Information Disclosure | safe |
| `gds-discovery` | FindServersOnNetwork | Information Disclosure | safe |
| `history` | History Read Access | Information Disclosure | safe |
| `redundancy` | Redundancy Info Exposure | Information Disclosure | safe |
| `buildinfo` | Build Information Exposure | Information Disclosure | safe |
| `roles` | Role / Permission Model | Information Disclosure | safe |
| `namespaces` | Namespace Exposure Analysis | Information Disclosure | safe |
| `audit` | Audit Configuration | Security Misconfiguration | safe |
| `session-limits` | Session Limits | Security Misconfiguration | safe |
| `session-timeout` | Session Timeout Policy | Security Misconfiguration | safe |
| `timestamp` | Timestamp Accuracy | Security Misconfiguration | safe |
| `endpoint-url` | Endpoint URL Validation | Security Misconfiguration | safe |
| `max-limits` | Server Limits (DoS Surface) | Security Misconfiguration | safe |
| `sampling` | Sampling Interval Limits | Security Misconfiguration | safe |
| `writable-config` | Server Config Write Access | Broken Access Control | safe |
| `browse-acl` | Browse Access Control | Broken Access Control | safe |
| `gds-trust` | GDS / Trust List Access | Broken Access Control | safe |
| `method-access` | Method Access Control | Broken Access Control | destructive |
| `node-write` | Node Write Verification | Broken Access Control | destructive |
| `transfer-sub` | Subscription Transfer Hijack | Broken Access Control | destructive |
| `sub-abuse` | Subscription Limits | Security Misconfiguration | destructive |
| `register-abuse` | RegisterNodes Abuse | Security Misconfiguration | destructive |
| `max-connections` | Max Connections (DoS) | Security Misconfiguration | destructive |

## --prod

--prod runs only the safe checks and skips all destructive ones.
By default it also introduces a 1 second delay between checks to reduce load on production servers.

```bash
# Default prod mode
python3 uarecon.py -t opc.tcp://target:4840 -u user -p pass --prod

# Slower for fragile systems
python3 uarecon.py -t opc.tcp://target:4840 -u user -p pass --prod --delay 3

# No inter-check delay (not recommended)
python3 uarecon.py -t opc.tcp://target:4840 -u user -p pass --prod --delay 0
```

## CLI Flags

```
-t, --target            opc.tcp://host:port
-u, --user              Username
-p, --password          Password
--prod                  Skip destructive checks (delay 1s between checks)
--delay SEC             Delay between checks in seconds (default: 0, --prod: 1.0)
--check SLUG [SLUG ...] Run only specific check(s) by slug
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

## Notes

Some OPC UA deployments use hostnames in certificates and endpoint URLs while clients connect via VPN/IP. This is common and should not automatically be treated as a vulnerability.
Self-signed OPC UA certificates are common in industrial environments and are reported as informational unless additional validation weaknesses are observed.
Production-safe findings related to administrative or certificate-management objects are based on read-only exposure unless explicitly verified otherwise.

## Disclaimer

Use only on systems you own or are explicitly authorized to assess.
Active/destructive checks may impact availability or behavior of production systems.
