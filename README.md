# UARecon

OPC UA security assessment toolkit — recon, security checks, CVE matching.

## Setup

```bash
git clone https://github.com/SilviaMun/uarecon.git
cd uarecon
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 tools/build_cve_db.py
```

`build_cve_db.py` fetches OPC UA advisories from OPC Foundation + NVD. First run takes a few minutes.

## Quick Start

```bash
# Pre-auth recon (no creds needed)
python3 uarecon.py -t opc.tcp://target:4840 --endpoints-only

# Full scan
python3 uarecon.py -t opc.tcp://target:4840 -u user -p pass

# Production-safe (read-only, 1s delay between checks)
python3 uarecon.py -t opc.tcp://target:4840 -u user -p pass --prod

# With your own certificate
python3 uarecon.py -t opc.tcp://target:4840 -u user -p pass \
  -c /path/to/cert.pem -k /path/to/key.pem

# Run specific checks or families
python3 uarecon.py -t opc.tcp://target:4840 -u user -p pass --check nonce browse-acl
python3 uarecon.py -t opc.tcp://target:4840 -u user -p pass --family auth authz

# CVE matching only
python3 uarecon.py -t opc.tcp://target:4840 -u user -p pass --cve-only

# Brute-force
python3 uarecon.py -t opc.tcp://target:4840 --wordlist users.txt --passlist passwords.txt
```

## Certificates

When you provide `-c`/`-k`, UARecon uses **only** that certificate — no auto-generation, no fallback. The application URI is extracted automatically from the cert's SAN field, so you don't need to pass `--uri` manually.

Without `-c`/`-k`, UARecon tries connecting without a security policy first, then auto-generates a temporary self-signed cert and tries all endpoint combinations advertised by the server.

You can still override the URI with `--uri` if needed.

## Prod vs Testing

`--prod` runs 30 read-only checks — no writes, no resource pressure, no credential guessing. Safe for production OT/ICS.

Without `--prod`, all 40 checks run, including active ones (write attempts, brute-force, resource abuse). Use only on systems you're authorized to test.

```bash
# Slower delay for fragile systems
python3 uarecon.py -t opc.tcp://target:4840 -u user -p pass --prod --delay 3
```

## Check Families

Use `--family` to run only specific families, `--list-checks` to see everything.

| Family | Alias | What it covers |
|--------|-------|----------------|
| authentication_posture | `auth` | Credentials, identity, lockout |
| endpoint_security_posture | `endpoint` | Transport, endpoint config |
| certificate_posture | `cert` | PKI, cert validation |
| secure_channel_posture | `channel` | Nonces, sessions, channels |
| authorization_posture | `authz` | Access control |
| information_disclosure | `disclosure` | Data exposure, fingerprinting |
| audit_posture | `audit` | Logging, diagnostics, timestamps |
| availability_posture | `availability` | Resource limits, DoS surface |
| deployment_posture | `deployment` | Network topology leaks |
| advisory_validation | — | CVE matching |

## Reports

Each scan generates JSON + HTML reports in `reports/`. Use `-o FILE` for a custom JSON path.

## CLI Reference

```
-t, --target            opc.tcp://host:port
-u, --user              Username
-p, --password          Password
-c, --cert              Client certificate (PEM or DER)
-k, --key               Client private key (PEM)
--uri                   Application URI (auto-detected from cert)
--policy                Security policy (Basic256Sha256, Aes128Sha256RsaOaep, Aes256Sha256RsaPss)
--mode                  Security mode (Sign, SignAndEncrypt)
--prod                  Production-safe mode (1s delay, read-only checks only)
--delay SEC             Delay between checks
--check SLUG [...]      Run specific check(s) by slug
--family NAME [...]     Run checks from specific families
--list-checks           Show all checks
--list-cves             Show CVE database
--wordlist FILE         Username wordlist for brute-force
--passlist FILE         Password wordlist for brute-force
-o, --output            JSON report path
-q, --quiet             No banner
--no-color              No ANSI colors
--depth N               Node browsing depth (default 8)
--timeout N             Connection timeout (default 5)
--endpoints-only        Pre-auth endpoint scan only
--cve-only              CVE matching only
--skip-deep             Skip deep node browsing
--skip-cve              Skip CVE matching
--skip-security-checks  Skip security assessment phase
```

## Disclaimer

Use only on systems you own or are authorized to assess. Testing-only checks may impact production systems.
