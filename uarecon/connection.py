from asyncua.sync import Client
from .banner import critical, info, good, bad, warn, tag
from .helpers import (
    uniq,
    classify_error,
    safe_disconnect,
    generate_self_signed_cert,
    cleanup_temp_artifacts,
)


def normalize_policy(policy_uri):
    try:
        if "#" in policy_uri:
            name = policy_uri.split("#")[-1]
        else:
            name = str(policy_uri)
        return name.replace("_", "")
    except Exception:
        return str(policy_uri)


def normalize_mode(mode):
    if hasattr(mode, "name"):
        name = mode.name
        if name == "None_":
            return "None"
        return name

    s = str(mode)
    if "SignAndEncrypt" in s:
        return "SignAndEncrypt"
    if "Sign" in s and "SignAndEncrypt" not in s:
        return "Sign"
    if "None" in s:
        return "None"
    return s


def get_endpoint_combinations(target, timeout=5):
    combos = []
    tmp = None
    try:
        tmp = Client(target, timeout=timeout)
        endpoints = tmp.connect_and_get_server_endpoints()
        for ep in endpoints:
            combos.append((normalize_policy(ep.SecurityPolicyUri), normalize_mode(ep.SecurityMode)))
    except Exception:
        pass
    finally:
        safe_disconnect(tmp)

    return uniq(combos)


def try_connect(target, user, pwd, cert=None, key=None, uri="urn:UARecon",
                policy="Basic256Sha256", mode="Sign", timeout=5):
    findings = []

    def build_client():
        c = Client(target, timeout=timeout)
        c.application_uri = uri
        c.set_user(user)
        c.set_password(pwd)
        return c

    # Strategy 1: provided cert
    if cert and key:
        client = build_client()
        info(f"Using provided certificate: {cert}")
        try:
            client.set_security_string(f"{policy},{mode},{cert},{key}")
            client.connect()
            good(f"Connected with provided certificate ({policy}/{mode})")
            return client, findings, {
                "strategy": "provided-certificate",
                "policy": policy, "mode": mode,
                "user_auth": "username-password",
                "cert_type": "provided",
            }
        except Exception as e:
            warn(f"Provided cert failed: {classify_error(e)}")
            safe_disconnect(client)

    # Strategy 2: no security
    info("Trying connection without security policy...")
    client = Client(target, timeout=timeout)
    client.set_user(user)
    client.set_password(pwd)
    try:
        client.connect()
        critical("CONNECTED WITHOUT SECURITY POLICY (SecurityPolicy None)")
        tag("Cryptographic Failures")
        findings.append({
            "title": "SecurityPolicy None Accepted",
            "severity": "Critical",
            "category": "Cryptographic Failures",
            "description": "Server accepts connections without any security policy. All traffic is unencrypted and unauthenticated.",
            "check": "security-policies",
            "confidence": "high",
            "verification_status": "confirmed-connect",
            "safe_check": True,
            "destructive": False,
            "observation": False,
            "evidence": {
                "policy": "None",
                "mode": "None",
            },
        })
        return client, findings, {
            "strategy": "no-security",
            "policy": "None", "mode": "None",
            "user_auth": "username-password",
            "cert_type": "none",
        }
    except Exception as e:
        good(f"SecurityPolicy None rejected ({classify_error(e)})")
        safe_disconnect(client)

    # Strategy 3: auto-generated self-signed cert
    info("Auto-generating self-signed certificate...")
    auto_cert, auto_key, cnf_path, out_dir, created_tmp = generate_self_signed_cert(uri)
    if not auto_cert:
        bad("Failed to generate certificate (is openssl installed?)")
        return None, findings, None

    endpoint_combos = get_endpoint_combinations(target, timeout=timeout)
    preferred = [(p, m) for (p, m) in endpoint_combos if p != "None" and m != "None"]

    if preferred:
        combos = preferred
        info(f"Using {len(preferred)} security combo(s) advertised by server")
    else:
        policies = uniq([policy, "Basic256Sha256", "Aes128Sha256RsaOaep", "Aes256Sha256RsaPss"])
        modes = uniq([mode, "Sign", "SignAndEncrypt"])
        combos = [(p, m) for p in policies for m in modes]

    last_errors = []

    for pol, mod in combos:
        client = build_client()
        try:
            client.set_security_string(f"{pol},{mod},{auto_cert},{auto_key}")
            client.connect()
            warn(f"Connected using auto-generated self-signed cert ({pol}/{mod})")
            findings.append({
                "title": "Auto-Generated Client Certificate Accepted During Enumeration",
                "severity": "Info",
                "category": "Cryptographic Failures",
                "description": f"Server accepted a session using an auto-generated self-signed client certificate ({pol}/{mod}). "
                               f"This may indicate permissive client certificate trust handling, trust-on-first-use behavior, "
                               f"or reliance on additional authentication factors. Manual verification is required to determine "
                               f"whether certificate trust validation is fully enforced.",
                "check": "cert-bypass",
                "confidence": "low",
                "verification_status": "inconclusive",
                "safe_check": True,
                "destructive": False,
                "observation": True,
                "evidence": {
                    "policy": pol,
                    "mode": mod,
                },
            })
            cleanup_temp_artifacts(auto_cert, auto_key, cnf_path, out_dir, remove_dir=created_tmp)
            return client, findings, {
                "strategy": "auto-generated-certificate",
                "policy": pol, "mode": mod,
                "user_auth": "username-password",
                "cert_type": "auto-generated-self-signed",
            }
        except Exception as e:
            err = classify_error(e)
            last_errors.append(f"{pol}/{mod}: {err}")

            if err == "badcertificateuntrusted":
                good(f"Self-signed cert rejected by {pol}/{mod} (trust validation enabled)")
                findings.append({
                    "title": "Untrusted Client Certificate Rejected",
                    "severity": "Info",
                    "category": "Cryptographic Failures",
                    "description": f"Server rejected an untrusted self-signed certificate on {pol}/{mod}. "
                                   f"This suggests certificate trust validation is enabled.",
                    "check": "cert-bypass",
                    "confidence": "high",
                    "verification_status": "confirmed-reject",
                    "safe_check": True,
                    "destructive": False,
                    "observation": True,
                    "evidence": {
                        "policy": pol,
                        "mode": mod,
                        "error": err,
                    },
                })
                safe_disconnect(client)
                cleanup_temp_artifacts(auto_cert, auto_key, cnf_path, out_dir, remove_dir=created_tmp)
                return None, findings, None

            warn(f"{pol}/{mod} failed: {err}")
            safe_disconnect(client)

    cleanup_temp_artifacts(auto_cert, auto_key, cnf_path, out_dir, remove_dir=created_tmp)

    if last_errors:
        findings.append({
            "title": "Connection Failed",
            "severity": "Info",
            "category": "Connection",
            "description": "All connection strategies failed.",
            "details": last_errors[:10],
            "check": "connection",
            "confidence": "high",
            "verification_status": "failed-all-strategies",
            "safe_check": True,
            "destructive": False,
            "observation": True,
            "evidence": {
                "errors": last_errors[:10],
            },
        })

    return None, findings, None
