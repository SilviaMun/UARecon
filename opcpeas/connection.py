from opcua import Client
from .banner import info, good, bad, warn
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
            return policy_uri.split("#")[-1]
        return str(policy_uri)
    except Exception:
        return str(policy_uri)


def normalize_mode(mode):
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


def try_connect(target, user, pwd, cert=None, key=None, uri="urn:OpcPEAS",
                policy="Basic256Sha256", mode="Sign", timeout=5):
    findings = []

    def build_client():
        c = Client(target, timeout=timeout)
        c.application_uri = uri
        c.set_user(user)
        c.set_password(pwd)
        return c

    if cert and key:
        client = build_client()
        info(f"Using provided certificate: {cert}")
        try:
            client.set_security_string(f"{policy},{mode},{cert},{key}")
            client.connect()
            good(f"Connected with provided certificate ({policy}/{mode})")
            return client, findings
        except Exception as e:
            warn(f"Provided cert failed: {classify_error(e)}")
            safe_disconnect(client)

    info("Trying connection without security policy...")
    client = Client(target, timeout=timeout)
    client.set_user(user)
    client.set_password(pwd)
    try:
        client.connect()
        bad("CONNECTED WITHOUT SECURITY POLICY (SecurityPolicy None)")
        findings.append({
            "title": "SecurityPolicy None Accepted",
            "severity": "High",
            "description": "Server accepts connections without any security policy."
        })
        return client, findings
    except Exception as e:
        good(f"SecurityPolicy None rejected ({classify_error(e)})")
        safe_disconnect(client)

    info("Auto-generating self-signed certificate...")
    auto_cert, auto_key, cnf_path, out_dir, created_tmp = generate_self_signed_cert(uri)
    if not auto_cert:
        bad("Failed to generate certificate (is openssl installed?)")
        return None, findings

    endpoint_combos = get_endpoint_combinations(target, timeout=timeout)
    preferred = [(p, m) for (p, m) in endpoint_combos if p != "None" and m != "None"]

    if preferred:
        combos = preferred
        info(f"Using {len(preferred)} security combo(s) advertised by server")
    else:
        policies = uniq([policy, "Basic256Sha256", "Aes128_Sha256_RsaOaep", "Aes256_Sha256_RsaPss"])
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
                "title": "Untrusted Client Certificate Appears Accepted",
                "severity": "Medium",
                "description": f"Server allowed a session using an auto-generated self-signed certificate ({pol}/{mod})."
            })
            cleanup_temp_artifacts(auto_cert, auto_key, cnf_path, out_dir, remove_dir=created_tmp)
            return client, findings
        except Exception as e:
            err = classify_error(e)
            last_errors.append(f"{pol}/{mod}: {err}")

            if err == "badcertificateuntrusted":
                good(f"Self-signed cert rejected by {pol}/{mod} (trust validation enabled)")
                findings.append({
                    "title": "Certificate Trust Validation Enabled",
                    "severity": "Info",
                    "description": f"Server rejected an untrusted self-signed certificate on {pol}/{mod}"
                })
                safe_disconnect(client)
                cleanup_temp_artifacts(auto_cert, auto_key, cnf_path, out_dir, remove_dir=created_tmp)
                return None, findings

            warn(f"{pol}/{mod} failed: {err}")
            safe_disconnect(client)

    cleanup_temp_artifacts(auto_cert, auto_key, cnf_path, out_dir, remove_dir=created_tmp)

    if last_errors:
        findings.append({
            "title": "Connection Failed",
            "severity": "Info",
            "description": "All connection strategies failed",
            "details": last_errors[:10]
        })

    return None, findings
