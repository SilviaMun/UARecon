from asyncua.sync import Client
from .banner import critical, info, good, bad, warn, tag
from .checks._base import build_finding
from .helpers import (
    uniq,
    classify_error,
    safe_disconnect,
    generate_self_signed_cert,
    cleanup_temp_artifacts,
    extract_uri_from_cert,
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


def _build_combos(target, policy, mode, timeout):
    endpoint_combos = get_endpoint_combinations(target, timeout=timeout)
    preferred = [(p, m) for (p, m) in endpoint_combos if p != "None" and m != "None"]

    if preferred:
        info(f"Server advertises {len(preferred)} security combo(s)")
        return preferred

    policies = uniq([policy, "Basic256Sha256", "Aes128Sha256RsaOaep", "Aes256Sha256RsaPss"])
    modes = uniq([mode, "Sign", "SignAndEncrypt"])
    return [(p, m) for p in policies for m in modes]


def try_connect(target, user, pwd, cert=None, key=None, uri="urn:UARecon",
                policy="Basic256Sha256", mode="Sign", timeout=5,
                report_data=None):
    findings = []

    if cert and uri == "urn:UARecon":
        extracted = extract_uri_from_cert(cert)
        if extracted:
            info(f"Auto-detected URI from certificate: {extracted}")
            uri = extracted

    def build_client():
        c = Client(target, timeout=timeout)
        c.application_uri = uri
        c.set_user(user)
        c.set_password(pwd)
        return c

    # --- Provided certificate: use it exclusively, no fallback ---
    if cert and key:
        info(f"Using provided certificate: {cert}")
        combos = _build_combos(target, policy, mode, timeout)

        last_errors = []
        for pol, mod in combos:
            client = build_client()
            try:
                client.set_security_string(f"{pol},{mod},{cert},{key}")
                client.connect()
                good(f"Connected with provided certificate ({pol}/{mod})")
                return client, findings, {
                    "strategy": "provided-certificate",
                    "policy": pol, "mode": mod,
                    "user_auth": "username-password",
                    "cert_type": "provided",
                }
            except Exception as e:
                err = classify_error(e)
                last_errors.append(f"{pol}/{mod}: {err}")
                warn(f"Provided cert {pol}/{mod} failed: {err}")
                safe_disconnect(client)

        bad("All combinations failed with provided certificate")
        return None, findings, None

    # --- No certificate provided: try no-security, then auto-generate ---

    info("Trying connection without security policy...")
    client = Client(target, timeout=timeout)
    client.set_user(user)
    client.set_password(pwd)
    try:
        client.connect()
        critical("CONNECTED WITHOUT SECURITY POLICY (SecurityPolicy None)")
        tag("Cryptographic Failures")
        findings.append(build_finding(
            "conn-policy-none",
            "Server accepts connections without any security policy. "
            "All traffic is unencrypted and unauthenticated.",
            report_data=report_data,
            confidence="high",
            verification_status="confirmed-connect",
            safe_check=True,
            destructive=False,
            evidence={"policy": "None", "mode": "None"},
        ))
        return client, findings, {
            "strategy": "no-security",
            "policy": "None", "mode": "None",
            "user_auth": "username-password",
            "cert_type": "none",
        }
    except Exception as e:
        good(f"SecurityPolicy None rejected ({classify_error(e)})")
        safe_disconnect(client)

    info("Auto-generating self-signed certificate...")
    auto_cert, auto_key, cnf_path, out_dir, created_tmp = generate_self_signed_cert(uri)
    if not auto_cert:
        bad("Failed to generate certificate (is openssl installed?)")
        return None, findings, None

    combos = _build_combos(target, policy, mode, timeout)
    last_errors = []

    for pol, mod in combos:
        client = build_client()
        try:
            client.set_security_string(f"{pol},{mod},{auto_cert},{auto_key}")
            client.connect()
            warn(f"Connected using auto-generated self-signed cert ({pol}/{mod})")
            findings.append(build_finding(
                "conn-auto-cert",
                f"Server accepted a session using an auto-generated self-signed client certificate ({pol}/{mod}). "
                f"This may indicate permissive client certificate trust handling, trust-on-first-use behavior, "
                f"or reliance on additional authentication factors. Manual verification is required to determine "
                f"whether certificate trust validation is fully enforced.",
                report_data=report_data,
                confidence="low",
                verification_status="inconclusive",
                safe_check=True,
                destructive=False,
                evidence={"policy": pol, "mode": mod},
            ))
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
                findings.append(build_finding(
                    "conn-cert-rejected",
                    f"Server rejected an untrusted self-signed certificate on {pol}/{mod}. "
                    f"This suggests certificate trust validation is enabled.",
                    report_data=report_data,
                    confidence="high",
                    verification_status="confirmed-reject",
                    safe_check=True,
                    destructive=False,
                    evidence={"policy": pol, "mode": mod, "error": err},
                ))
                safe_disconnect(client)
                cleanup_temp_artifacts(auto_cert, auto_key, cnf_path, out_dir, remove_dir=created_tmp)
                return None, findings, None

            warn(f"{pol}/{mod} failed: {err}")
            safe_disconnect(client)

    cleanup_temp_artifacts(auto_cert, auto_key, cnf_path, out_dir, remove_dir=created_tmp)

    if last_errors:
        findings.append(build_finding(
            "conn-failed",
            "All connection strategies failed.",
            report_data=report_data,
            confidence="high",
            verification_status="failed-all-strategies",
            safe_check=True,
            destructive=False,
            evidence={"errors": last_errors[:10]},
        ))

    return None, findings, None
