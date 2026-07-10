import datetime
import time
import math
import re
from urllib.parse import urlparse

from asyncua.sync import Client
from asyncua import ua

from .banner import critical, bad, warn, good, info, section, tag
from .helpers import (
    safe_disconnect, classify_error, sr, sn, sc,
    generate_expired_cert, generate_wrong_uri_cert,
    cleanup_temp_artifacts, uniq,
)


def add_finding(
    report_data,
    title,
    severity,
    category,
    description,
    check=None,
    confidence="medium",
    verification_status=None,
    safe_check=None,
    destructive=None,
    evidence=None,
    observation=False,
):
    report_data["findings"].append({
        "title": title,
        "severity": severity,
        "category": category,
        "description": description,
        "check": check,
        "confidence": confidence,
        "verification_status": verification_status,
        "safe_check": safe_check,
        "destructive": destructive,
        "evidence": evidence,
        "observation": observation,
    })


def add_observation(
    report_data,
    title,
    category,
    description,
    check=None,
    confidence="low",
    verification_status=None,
    safe_check=True,
    destructive=False,
    evidence=None,
):
    add_finding(
        report_data=report_data,
        title=title,
        severity="Info",
        category=category,
        description=description,
        check=check,
        confidence=confidence,
        verification_status=verification_status,
        safe_check=safe_check,
        destructive=destructive,
        evidence=evidence,
        observation=True,
    )


SENSITIVE_KEYWORDS = {
    "password": 5,
    "passwd": 5,
    "pwd": 5,
    "secret": 4,
    "token": 4,
    "api_key": 5,
    "apikey": 5,
    "client_secret": 5,
    "authorization": 4,
    "bearer": 4,
    "private_key": 8,
    "connection_string": 5,
    "connectionstring": 5,
    "jdbc": 4,
    "odbc": 4,
    "mqtt_password": 5,
    "ftp_password": 5,
}

BENIGN_KEYWORDS = {
    "token_type": -4,
    "public_key": -5,
    "keycode": -3,
    "keyboard": -3,
    "password_policy": -3,
    "has_password": -2,
    "session_timeout": -2,
    "build_number": -2,
}

EMAIL_RE = re.compile(r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b", re.I)
JWT_RE = re.compile(r"^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$")
PRIVATE_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
)
CONNSTR_RE = re.compile(r"(password\s*=|pwd\s*=|user id\s*=|uid\s*=|username\s*=)", re.I)
PEM_RE = re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----")
BEARER_RE = re.compile(r"^Bearer\s+[A-Za-z0-9\-_\.=]+$", re.I)


def normalize_text(s):
    if s is None:
        return ""
    s = str(s).strip()
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s)
    s = s.replace("-", "_").replace(" ", "_").lower()
    return s


def shannon_entropy(s):
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


def mask_value(v, max_len=120):
    s = "" if v is None else str(v)
    if not s:
        return ""
    if len(s) <= 8:
        return "***"
    if len(s) > max_len:
        s = s[:max_len] + "..."
    return f"{s[:4]}***{s[-4:]}"


def score_sensitive_content(path, browse_name, value):
    score = 0
    reasons = []

    key_material = " ".join([
        normalize_text(path),
        normalize_text(browse_name),
    ])

    for kw, pts in SENSITIVE_KEYWORDS.items():
        if kw in key_material:
            score += pts
            reasons.append(f"keyword:{kw}")

    for kw, pts in BENIGN_KEYWORDS.items():
        if kw in key_material:
            score += pts
            reasons.append(f"benign:{kw}")

    sval = "" if value is None else str(value).strip()

    if not sval:
        return score, reasons

    if EMAIL_RE.search(sval):
        score += 2
        reasons.append("value:email")

    if JWT_RE.match(sval) and len(sval) > 40:
        score += 5
        reasons.append("value:jwt")

    if BEARER_RE.match(sval) and len(sval) > 20:
        score += 5
        reasons.append("value:bearer")

    if PRIVATE_IP_RE.search(sval):
        score += 2
        reasons.append("value:private_ip")

    if CONNSTR_RE.search(sval):
        score += 5
        reasons.append("value:connection_string")

    if PEM_RE.search(sval):
        score += 8
        reasons.append("value:private_key_pem")

    if len(sval) >= 16:
        entropy = shannon_entropy(sval)
        if entropy >= 3.5:
            score += 2
            reasons.append(f"value:high_entropy:{entropy:.2f}")

    placeholders = {"test", "example", "dummy", "changeme", "password", "admin", "guest"}
    if sval.lower() in placeholders:
        score -= 2
        reasons.append("value:placeholder")

    return score, reasons


def check_sensitive_data_exposure(client, report_data, max_nodes=1000, threshold=6, include_diagnostics=False):
    section("SENSITIVE DATA EXPOSURE")

    nodes = report_data.get("all_nodes", [])
    if not nodes:
        info("No enumerated nodes available (run deep enumeration first)")
        return

    noisy_path_parts = [
        "/ServerDiagnostics/",
        "/SessionsDiagnosticsSummary/",
        "/SubscriptionDiagnosticsArray/",
        "/VendorServerInfo/ObjectStatistics/",
    ]

    matches = []
    tested = 0

    for n in nodes[:max_nodes]:
        path = n.get("path", "")
        browse_name = n.get("browse_name", "") or n.get("name", "") or (path.split("/")[-1] if path else "")
        value = n.get("value", None)

        if not include_diagnostics and any(part in path for part in noisy_path_parts):
            continue

        if value is None:
            nid = n.get("node_id", "")
            if nid:
                try:
                    value = client.get_node(nid).read_value()
                except Exception:
                    continue
            else:
                continue

        tested += 1
        score, reasons = score_sensitive_content(path, browse_name, value)

        if score >= threshold:
            sample = mask_value(value)
            warn(f"SENSITIVE-LOOKING VALUE: {path or browse_name} | score={score} | sample={sample}")
            tag("Information Disclosure")
            matches.append({
                "path": path,
                "browse_name": browse_name,
                "score": score,
                "reasons": reasons,
                "sample": sample,
            })

    if matches:
        add_finding(
            report_data,
            "Potential Sensitive Data Exposed",
            "Medium",
            "Information Disclosure",
            f"Read access exposed {len(matches)} node(s) with potentially sensitive content patterns. "
            f"Manual validation is required to distinguish true secrets from benign operational strings.",
            check="sensitive-data",
            confidence="medium",
            verification_status="pattern-match",
            safe_check=True,
            destructive=False,
            evidence=matches[:20],
        )
    else:
        good(f"No obvious sensitive-data patterns found in {tested} nodes")


def check_anonymous_access(target, report_data, timeout=5):
    section("ANONYMOUS ACCESS CHECK")
    client = None
    try:
        client = Client(target, timeout=timeout)
        client.connect()

        can_browse = False
        can_read = False

        warn("Anonymous session accepted")

        try:
            objects = client.get_objects_node()
            children = objects.get_children()
            if children:
                can_browse = True
                bad(f"Anonymous user can browse Objects node ({len(children)} children)")
                tag("Broken Access Control")
        except Exception:
            pass

        try:
            current_time = client.get_node("i=2258").read_value()
            if current_time is not None:
                can_read = True
                info(f"Anonymous read succeeded (CurrentTime={current_time})")
        except Exception:
            pass

        if can_browse or can_read:
            critical("ANONYMOUS ACCESS CONFIRMED WITH REAL PRIVILEGES")
            tag("Broken Authentication")
            add_finding(
                report_data,
                "Anonymous Access Allowed",
                "Critical",
                "Broken Authentication",
                "Server accepted anonymous access and allowed browse/read operations. "
                "Any network-reachable attacker can access the OPC UA server without credentials.",
                check="anonymous",
                confidence="high",
                verification_status="confirmed-read",
                safe_check=True,
                destructive=False,
            )
        else:
            warn("Anonymous session accepted, but no meaningful browse/read confirmed")
            add_finding(
                report_data,
                "Anonymous Session Accepted",
                "High",
                "Broken Authentication",
                "Server accepted an anonymous session, but the effective privileges could not be fully confirmed. "
                "Review whether anonymous sessions are intended.",
                check="anonymous",
                confidence="medium",
                verification_status="session-only",
                safe_check=True,
                destructive=False,
            )

        safe_disconnect(client)
        return True

    except Exception as e:
        err = classify_error(e)
        if "badidentitytoken" in err or "baduseraccessdenied" in err:
            good(f"Anonymous access rejected ({err})")
        else:
            info(f"Anonymous connect failed: {err}")
        safe_disconnect(client)
        return False


def check_audit_config(client, report_data):
    section("AUDIT CONFIGURATION")
    try:
        auditing = client.get_node("i=2994").read_value()
        if auditing:
            good("Auditing is ENABLED")
        else:
            bad("AUDITING IS DISABLED - operations are not being logged")
            tag("Security Misconfiguration")
            add_finding(
                report_data,
                "Auditing Disabled",
                "High",
                "Security Misconfiguration",
                "Server auditing is disabled. Malicious operations will not be logged or traced.",
                check="audit",
                confidence="high",
                verification_status="confirmed-read",
                safe_check=True,
                destructive=False,
            )
    except Exception:
        warn("Could not read auditing status (node i=2994)")

    try:
        diag_enabled = client.get_node("i=2274").read_value()
        if diag_enabled:
            info("Server diagnostics enabled")
        else:
            info("Server diagnostics disabled")
    except Exception:
        pass


def check_security_policies(report_data):
    section("SECURITY POLICY ANALYSIS")
    endpoints = report_data.get("endpoints", [])
    if not endpoints:
        info("No endpoints to analyze (run endpoint enumeration first)")
        return

    has_none = False
    deprecated_policies = set()
    legacy_policies = set()
    sign_only_policies = set()
    has_strong = False

    for ep in endpoints:
        policy = ep.get("policy", "")
        mode = ep.get("mode", "")

        if policy == "None" and mode == "None":
            has_none = True

        if policy == "Basic128Rsa15":
            deprecated_policies.add(policy)
            bad(f"DEPRECATED POLICY: {ep['url']} | {mode} | {policy}")
            tag("Cryptographic Failures")

        if policy == "Basic256":
            legacy_policies.add(policy)
            warn(f"LEGACY POLICY: {ep['url']} | {mode} | {policy}")
            tag("Cryptographic Failures")

        if mode == "Sign" and policy != "None":
            sign_only_policies.add(policy)
            warn(f"SIGN-ONLY (no encryption): {ep['url']} | {policy}")
            tag("Cryptographic Failures")

        if policy in ("Basic256Sha256", "Aes128Sha256RsaOaep", "Aes256Sha256RsaPss") and mode == "SignAndEncrypt":
            has_strong = True

    if has_none:
        bad("SecurityPolicy None is available")
        tag("Cryptographic Failures")
        add_finding(
            report_data,
            "SecurityPolicy None Available",
            "High",
            "Cryptographic Failures",
            "Server advertises at least one endpoint with SecurityPolicy None. "
            "This may allow unencrypted transport depending on the authentication mode and access control.",
            check="security-policies",
            confidence="high",
            verification_status="endpoint-analysis",
            safe_check=True,
            destructive=False,
            evidence={"has_none": True},
        )

    if deprecated_policies:
        add_finding(
            report_data,
            f"Deprecated Security Policy: {', '.join(sorted(deprecated_policies))}",
            "High",
            "Cryptographic Failures",
            f"Server offers deprecated policies: {', '.join(sorted(deprecated_policies))}. "
            f"Basic128Rsa15 is deprecated and should be disabled.",
            check="security-policies",
            confidence="high",
            verification_status="endpoint-analysis",
            safe_check=True,
            destructive=False,
            evidence={"deprecated_policies": sorted(deprecated_policies)},
        )

    if legacy_policies:
        add_finding(
            report_data,
            f"Legacy Security Policy: {', '.join(sorted(legacy_policies))}",
            "Medium",
            "Cryptographic Failures",
            f"Server offers legacy policy {', '.join(sorted(legacy_policies))}. "
            f"Review whether newer policies can be enforced instead.",
            check="security-policies",
            confidence="high",
            verification_status="endpoint-analysis",
            safe_check=True,
            destructive=False,
            evidence={"legacy_policies": sorted(legacy_policies)},
        )

    if sign_only_policies:
        add_finding(
            report_data,
            "Sign-Only Mode Available (No Encryption)",
            "Medium",
            "Cryptographic Failures",
            f"Endpoints with Sign-only mode (no encryption) are available for: "
            f"{', '.join(sorted(sign_only_policies))}. "
            f"Traffic integrity is protected, but data confidentiality is not.",
            check="security-policies",
            confidence="high",
            verification_status="endpoint-analysis",
            safe_check=True,
            destructive=False,
            evidence={"sign_only_policies": sorted(sign_only_policies)},
        )

    if has_strong:
        good("At least one strong endpoint available (SignAndEncrypt with modern policy)")
    elif not has_none:
        warn("No strong SignAndEncrypt endpoints with modern policies found")

    anon_endpoints = [ep for ep in endpoints if "Anonymous" in ep.get("tokens", [])]
    if anon_endpoints:
        info(
            f"Anonymous token advertised on {len(anon_endpoints)}/{len(endpoints)} endpoint(s) "
            "(actual access must be confirmed separately)"
        )
    else:
        good("No endpoints advertise anonymous tokens")


def check_server_certificate(target, report_data, timeout=5):
    section("SERVER CERTIFICATE ANALYSIS")
    tmp = None
    try:
        tmp = Client(target, timeout=timeout)
        endpoints = tmp.connect_and_get_server_endpoints()
    except Exception as e:
        warn(f"Could not retrieve endpoints for cert analysis: {e}")
        return
    finally:
        safe_disconnect(tmp)

    checked = set()
    for ep in endpoints:
        cert_bytes = getattr(ep, "ServerCertificate", None)
        if not cert_bytes or bytes(cert_bytes) in checked:
            continue
        checked.add(bytes(cert_bytes))

        try:
            from cryptography import x509
            from cryptography.hazmat.primitives.asymmetric import rsa, ec

            cert = x509.load_der_x509_certificate(bytes(cert_bytes))
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            not_after = cert.not_valid_after_utc
            now = datetime.datetime.now(datetime.timezone.utc)

            info(f"Subject: {subject}")
            info(f"Issuer: {issuer}")
            info(f"Valid until: {not_after}")

            if subject == issuer:
                info("Server certificate is self-signed (common in OPC UA deployments)")
                add_observation(
                    report_data,
                    "Self-Signed Server Certificate",
                    "Cryptographic Failures",
                    f"Server uses a self-signed certificate ({subject}). "
                    f"This is common in OPC UA and does not necessarily indicate a vulnerability.",
                    check="server-cert",
                    confidence="high",
                    verification_status="confirmed-read",
                    safe_check=True,
                    destructive=False,
                    evidence={"subject": subject, "issuer": issuer},
                )

            if not_after < now:
                bad(f"Server certificate EXPIRED on {not_after}")
                tag("Cryptographic Failures")
                add_finding(
                    report_data,
                    "Expired Server Certificate",
                    "High",
                    "Cryptographic Failures",
                    f"Server certificate expired on {not_after}. Clients may skip validation to connect.",
                    check="server-cert",
                    confidence="high",
                    verification_status="confirmed-read",
                    safe_check=True,
                    destructive=False,
                    evidence={"not_after": str(not_after)},
                )
            else:
                days_left = (not_after - now).days
                if days_left < 30:
                    warn(f"Certificate expires in {days_left} days")
                else:
                    good(f"Certificate valid for {days_left} more days")

            pub_key = cert.public_key()
            if isinstance(pub_key, rsa.RSAPublicKey):
                key_size = pub_key.key_size
                info(f"Key: RSA {key_size}-bit")
                if key_size < 2048:
                    bad(f"WEAK RSA KEY: {key_size}-bit (minimum 2048 recommended)")
                    tag("Cryptographic Failures")
                    add_finding(
                        report_data,
                        "Weak Server Certificate Key",
                        "High",
                        "Cryptographic Failures",
                        f"Server certificate uses {key_size}-bit RSA. Keys < 2048 bits are weak by modern standards.",
                        check="server-cert",
                        confidence="high",
                        verification_status="confirmed-read",
                        safe_check=True,
                        destructive=False,
                        evidence={"rsa_key_bits": key_size},
                    )
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                key_size = pub_key.key_size
                info(f"Key: EC {key_size}-bit")
                if key_size < 256:
                    warn(f"Weak EC key: {key_size}-bit")

            try:
                san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                uris = san.value.get_values_for_type(x509.UniformResourceIdentifier)
                for uri in uris:
                    info(f"SAN URI: {uri}")
            except x509.ExtensionNotFound:
                warn("No SubjectAlternativeName extension (some clients may reject)")

        except ImportError:
            warn("cryptography library not available for cert analysis")
        except Exception as e:
            warn(f"Certificate parsing failed: {e}")


def check_discovery_exposure(target, report_data, timeout=5):
    section("DISCOVERY SERVICE EXPOSURE")
    tmp = None
    try:
        tmp = Client(target, timeout=timeout)
        servers = tmp.connect_and_find_servers()
        if servers:
            for srv in servers:
                name = getattr(srv, "ApplicationName", None)
                app_uri = getattr(srv, "ApplicationUri", "")
                disc_urls = getattr(srv, "DiscoveryUrls", []) or []
                label = name.Text if name else app_uri
                info(f"  Server: {label}")
                for url in disc_urls:
                    info(f"    URL: {url}")

            if len(servers) > 1:
                warn(f"FindServers returned {len(servers)} server(s)")
                tag("Information Disclosure")
                add_finding(
                    report_data,
                    "Discovery Service Exposes Multiple Servers",
                    "Medium",
                    "Information Disclosure",
                    f"FindServers returned {len(servers)} server(s). "
                    f"This may expose additional OPC UA targets and internal topology.",
                    check="discovery",
                    confidence="medium",
                    verification_status="confirmed-read",
                    safe_check=True,
                    destructive=False,
                    evidence={"server_count": len(servers)},
                )
            else:
                good("FindServers returned only self (no extra topology)")
        else:
            good("FindServers returned empty")
    except Exception as e:
        info(f"FindServers not available: {classify_error(e)}")
    finally:
        safe_disconnect(tmp)


def check_session_limits(client, report_data):
    section("SESSION SECURITY")
    try:
        max_sessions = client.get_node("i=11706").read_value()
        if max_sessions is not None:
            if max_sessions == 0:
                warn("MaxSessionCount = 0 (unlimited or unspecified)")
                add_observation(
                    report_data,
                    "Session Count Not Explicitly Limited",
                    "Security Misconfiguration",
                    "MaxSessionCount is 0 (unlimited or unspecified). This may increase DoS surface, "
                    "but impact depends on implementation-specific controls.",
                    check="session-limits",
                    confidence="low",
                    verification_status="confirmed-read",
                    safe_check=True,
                    destructive=False,
                    evidence={"max_session_count": max_sessions},
                )
            else:
                info(f"MaxSessionCount: {max_sessions}")
    except Exception:
        pass

    try:
        current = client.get_node("i=2277").read_value()
        cumulated = client.get_node("i=2278").read_value()
        if current is not None:
            info(f"Current sessions: {current}")
        if cumulated is not None:
            info(f"Cumulated sessions: {cumulated}")
    except Exception:
        pass

    try:
        timeout_val = client.get_node("i=2281").read_value()
        if timeout_val is not None and timeout_val > 0:
            warn(f"SessionTimeoutCount: {timeout_val} (sessions timing out may indicate poor cleanup)")
    except Exception:
        pass


def check_timestamp_accuracy(client, report_data):
    section("TIMESTAMP VALIDATION")
    try:
        server_time = client.get_node("i=2258").read_value()
        if server_time:
            now = datetime.datetime.now(datetime.timezone.utc)
            st = server_time.replace(tzinfo=datetime.timezone.utc) if server_time.tzinfo is None else server_time
            drift = abs((now - st).total_seconds())

            info(f"Server time: {st}")
            info(f"Local time:  {now.strftime('%Y-%m-%d %H:%M:%S+00:00')}")

            if drift > 300:
                warn(f"Clock drift detected: {drift:.0f}s (>5 min)")
                tag("Security Misconfiguration")
                add_observation(
                    report_data,
                    "Clock Drift Detected",
                    "Security Misconfiguration",
                    f"Server clock differs from local time by {drift:.0f} seconds. "
                    f"This may indicate poor time synchronization or timezone/configuration mismatch. "
                    f"Security impact depends on whether the deployment relies on strict time-based validation.",
                    check="timestamp",
                    confidence="medium",
                    verification_status="confirmed-read",
                    safe_check=True,
                    destructive=False,
                    evidence={"drift_seconds": int(drift)},
                )
            elif drift > 60:
                warn(f"Clock drift: {drift:.0f}s (>1 min)")
            else:
                good(f"Clock drift: {drift:.0f}s (acceptable)")
    except Exception:
        warn("Could not read server timestamp (node i=2258)")


def check_user_token_policies(report_data):
    section("USER TOKEN POLICY ANALYSIS")
    endpoints = report_data.get("endpoints", [])
    if not endpoints:
        return

    possible_plaintext_password = False
    affected = []
    for ep in endpoints:
        policy = ep.get("policy", "")
        mode = ep.get("mode", "")
        tokens = ep.get("tokens", [])

        if "UserName" in tokens and policy == "None" and mode == "None":
            possible_plaintext_password = True
            affected.append({
                "url": ep.get("url"),
                "policy": policy,
                "mode": mode,
                "tokens": tokens,
            })

    if possible_plaintext_password:
        bad("Potential plaintext username/password transport detected")
        tag("Cryptographic Failures")
        add_finding(
            report_data,
            "Potential Plaintext Password Transmission",
            "High",
            "Cryptographic Failures",
            "At least one endpoint accepts UserName authentication over SecurityPolicy None. "
            "This may expose credentials in plaintext unless the UserIdentityToken has separate protection. "
            "Manual verification is recommended.",
            check="user-tokens",
            confidence="medium",
            verification_status="endpoint-analysis",
            safe_check=True,
            destructive=False,
            evidence={"affected_endpoints": affected},
        )
    else:
        good("No obvious plaintext password transport detected")


def check_writable_server_config(client, report_data):
    section("SERVER CONFIGURATION WRITE ACCESS")
    config_nodes = [
        ("i=2274", "EnabledFlag (Diagnostics)"),
        ("i=2994", "EnabledFlag (Auditing)"),
    ]

    for nid, label in config_nodes:
        try:
            node = client.get_node(nid)
            ual = node.get_user_access_level()
            access = str(ual)
            writable = "Write" in access or (isinstance(ual, int) and (ual & 0x02))
            if writable:
                bad(f"WRITABLE CONFIG NODE: {label} ({nid})")
                tag("Broken Access Control")
                add_finding(
                    report_data,
                    f"Writable Server Config: {label}",
                    "High",
                    "Broken Access Control",
                    f"Configuration node {label} ({nid}) is writable by current user. "
                    f"Attacker could modify server behavior.",
                    check="writable-config",
                    confidence="high",
                    verification_status="confirmed-write-capable",
                    safe_check=True,
                    destructive=False,
                    evidence={"node_id": nid, "label": label},
                )
            else:
                good(f"{label} ({nid}) is read-only for current user")
        except Exception:
            pass


DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", ""),
    ("user", "user"),
    ("user", "password"),
    ("operator", "operator"),
    ("guest", "guest"),
    ("root", "root"),
    ("admin", "1234"),
    ("admin", "admin123"),
    ("opcua", "opcua"),
]


def check_default_credentials(target, report_data, timeout=5):
    section("DEFAULT CREDENTIALS CHECK")
    found = []

    for user, pwd in DEFAULT_CREDENTIALS:
        client = None
        try:
            client = Client(target, timeout=timeout)
            client.set_user(user)
            client.set_password(pwd)
            client.connect()
            display = f"{user}:{pwd}" if pwd else f"{user}:(empty)"
            critical(f"DEFAULT CREDENTIALS ACCEPTED: {display}")
            tag("Broken Authentication")
            found.append(display)
            safe_disconnect(client)
        except Exception:
            safe_disconnect(client)

    if found:
        add_finding(
            report_data,
            "Default Credentials Accepted",
            "Critical",
            "Broken Authentication",
            f"Server accepted default credentials: {', '.join(found)}. "
            f"Attacker can authenticate without knowing valid credentials.",
            check="default-creds",
            confidence="high",
            verification_status="confirmed-auth",
            safe_check=False,
            destructive=True,
            evidence={"accepted_credentials": found},
        )
    else:
        good(f"None of {len(DEFAULT_CREDENTIALS)} default credential pairs accepted")


def check_bruteforce(target, report_data, userlist, passlist, timeout=5, delay=0):
    section("BRUTE-FORCE CREDENTIAL CHECK")

    users = []
    passwords = []
    try:
        with open(userlist, "r") as f:
            users = [line.strip() for line in f if line.strip()]
    except Exception as e:
        bad(f"Cannot read wordlist {userlist}: {e}")
        return
    try:
        with open(passlist, "r") as f:
            passwords = [line.strip() for line in f if line.strip()]
    except Exception as e:
        bad(f"Cannot read passlist {passlist}: {e}")
        return

    total = len(users) * len(passwords)
    info(f"Testing {len(users)} users × {len(passwords)} passwords = {total} combinations")

    found = []
    tested = 0
    for user in users:
        for pwd in passwords:
            tested += 1
            client = None
            try:
                client = Client(target, timeout=timeout)
                client.set_user(user)
                client.set_password(pwd)
                client.connect()
                display = f"{user}:{pwd}" if pwd else f"{user}:(empty)"
                critical(f"VALID CREDENTIALS: {display}  [{tested}/{total}]")
                tag("Broken Authentication")
                found.append(display)
                safe_disconnect(client)
            except Exception:
                safe_disconnect(client)
            if delay > 0 and tested < total:
                time.sleep(delay)

        if tested % 50 == 0 or tested == total:
            info(f"Progress: {tested}/{total} ({len(found)} found)")

    if found:
        add_finding(
            report_data,
            "Valid Credentials Found (Brute-Force)",
            "Critical",
            "Broken Authentication",
            f"Brute-force attack found {len(found)} valid credential(s): {', '.join(found)}.",
            check="bruteforce",
            confidence="high",
            verification_status="confirmed-auth",
            safe_check=False,
            destructive=True,
            evidence={"accepted_credentials": found, "tested_combinations": total},
        )
    else:
        good(f"No valid credentials found in {total} combinations")


def check_account_lockout(target, report_data, timeout=5):
    section("ACCOUNT LOCKOUT DETECTION")
    test_users = ["admin", "user", "operator"]
    fake_pwd = "UARecon_wrong_pwd_!"
    attempts = 10
    observed_failed_attempts = 0
    last_error = ""
    inconclusive = False

    for test_user in test_users:
        observed_failed_attempts = 0

        for _ in range(attempts):
            client = None
            try:
                client = Client(target, timeout=timeout)
                client.set_user(test_user)
                client.set_password(fake_pwd)
                client.connect()
                safe_disconnect(client)
                observed_failed_attempts = 0
                break
            except Exception as e:
                err = classify_error(e)
                last_error = err
                safe_disconnect(client)

                if "baduseraccessdenied" in err or "badidentitytoken" in err:
                    observed_failed_attempts += 1
                else:
                    inconclusive = True
                    break

        if observed_failed_attempts > 0 or inconclusive:
            break

    if observed_failed_attempts >= attempts:
        warn(f"No lockout observed after {attempts} failed attempts")
        add_observation(
            report_data,
            "No Visible Account Lockout Observed",
            "Broken Authentication",
            f"Server returned authentication failures for {attempts} invalid login attempts without visible lockout. "
            f"This does not exclude throttling, upstream controls, or delayed lockout mechanisms.",
            check="lockout",
            confidence="low",
            verification_status="inconclusive-no-lockout-observed",
            safe_check=False,
            destructive=True,
            evidence={
                "attempts": attempts,
                "test_users": test_users,
                "last_error": last_error,
            },
        )
    elif observed_failed_attempts > 0:
        good(f"Authentication failures observed with possible lockout/throttling behavior (last error: {last_error})")
    else:
        info(f"Could not determine lockout behavior (error: {last_error})")


def check_method_access_control(client, report_data):
    section("METHOD ACCESS CONTROL")
    methods_found = report_data.get("method_nodes", [])
    if not methods_found:
        info("No methods discovered (run deep enumeration first)")
        return

    call_succeeded = []
    arg_reachable = []
    denied_methods = 0
    tested = 0

    for m in methods_found[:20]:
        path = m.get("path", "")
        try:
            parts = path.strip("/").split("/")
            node = client.get_node("i=85")

            for part in parts[1:]:
                found = False
                for child in sc(node):
                    if sn(child) == part:
                        node = child
                        found = True
                        break
                if not found:
                    node = None
                    break

            if node is None:
                continue

            node_class = node.read_node_class()
            if node_class != ua.NodeClass.Method:
                continue

            tested += 1
            parent = node.get_parent()
            if parent is None:
                continue

            try:
                parent.call_method(node, [])
                call_succeeded.append(path)
                bad(f"Method call succeeded: {path}")
                tag("Broken Access Control")
            except ua.UaStatusCodeError as e:
                status = str(e)
                if "BadUserAccessDenied" in status or "BadNotExecutable" in status:
                    denied_methods += 1
                    good(f"Method access denied: {path}")
                elif "BadInvalidArgument" in status or "BadArgumentsMissing" in status or "BadTypeMismatch" in status:
                    arg_reachable.append(path)
                    warn(f"Method reachable but arguments invalid: {path}")
                else:
                    info(f"Method {path}: {status}")
            except Exception:
                pass

        except Exception:
            pass

    if call_succeeded:
        add_finding(
            report_data,
            "Method Invocation Succeeded",
            "High",
            "Broken Access Control",
            f"{len(call_succeeded)} method(s) were successfully invoked by the current user: "
            f"{', '.join(call_succeeded[:5])}. Authorization should be reviewed immediately.",
            check="method-access",
            confidence="high",
            verification_status="confirmed-exec",
            safe_check=False,
            destructive=True,
            evidence={"successful_calls": call_succeeded[:20], "tested": tested},
        )

    if arg_reachable and not call_succeeded:
        add_observation(
            report_data,
            "Methods Reachable by Current Role",
            "Information Disclosure",
            f"{len(arg_reachable)} method(s) appear reachable because the server returned argument/type errors "
            f"instead of access denial. This suggests callable method exposure, but does not by itself prove unsafe authorization.",
            check="method-access",
            confidence="medium",
            verification_status="reachable-interface",
            safe_check=False,
            destructive=True,
            evidence={"argument_reachable": arg_reachable[:20], "tested": tested},
        )

    if not call_succeeded and not arg_reachable and tested > 0:
        good(f"All {tested} tested method(s) denied access or were not callable")
    elif tested == 0:
        info("No methods could be resolved for testing")


def _try_cert_connect(target, cert, key, uri, policy, mode, timeout):
    client = None
    try:
        client = Client(target, timeout=timeout)
        client.application_uri = uri
        client.set_security_string(f"{policy},{mode},{cert},{key}")
        client.connect()
        safe_disconnect(client)
        return True
    except Exception as e:
        safe_disconnect(client)
        return classify_error(e)


def check_certificate_trust_bypass(target, report_data, timeout=5):
    section("CERTIFICATE TRUST BYPASS")
    from .connection import get_endpoint_combinations

    endpoint_combos = get_endpoint_combinations(target, timeout=timeout)
    secure = [(p, m) for p, m in endpoint_combos if p != "None" and m != "None"]
    if not secure:
        info("No secure endpoints to test certificate bypass against")
        return

    pol, mod = secure[0]

    info("Testing expired certificate acceptance...")
    exp_cert, exp_key, exp_cnf, exp_dir, exp_tmp = generate_expired_cert(
        uri="urn:UARecon", out_dir=None
    )
    if exp_cert:
        result = _try_cert_connect(target, exp_cert, exp_key, "urn:UARecon", pol, mod, timeout)
        cleanup_temp_artifacts(exp_cert, exp_key, exp_cnf, exp_dir, remove_dir=exp_tmp)

        result_str = str(result).lower()
        if result is True:
            bad(f"EXPIRED CERTIFICATE ACCEPTED ({pol}/{mod})")
            tag("Cryptographic Failures")
            add_finding(
                report_data,
                "Expired Client Certificate Accepted",
                "High",
                "Cryptographic Failures",
                f"Server accepted an expired client certificate on {pol}/{mod}. "
                f"Certificate validity period does not appear to be enforced.",
                check="cert-bypass",
                confidence="high",
                verification_status="confirmed-auth-bypass",
                safe_check=False,
                destructive=True,
                evidence={"policy": pol, "mode": mod, "test": "expired-cert"},
            )
        elif "badcertificatetimeinvalid" in result_str:
            good(f"Expired certificate rejected ({result})")
        elif "badcertificateuntrusted" in result_str:
            info("Expired certificate test inconclusive: untrusted certificate was rejected before validity could be assessed")
        else:
            info(f"Expired cert result: {result}")
    else:
        warn("Could not generate expired certificate")

    info("Testing wrong Application URI certificate acceptance...")
    wu_cert, wu_key, wu_cnf, wu_dir, wu_tmp = generate_wrong_uri_cert(out_dir=None)
    if wu_cert:
        result = _try_cert_connect(target, wu_cert, wu_key, "urn:FAKE:InvalidApplication:NotReal", pol, mod, timeout)
        cleanup_temp_artifacts(wu_cert, wu_key, wu_cnf, wu_dir, remove_dir=wu_tmp)

        result_str = str(result).lower()
        if result is True:
            bad(f"WRONG URI CERTIFICATE ACCEPTED ({pol}/{mod})")
            tag("Cryptographic Failures")
            add_finding(
                report_data,
                "Wrong URI Client Certificate Accepted",
                "High",
                "Cryptographic Failures",
                f"Server accepted a certificate with a mismatched Application URI on {pol}/{mod}. "
                f"Application identity validation does not appear to be enforced.",
                check="cert-bypass",
                confidence="high",
                verification_status="confirmed-auth-bypass",
                safe_check=False,
                destructive=True,
                evidence={"policy": pol, "mode": mod, "test": "wrong-uri-cert"},
            )
        elif "badcertificateuriinvalid" in result_str:
            good(f"Wrong URI certificate rejected ({result})")
        elif "badcertificateuntrusted" in result_str:
            info("Wrong URI test inconclusive: untrusted certificate was rejected before URI validation could be assessed")
        else:
            info(f"Wrong URI cert result: {result}")
    else:
        warn("Could not generate wrong-URI certificate")


def check_max_limits(client, report_data):
    section("SERVER LIMITS (DoS SURFACE)")
    limits = [
        ("i=11702", "MaxArrayLength"),
        ("i=11703", "MaxStringLength"),
        ("i=12911", "MaxByteStringLength"),
        ("i=11705", "MaxNodesPerRead"),
        ("i=11707", "MaxNodesPerWrite"),
        ("i=11709", "MaxNodesPerMethodCall"),
        ("i=11710", "MaxNodesPerBrowse"),
        ("i=11714", "MaxMonitoredItemsPerCall"),
        ("i=2735", "MaxBrowseContinuationPoints"),
        ("i=2736", "MaxQueryContinuationPoints"),
        ("i=2737", "MaxHistoryContinuationPoints"),
    ]

    size_labels = {"MaxArrayLength", "MaxStringLength", "MaxByteStringLength"}
    suspicious = []

    for nid, label in limits:
        try:
            val = client.get_node(nid).read_value()
            if val is not None:
                if label in size_labels:
                    if val == 0:
                        warn(f"{label} = 0 (unlimited or unspecified)")
                        suspicious.append(f"{label}=0")
                    elif val > 67108864:
                        warn(f"{label} = {val:,} (>64MB)")
                        suspicious.append(f"{label}={val}")
                    else:
                        info(f"{label}: {val:,}")
                else:
                    if val == 0:
                        info(f"{label}: 0 (unlimited or unspecified)")
                    else:
                        info(f"{label}: {val:,}")
        except Exception:
            pass

    if suspicious:
        add_observation(
            report_data,
            "Potentially Unrestricted Message Size Limits",
            "Security Misconfiguration",
            f"Server reports unlimited or unusually large limits for: {', '.join(suspicious)}. "
            f"This may increase DoS surface, but impact depends on implementation-specific enforcement.",
            check="max-limits",
            confidence="low",
            verification_status="confirmed-read",
            safe_check=True,
            destructive=False,
            evidence={"suspicious_limits": suspicious},
        )
    else:
        good("Server size limits appear reasonable")


def check_gds_network_discovery(target, report_data, timeout=5):
    section("NETWORK DISCOVERY (FindServersOnNetwork)")
    tmp = None
    try:
        tmp = Client(target, timeout=timeout)
        records = tmp.connect_and_find_servers_on_network()
        if records:
            warn(f"FindServersOnNetwork returned {len(records)} record(s)")
            tag("Information Disclosure")
            for rec in records[:20]:
                server_name = getattr(rec, "ServerName", "")
                discovery_url = getattr(rec, "DiscoveryUrl", "")
                caps = getattr(rec, "ServerCapabilities", []) or []
                cap_str = ", ".join(str(c) for c in caps) if caps else "none"
                info(f"  {server_name or '(unnamed)'} | {discovery_url} | caps: {cap_str}")

            add_finding(
                report_data,
                "FindServersOnNetwork Exposes OT Network",
                "Medium",
                "Information Disclosure",
                f"FindServersOnNetwork returned {len(records)} server(s). "
                f"This may help attackers map the OPC UA environment.",
                check="gds-discovery",
                confidence="medium",
                verification_status="confirmed-read",
                safe_check=True,
                destructive=False,
                evidence={"record_count": len(records)},
            )
        else:
            good("FindServersOnNetwork returned empty")
    except Exception as e:
        err = classify_error(e)
        if "badservicenotsupported" in err.lower():
            info("FindServersOnNetwork not supported (no LDS/GDS)")
        else:
            info(f"FindServersOnNetwork: {err}")
    finally:
        safe_disconnect(tmp)


def check_history_read_access(client, report_data):
    section("HISTORY READ ACCESS")
    test_nodes = [
        ("i=2258", "Server.ServerStatus.CurrentTime"),
        ("i=2259", "Server.ServerStatus.State"),
        ("i=2261", "Server.ServerStatus.BuildInfo.ProductName"),
    ]

    readable = []
    for nid, label in test_nodes[:10]:
        try:
            node = client.get_node(nid)
            now = datetime.datetime.now(datetime.timezone.utc)
            start = now - datetime.timedelta(days=7)
            results = node.read_raw_history(start, now, numvalues=5)
            if results:
                count = len(results)
                readable.append(f"{label}({count} vals)")
                warn(f"HISTORY READABLE: {label} ({nid}) - {count} historical value(s)")
                tag("Information Disclosure")
            else:
                info(f"No history data: {label}")
        except ua.UaStatusCodeError as e:
            status = str(e).lower()
            if "badhistoryoperationunsupported" in status or "badhistoryoperationinvalid" in status:
                pass
            elif "baduseraccessdenied" in status or "badnotreadable" in status:
                good(f"History read denied: {label}")
            else:
                pass
        except Exception:
            pass

    if readable:
        add_finding(
            report_data,
            "Historical Data Accessible",
            "Low",
            "Information Disclosure",
            f"Authenticated user can read historical values from {len(readable)} node(s): "
            f"{', '.join(readable[:5])}. Verify this is intended for the current role.",
            check="history",
            confidence="medium",
            verification_status="confirmed-read",
            safe_check=True,
            destructive=False,
            evidence={"readable_nodes": readable[:20]},
        )
    else:
        good("No historical data accessible (or historizing not enabled)")


def check_subscription_abuse(client, report_data):
    section("SUBSCRIPTION LIMITS")
    sub = None
    try:
        sub = client.create_subscription(100)
        info("Subscription created (100ms interval)")

        node = client.get_node("i=2258")
        handles = []
        max_items = 50

        for _ in range(max_items):
            try:
                h = sub.subscribe_data_change(node)
                handles.append(h)
            except Exception:
                break

        created = len(handles)

        if created >= max_items:
            warn(f"At least {created} monitored items accepted on a single subscription")
            add_observation(
                report_data,
                "High Monitored Item Count Accepted",
                "Security Misconfiguration",
                f"Server accepted at least {created} monitored items on a single subscription. "
                f"This is capacity-relevant behavior and not necessarily a vulnerability by itself.",
                check="sub-abuse",
                confidence="low",
                verification_status="capacity-observation",
                safe_check=False,
                destructive=True,
                evidence={"created_items": created, "max_tested": max_items},
            )
        elif created > 0:
            info(f"Created {created} monitored items before limit or rejection")
        else:
            info("No monitored items created during test")

        for h in handles:
            try:
                sub.unsubscribe(h)
            except Exception:
                pass

        try:
            sub.delete()
        except Exception:
            pass

    except ua.UaStatusCodeError as e:
        status = str(e).lower()
        if "badtoomanysubscriptions" in status:
            good("Server enforces subscription limits")
        else:
            info(f"Subscription test: {e}")
    except Exception as e:
        info(f"Subscription test: {classify_error(e)}")


def check_node_write_access(client, report_data):
    section("NODE WRITE VERIFICATION")
    writable_nodes = report_data.get("writable_nodes", [])
    if not writable_nodes:
        info("No writable nodes discovered (run deep enumeration first)")
        return

    confirmed_writable = []
    tested = 0

    for n in writable_nodes[:15]:
        nid = n.get("node_id", "")
        path = n.get("path", "")
        if not nid:
            continue

        try:
            node = client.get_node(nid)
            current_val = node.read_value()
            tested += 1

            try:
                node.write_value(current_val)
                confirmed_writable.append(path or nid)
                bad(f"WRITE CONFIRMED: {path or nid} (wrote back same value)")
                tag("Broken Access Control")
            except ua.UaStatusCodeError as e:
                status = str(e).lower()
                if "baduseraccessdenied" in status or "badnotwritable" in status:
                    good(f"Write denied at runtime: {path or nid}")
                else:
                    info(f"Write test {path or nid}: {e}")
            except Exception:
                pass
        except Exception:
            pass

    if confirmed_writable:
        add_finding(
            report_data,
            "Confirmed Writable Nodes",
            "Critical",
            "Broken Access Control",
            f"{len(confirmed_writable)} node(s) are writable by current user: "
            f"{', '.join(confirmed_writable[:5])}. Attacker can modify process values.",
            check="node-write",
            confidence="high",
            verification_status="confirmed-write",
            safe_check=False,
            destructive=True,
            evidence={"confirmed_writable": confirmed_writable[:20], "tested": tested},
        )
    elif tested > 0:
        good(f"All {tested} nodes with write flag denied actual write")
    else:
        info("Could not test write access")


def check_register_nodes_abuse(client, report_data):
    section("RegisterNodes ABUSE")
    fake_nodes = [ua.NodeId(99990 + i, 0) for i in range(20)]
    try:
        result = client.register_nodes(fake_nodes)
        if result:
            registered = len(result)
            info(f"RegisterNodes accepted {registered} node registrations")
            add_observation(
                report_data,
                "RegisterNodes Accepted Test Registrations",
                "Security Misconfiguration",
                f"Server accepted {registered} test node registrations. This may be spec-compliant behavior and "
                f"should only be interpreted in the context of resource-consumption testing.",
                check="register-abuse",
                confidence="low",
                verification_status="service-accepted",
                safe_check=False,
                destructive=True,
                evidence={"registered_count": registered},
            )
            try:
                client.unregister_nodes(result)
            except Exception:
                pass
        else:
            good("RegisterNodes returned empty")
    except ua.UaStatusCodeError as e:
        status = str(e).lower()
        if "badnodeidunknown" in status or "badservicenotsupported" in status:
            good(f"RegisterNodes properly rejected ({e})")
        else:
            info(f"RegisterNodes: {e}")
    except Exception as e:
        info(f"RegisterNodes: {classify_error(e)}")


def check_browse_access_control(client, report_data):
    section("BROWSE ACCESS CONTROL")

    sensitive_areas = [
        ("i=2996", "ServerConfiguration", "server security configuration"),
        ("i=13813", "CertificateGroups", "certificate management objects"),
        ("i=15606", "KeyCredentialConfiguration", "credential store"),
        ("i=15607", "AuthorizationServices", "authorization service configuration"),
    ]

    admin_evidence = []
    session_diag_exposed = False
    session_diag_count = 0
    session_diag_samples = []

    for nid, label, desc in sensitive_areas:
        try:
            node = client.get_node(nid)
            children = sc(node)
            if not children:
                continue

            readable_children = 0
            method_children = 0
            sample_children = []

            for child in children[:20]:
                try:
                    child_name = sn(child)
                except Exception:
                    child_name = "?"

                try:
                    nc = child.read_node_class()
                except Exception:
                    nc = None

                if nc == ua.NodeClass.Method:
                    method_children += 1

                try:
                    _ = child.read_value()
                    readable_children += 1
                except Exception:
                    pass

                if len(sample_children) < 5:
                    sample_children.append(child_name)

            warn(
                f"BROWSABLE ADMIN OBJECT: {label} "
                f"(children={len(children)}, readable={readable_children}, methods={method_children})"
            )
            tag("Information Disclosure")

            admin_evidence.append({
                "node_id": nid,
                "label": label,
                "description": desc,
                "child_count": len(children),
                "readable_children": readable_children,
                "method_children": method_children,
                "sample_children": sample_children,
            })

        except Exception:
            pass

    try:
        sessions_node = client.get_node("i=3707")
        sess_children = sc(sessions_node)
        if len(sess_children) > 1:
            session_diag_exposed = True
            session_diag_count = len(sess_children)

            for child in sess_children[:5]:
                try:
                    cname = sn(child)
                except Exception:
                    cname = "?"

                sample = {"name": cname}

                try:
                    val = child.read_value()
                    sval = str(val)
                    if sval:
                        sample["preview"] = sval[:160]
                except Exception:
                    pass

                session_diag_samples.append(sample)

            bad(f"Session diagnostics visible for {len(sess_children)} entries (including other clients)")
            tag("Information Disclosure")
    except Exception:
        pass

    if session_diag_exposed:
        add_finding(
            report_data,
            "Session Diagnostics Exposed",
            "Medium",
            "Information Disclosure",
            f"Current user can browse {session_diag_count} session diagnostic entries, including other clients. "
            f"This may expose client identities, connection times, endpoint usage, and operational metadata.",
            check="browse-acl",
            confidence="high",
            verification_status="confirmed-read",
            safe_check=True,
            destructive=False,
            evidence={
                "session_entry_count": session_diag_count,
                "samples": session_diag_samples,
            },
        )

    if admin_evidence:
        add_observation(
            report_data,
            "Administrative Security Surface Exposed",
            "Information Disclosure",
            "Administrative or security-relevant objects are browsable by the current user. "
            "This is based on read-only enumeration only and does not prove write access or dangerous method execution.",
            check="browse-acl",
            confidence="medium",
            verification_status="surface-only",
            safe_check=True,
            destructive=False,
            evidence=admin_evidence,
        )

    if not session_diag_exposed and not admin_evidence:
        good("Sensitive server areas not accessible to current user")


def check_endpoint_url_mismatch(target, report_data, timeout=5):
    section("ENDPOINT URL VALIDATION")
    tmp = None
    try:
        tmp = Client(target, timeout=timeout)
        endpoints = tmp.connect_and_get_server_endpoints()

        target_parsed = urlparse(target)
        target_host = (target_parsed.hostname or "").lower()

        mismatched = []
        for ep in endpoints:
            ep_url = str(getattr(ep, "EndpointUrl", ""))
            if not ep_url:
                continue
            ep_parsed = urlparse(ep_url)
            ep_host = (ep_parsed.hostname or "").lower()

            if ep_host and target_host and ep_host != target_host:
                local = {"localhost", "127.0.0.1", "::1"}
                if ep_host in local or target_host in local:
                    continue

                ipv4_private = (
                    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
                    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                    "172.30.", "172.31.", "192.168."
                )
                ipv6_private = ("fd", "fe80:")
                ep_is_private = (
                    any(ep_host.startswith(p) for p in ipv4_private)
                    or (":" in ep_host and any(ep_host.startswith(p) for p in ipv6_private))
                )
                target_is_private = (
                    any(target_host.startswith(p) for p in ipv4_private)
                    or (":" in target_host and any(target_host.startswith(p) for p in ipv6_private))
                )
                if ep_is_private and not target_is_private:
                    mismatched.append((ep_url, ep_host))
                    bad(f"INTERNAL ADDRESS LEAKED: server advertises {ep_url} (reached via {target_host})")
                    tag("Security Misconfiguration")

        if mismatched:
            hosts = uniq([h for _, h in mismatched])
            add_finding(
                report_data,
                "Endpoint URL Hostname Mismatch",
                "Medium",
                "Security Misconfiguration",
                f"Server advertises endpoints with internal address(es) {', '.join(hosts)} "
                f"but was reached via {target_host}. This leaks internal network topology.",
                check="endpoint-url",
                confidence="high",
                verification_status="endpoint-analysis",
                safe_check=True,
                destructive=False,
                evidence={"mismatched_hosts": hosts, "target_host": target_host},
            )
        else:
            good(f"All endpoint URLs match target hostname ({target_host})")
    except Exception as e:
        info(f"Could not validate endpoint URLs: {classify_error(e)}")
    finally:
        safe_disconnect(tmp)


def check_nonce_quality(target, client, report_data, timeout=5):
    section("SERVER NONCE ANALYSIS")
    nonces = []

    for src_label, src in [("current session", client), ("new session", None)]:
        try:
            if src is None:
                src = Client(target, timeout=timeout)
                src.connect()

            nonce = None
            aio = getattr(src, "aio_obj", None)
            if aio:
                nonce = getattr(aio, "_server_nonce", None)
            if nonce is None:
                uac = getattr(src, "uaclient", None)
                if uac:
                    inner = getattr(uac, "aio_obj", None)
                    if inner:
                        nonce = getattr(inner, "_server_nonce", None)

            if nonce:
                nonces.append(bytes(nonce))
                info(f"Nonce from {src_label}: {len(nonce)} bytes")

            if src is not client:
                safe_disconnect(src)
        except Exception:
            if src is not None and src is not client:
                safe_disconnect(src)

    if not nonces:
        warn("Could not extract server nonces for analysis")
        return

    for nonce in nonces:
        if len(nonce) < 32:
            bad(f"SHORT NONCE: {len(nonce)} bytes (minimum 32 expected)")
            tag("Cryptographic Failures")
            add_finding(
                report_data,
                "Weak Server Nonce (Short Length)",
                "High",
                "Cryptographic Failures",
                f"Server nonce is only {len(nonce)} bytes. Short nonces reduce replay resistance.",
                check="nonce",
                confidence="high",
                verification_status="confirmed-read",
                safe_check=True,
                destructive=False,
                evidence={"nonce_length": len(nonce)},
            )
            return

    for nonce in nonces:
        if len(set(nonce)) <= 2:
            bad(f"LOW ENTROPY NONCE: only {len(set(nonce))} unique byte value(s)")
            tag("Cryptographic Failures")
            add_finding(
                report_data,
                "Low Entropy Server Nonce",
                "Critical",
                "Cryptographic Failures",
                f"Server nonce has extremely low entropy ({len(set(nonce))} unique byte values). "
                f"This strongly suggests broken randomness.",
                check="nonce",
                confidence="high",
                verification_status="confirmed-read",
                safe_check=True,
                destructive=False,
                evidence={"unique_bytes": len(set(nonce)), "nonce_length": len(nonce)},
            )
            return

    if len(nonces) >= 2:
        if nonces[0] == nonces[1]:
            critical("SERVER NONCE REUSED across sessions")
            tag("Cryptographic Failures")
            add_finding(
                report_data,
                "Server Nonce Reuse",
                "Critical",
                "Cryptographic Failures",
                "Server returned identical nonces in separate sessions. This breaks replay protection.",
                check="nonce",
                confidence="high",
                verification_status="confirmed-read",
                safe_check=True,
                destructive=False,
                evidence={"sampled_nonces": 2, "reuse": True},
            )
        elif nonces[0][:8] == nonces[1][:8]:
            warn("Nonce prefix collision observed across two sessions")
            add_observation(
                report_data,
                "Potentially Predictable Server Nonce",
                "Cryptographic Failures",
                "Two sampled nonces shared the same 8-byte prefix. This is suspicious but does not by itself prove predictability.",
                check="nonce",
                confidence="low",
                verification_status="weak-signal",
                safe_check=True,
                destructive=False,
                evidence={"prefix_bytes_equal": 8, "sampled_nonces": 2},
            )
        else:
            good(f"Server nonces appear distinct ({len(nonces[0])} bytes each)")
    else:
        nonce = nonces[0]
        good(f"Nonce length OK ({len(nonce)} bytes), entropy appears reasonable ({len(set(nonce))} unique byte values)")


def check_gds_trust_list(client, report_data):
    section("GDS / CERTIFICATE TRUST LIST ACCESS")

    trust_objects = []
    trust_paths = [
        ("i=12555", "DefaultApplicationGroup"),
        ("i=12556", "DefaultHttpsGroup"),
        ("i=14088", "DefaultUserTokenGroup"),
    ]

    for nid, label in trust_paths:
        try:
            node = client.get_node(nid)
            children = sc(node)
            if not children:
                continue

            readable_children = 0
            method_children = 0
            sample_children = []

            for child in children[:20]:
                try:
                    child_name = sn(child)
                except Exception:
                    child_name = "?"

                try:
                    nc = child.read_node_class()
                except Exception:
                    nc = None

                if nc == ua.NodeClass.Method:
                    method_children += 1

                try:
                    _ = child.read_value()
                    readable_children += 1
                except Exception:
                    pass

                if len(sample_children) < 5:
                    sample_children.append(child_name)

            warn(
                f"TRUST MGMT OBJECT BROWSABLE: {label} "
                f"(children={len(children)}, readable={readable_children}, methods={method_children})"
            )
            tag("Information Disclosure")

            trust_objects.append({
                "node_id": nid,
                "label": label,
                "child_count": len(children),
                "readable_children": readable_children,
                "method_children": method_children,
                "sample_children": sample_children,
            })

        except Exception:
            pass

    if trust_objects:
        add_observation(
            report_data,
            "Certificate Management Surface Exposed",
            "Information Disclosure",
            "Certificate-management objects are browsable by the current user. "
            "This finding is based on read-only enumeration only; it does not prove access to trust-list contents, "
            "certificate update capability, or writable trust stores.",
            check="gds-trust",
            confidence="medium",
            verification_status="surface-only",
            safe_check=True,
            destructive=False,
            evidence=trust_objects,
        )
    else:
        good("Certificate trust lists and related objects not accessible")


def check_redundancy_exposure(client, report_data):
    section("SERVER REDUNDANCY INFORMATION")
    exposed_info = []

    try:
        val = client.get_node("i=2035").read_value()
        if val is not None:
            level = str(val)
            info(f"RedundancySupport: {level}")
            if "none" not in level.lower() and str(val) != "0":
                exposed_info.append(f"RedundancySupport={level}")
    except Exception:
        pass

    try:
        uri_array = client.get_node("i=2005").read_value()
        if uri_array and len(uri_array) > 1:
            exposed_info.append(f"ServerUriArray ({len(uri_array)} servers)")
            for u in uri_array[:10]:
                warn(f"  Redundancy peer: {u}")
            tag("Information Disclosure")
    except Exception:
        pass

    try:
        server_array = client.get_node("i=2254").read_value()
        if server_array and len(server_array) > 1:
            exposed_info.append(f"ServerArray ({len(server_array)} entries)")
            for s in server_array:
                warn(f"  Server: {s}")
            tag("Information Disclosure")
    except Exception:
        pass

    if exposed_info:
        add_finding(
            report_data,
            "Server Redundancy Topology Exposed",
            "Medium",
            "Information Disclosure",
            f"Server exposes redundancy/cluster information: {', '.join(exposed_info)}. "
            f"This may reveal additional servers for lateral movement.",
            check="redundancy",
            confidence="medium",
            verification_status="confirmed-read",
            safe_check=True,
            destructive=False,
            evidence={"exposed_info": exposed_info},
        )
    else:
        good("No redundancy topology information exposed")


def check_transfer_subscription(target, client, report_data, timeout=5):
    section("SUBSCRIPTION TRANSFER HIJACK")
    sub = None
    client2 = None
    try:
        sub = client.create_subscription(500)
        node = client.get_node("i=2258")
        handle = sub.subscribe_data_change(node)
        sub_id = sub.subscription_id
        info(f"Created subscription {sub_id} on primary session")

        client2 = Client(target, timeout=timeout)
        try:
            client2.connect()
        except Exception:
            info("Could not open second session for transfer test")
            try:
                sub.unsubscribe(handle)
                sub.delete()
            except Exception:
                pass
            return

        try:
            uac = client2.uaclient
            if hasattr(uac, "transfer_subscriptions"):
                uac.transfer_subscriptions([sub_id], False)
                bad(f"SUBSCRIPTION TRANSFER ACCEPTED: subscription {sub_id} moved to another session")
                tag("Broken Access Control")
                add_finding(
                    report_data,
                    "Subscription Transfer Hijack Possible",
                    "Critical",
                    "Broken Access Control",
                    f"Server allowed transferring subscription {sub_id} to another session. "
                    f"This may permit data-stream hijacking.",
                    check="transfer-sub",
                    confidence="medium",
                    verification_status="confirmed-exec",
                    safe_check=False,
                    destructive=True,
                    evidence={"subscription_id": sub_id},
                )
            else:
                info("TransferSubscriptions service not available in client library")
        except ua.UaStatusCodeError as e:
            status = str(e).lower()
            if "badsubscriptionidinvalid" in status or "badservicenotsupported" in status:
                good(f"Subscription transfer rejected ({e})")
            elif "baduseraccessdenied" in status:
                good("Subscription transfer denied by access control")
            else:
                info(f"Transfer result: {e}")
        except Exception as e:
            info(f"Transfer test: {classify_error(e)}")

        try:
            sub.unsubscribe(handle)
            sub.delete()
        except Exception:
            pass

    except Exception as e:
        info(f"Subscription transfer test: {classify_error(e)}")
    finally:
        safe_disconnect(client2)


def check_session_timeout_policy(client, report_data):
    section("SESSION TIMEOUT POLICY")
    try:
        timeout_ms = None
        aio = getattr(client, "aio_obj", None)
        if aio:
            timeout_ms = getattr(aio, "session_timeout", None)
        if timeout_ms is None:
            uac = getattr(client, "uaclient", None)
            if uac:
                inner = getattr(uac, "aio_obj", None)
                if inner:
                    timeout_ms = getattr(inner, "session_timeout", None)

        if timeout_ms and timeout_ms > 0:
            hours = timeout_ms / 3600000
            info(f"Revised session timeout: {timeout_ms / 1000:.0f}s ({hours:.1f}h)")

            if timeout_ms > 86400000:
                bad(f"SESSION TIMEOUT TOO LONG: {hours:.0f}h (>24h)")
                tag("Security Misconfiguration")
                add_observation(
                    report_data,
                    "Excessive Session Timeout",
                    "Security Misconfiguration",
                    f"Server session timeout is {hours:.0f} hours. Long timeouts increase the window for session misuse.",
                    check="session-timeout",
                    confidence="medium",
                    verification_status="confirmed-read",
                    safe_check=True,
                    destructive=False,
                    evidence={"timeout_ms": timeout_ms, "timeout_hours": hours},
                )
            elif timeout_ms > 3600000:
                warn(f"Session timeout relatively long: {hours:.1f}h")
            else:
                good(f"Session timeout reasonable: {timeout_ms / 1000:.0f}s")
        else:
            info("Could not determine session timeout value")
    except Exception:
        info("Could not check session timeout")


def check_certificate_hostname(target, report_data, timeout=5):
    section("CERTIFICATE HOSTNAME VALIDATION")
    tmp = None
    try:
        tmp = Client(target, timeout=timeout)
        endpoints = tmp.connect_and_get_server_endpoints()

        target_parsed = urlparse(target)
        target_host = (target_parsed.hostname or "").lower()

        endpoint_hosts = set()
        for ep in endpoints:
            ep_url = str(getattr(ep, "EndpointUrl", "") or "")
            try:
                ep_host = (urlparse(ep_url).hostname or "").lower()
                if ep_host:
                    endpoint_hosts.add(ep_host)
            except Exception:
                pass

        checked = set()
        for ep in endpoints:
            cert_bytes = getattr(ep, "ServerCertificate", None)
            if not cert_bytes or bytes(cert_bytes) in checked:
                continue
            checked.add(bytes(cert_bytes))

            try:
                from cryptography import x509

                cert = x509.load_der_x509_certificate(bytes(cert_bytes))
                cert_hosts = set()

                try:
                    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    for dns in san.value.get_values_for_type(x509.DNSName):
                        cert_hosts.add(dns.lower())
                    for ip in san.value.get_values_for_type(x509.IPAddress):
                        cert_hosts.add(str(ip))
                except x509.ExtensionNotFound:
                    pass

                if not cert_hosts:
                    for attr in cert.subject:
                        if attr.oid == x509.oid.NameOID.COMMON_NAME:
                            cert_hosts.add(attr.value.lower())

                if not cert_hosts:
                    good("Certificate uses Application URI only (standard OPC UA practice)")
                    break

                info(f"Certificate names: {', '.join(sorted(cert_hosts))}")

                if target_host and target_host in cert_hosts:
                    good(f"Certificate covers target host ({target_host})")
                    break

                if endpoint_hosts and any(h in cert_hosts for h in endpoint_hosts):
                    info(
                        f"Certificate matches advertised endpoint hostname(s) ({', '.join(sorted(endpoint_hosts))}), "
                        f"while the scan used {target_host}. This is common when accessing the server via VPN, NAT, or IP."
                    )
                    break

                warn(
                    f"Certificate name mismatch: cert covers {', '.join(sorted(cert_hosts))}, "
                    f"target is {target_host}, advertised endpoint host(s): {', '.join(sorted(endpoint_hosts)) or 'n/a'}"
                )
                add_observation(
                    report_data,
                    "Certificate Name Does Not Match Access Path",
                    "Cryptographic Failures",
                    f"Server certificate names ({', '.join(sorted(cert_hosts))}) do not match the target host ({target_host}) "
                    f"or the advertised endpoint hostnames ({', '.join(sorted(endpoint_hosts)) or 'n/a'}). "
                    f"In OPC UA this may still be benign depending on Application URI validation and deployment topology, "
                    f"but it should be reviewed.",
                    check="cert-hostname",
                    confidence="low",
                    verification_status="endpoint-analysis",
                    safe_check=True,
                    destructive=False,
                    evidence={
                        "cert_hosts": sorted(cert_hosts),
                        "target_host": target_host,
                        "endpoint_hosts": sorted(endpoint_hosts),
                    },
                )
                break

            except ImportError:
                warn("cryptography library not available")
                break
            except Exception as e:
                warn(f"Certificate hostname check failed: {e}")

    except Exception as e:
        info(f"Could not check certificate hostname: {classify_error(e)}")
    finally:
        safe_disconnect(tmp)


def check_buildinfo_exposure(client, report_data):
    section("BUILD INFORMATION EXPOSURE")
    build_nodes = [
        ("i=2261", "ProductName"),
        ("i=2262", "ProductUri"),
        ("i=2263", "ManufacturerName"),
        ("i=2264", "SoftwareVersion"),
        ("i=2265", "BuildNumber"),
        ("i=2266", "BuildDate"),
    ]

    exposed = {}
    for nid, label in build_nodes:
        try:
            val = sr(client.get_node(nid))
            if val is not None and str(val).strip():
                exposed[label] = str(val)
        except Exception:
            pass

    if exposed:
        details = "; ".join(f"{k}={v}" for k, v in exposed.items())
        info(f"Build info: {details}")

        has_version = "SoftwareVersion" in exposed or "BuildNumber" in exposed
        has_product = "ProductName" in exposed or "ProductUri" in exposed

        if has_version and has_product:
            add_observation(
                report_data,
                "Build Information Available",
                "Information Disclosure",
                f"Server exposes build information: {details}. "
                f"This is standard OPC UA behavior but may help identify applicable CVEs.",
                check="buildinfo",
                confidence="high",
                verification_status="confirmed-read",
                safe_check=True,
                destructive=False,
                evidence={"exposed_fields": exposed},
            )
    else:
        good("Build information not readable")


def check_role_permissions(client, report_data):
    section("ROLE / PERMISSION MODEL")
    roles_found = []
    for nid in ["i=15606", "i=23470", "i=16036"]:
        try:
            node = client.get_node(nid)
            children = sc(node)
            if children:
                for c in children:
                    name = sn(c)
                    if name and name != "?" and name not in roles_found:
                        roles_found.append(name)
        except Exception:
            pass

    if roles_found:
        bad(f"ROLES BROWSABLE: {', '.join(roles_found)}")
        tag("Information Disclosure")
        add_observation(
            report_data,
            "Role Configuration Browsable",
            "Information Disclosure",
            f"Server role configuration is browsable. Roles found: {', '.join(roles_found)}. "
            f"This may help attackers understand the authorization model.",
            check="roles",
            confidence="medium",
            verification_status="surface-only",
            safe_check=True,
            destructive=False,
            evidence={"roles": roles_found},
        )
    else:
        info("Role configuration not accessible (or RBAC not implemented)")


def check_namespace_exposure(client, report_data):
    section("NAMESPACE ANALYSIS")
    try:
        ns_array = client.get_namespace_array()
        if not ns_array or len(ns_array) <= 2:
            info(f"Only standard namespaces ({len(ns_array or [])})")
            return

        standard_prefixes = ("http://opcfoundation.org/", "urn:opcfoundation.org:")
        vendor_ns = []
        for i, ns in enumerate(ns_array):
            if ns and not any(ns.startswith(p) for p in standard_prefixes):
                vendor_ns.append((i, ns))

        if not vendor_ns:
            good("Only standard OPC Foundation namespaces present")
            return

        for idx, ns in vendor_ns:
            info(f"Namespace [{idx}]: {ns}")

        ip_pattern = re.compile(r'(?:192\.168|10\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}')
        host_keywords = ["localhost", "internal"]
        sensitive = []
        for _, ns in vendor_ns:
            score = 0
            ns_lower = ns.lower()

            if ip_pattern.search(ns_lower):
                score += 3
            if "localhost" in ns_lower:
                score += 1
            if "internal" in ns_lower:
                score += 1

            if score >= 3:
                sensitive.append(ns)

        if sensitive:
            bad(f"Namespace URIs reveal internal info: {', '.join(sensitive)}")
            tag("Information Disclosure")
            add_finding(
                report_data,
                "Namespace URIs Expose Internal Structure",
                "Medium",
                "Information Disclosure",
                f"Vendor namespace URIs contain internal hostnames or network info: {', '.join(sensitive)}. "
                f"This may reveal infrastructure details.",
                check="namespaces",
                confidence="medium",
                verification_status="pattern-match",
                safe_check=True,
                destructive=False,
                evidence={"sensitive_namespaces": sensitive},
            )
    except Exception:
        info("Could not read namespace array")


def check_min_sampling_interval(client, report_data):
    section("SAMPLING INTERVAL LIMITS")
    try:
        val = client.get_node("i=2272").read_value()
        if val is not None:
            if val == 0:
                info("MinSupportedSampleRate: 0 (fastest possible, server default)")
            else:
                info(f"MinSupportedSampleRate: {val}ms")
    except Exception:
        pass


def check_max_connections(target, report_data, timeout=5):
    section("MAX CONNECTIONS (DoS SURFACE)")
    clients = []
    max_test = 20
    try:
        for _ in range(max_test):
            c = Client(target, timeout=timeout)
            try:
                c.connect()
                clients.append(c)
            except Exception:
                break

        count = len(clients)

        if count >= max_test:
            warn(f"At least {count} simultaneous anonymous connections accepted")
            add_observation(
                report_data,
                "Multiple Simultaneous Anonymous Connections Accepted",
                "Security Misconfiguration",
                f"Server accepted at least {count} simultaneous anonymous connections during this limited test. "
                f"This is an observation relevant to DoS assessment, not proof of unsafe connection limits.",
                check="max-connections",
                confidence="low",
                verification_status="capacity-observation",
                safe_check=False,
                destructive=True,
                evidence={"accepted_connections": count, "max_test": max_test},
            )
        elif count > 0:
            info(f"Server accepted {count} anonymous connections before rejecting")
        else:
            info("Anonymous connections not allowed (test requires anonymous access)")
    finally:
        for c in clients:
            safe_disconnect(c)


def run_security_checks(target, client, report_data, timeout=5, safe=False, delay=0):
    def _wait():
        if delay > 0:
            time.sleep(delay)

    check_security_policies(report_data); _wait()
    check_user_token_policies(report_data); _wait()
    check_server_certificate(target, report_data, timeout); _wait()
    check_discovery_exposure(target, report_data, timeout); _wait()
    check_gds_network_discovery(target, report_data, timeout); _wait()
    check_account_lockout(target, report_data, timeout); _wait()
    check_certificate_trust_bypass(target, report_data, timeout); _wait()
    check_endpoint_url_mismatch(target, report_data, timeout); _wait()
    check_certificate_hostname(target, report_data, timeout)

    if client:
        _wait(); check_audit_config(client, report_data)
        _wait(); check_session_limits(client, report_data)
        _wait(); check_session_timeout_policy(client, report_data)
        _wait(); check_timestamp_accuracy(client, report_data)
        _wait(); check_writable_server_config(client, report_data)
        _wait(); check_max_limits(client, report_data)
        _wait(); check_history_read_access(client, report_data)
        _wait(); check_nonce_quality(target, client, report_data, timeout)
        _wait(); check_browse_access_control(client, report_data)
        _wait(); check_gds_trust_list(client, report_data)
        _wait(); check_redundancy_exposure(client, report_data)
        _wait(); check_buildinfo_exposure(client, report_data)
        _wait(); check_sensitive_data_exposure(client, report_data)
        _wait(); check_role_permissions(client, report_data)
        _wait(); check_namespace_exposure(client, report_data)
        _wait(); check_min_sampling_interval(client, report_data)

    if safe:
        info("--prod mode: skipping active/destructive checks "
             "(method calls, node write, subscription/register/transfer abuse, connection flood)")
        return

    if client:
        _wait(); check_method_access_control(client, report_data)
        _wait(); check_node_write_access(client, report_data)
        _wait(); check_subscription_abuse(client, report_data)
        _wait(); check_register_nodes_abuse(client, report_data)
        _wait(); check_transfer_subscription(target, client, report_data, timeout)

    _wait(); check_max_connections(target, report_data, timeout)


CHECK_CATALOG = [
    ("anonymous",        "Anonymous Access",                 "Broken Authentication",     False, "target"),
    ("default-creds",    "Default Credentials",              "Broken Authentication",     False, "target"),
    ("security-policies","Security Policy Analysis",         "Cryptographic Failures",    False, "endpoints"),
    ("user-tokens",      "User Token Policies",              "Cryptographic Failures",    False, "endpoints"),
    ("server-cert",      "Server Certificate Analysis",      "Cryptographic Failures",    False, "target"),
    ("cert-hostname",    "Certificate Hostname Validation",  "Cryptographic Failures",    False, "target"),
    ("cert-bypass",      "Certificate Trust Bypass",         "Cryptographic Failures",    False, "target"),
    ("nonce",            "Server Nonce Quality",             "Cryptographic Failures",    False, "client"),
    ("discovery",        "Discovery Service Exposure",       "Information Disclosure",    False, "target"),
    ("gds-discovery",    "FindServersOnNetwork",             "Information Disclosure",    False, "target"),
    ("endpoint-url",     "Endpoint URL Validation",          "Security Misconfiguration", False, "target"),
    ("lockout",          "Account Lockout Detection",        "Broken Authentication",     False, "target"),
    ("audit",            "Audit Configuration",              "Security Misconfiguration", False, "client"),
    ("session-limits",   "Session Limits",                   "Security Misconfiguration", False, "client"),
    ("session-timeout",  "Session Timeout Policy",           "Security Misconfiguration", False, "client"),
    ("timestamp",        "Timestamp Accuracy",               "Security Misconfiguration", False, "client"),
    ("writable-config",  "Server Config Write Access",       "Broken Access Control",     False, "client"),
    ("max-limits",       "Server Limits (DoS Surface)",      "Security Misconfiguration", False, "client"),
    ("history",          "History Read Access",              "Information Disclosure",    False, "client"),
    ("browse-acl",       "Browse Access Control",            "Broken Access Control",     False, "client"),
    ("gds-trust",        "GDS / Trust List Access",          "Broken Access Control",     False, "client"),
    ("redundancy",       "Redundancy Info Exposure",         "Information Disclosure",    False, "client"),
    ("buildinfo",        "Build Information Exposure",       "Information Disclosure",    False, "client"),
    ("sensitive-data",   "Sensitive Data Exposure",          "Information Disclosure",    False, "client"),
    ("roles",            "Role / Permission Model",          "Information Disclosure",    False, "client"),
    ("namespaces",       "Namespace Exposure Analysis",      "Information Disclosure",    False, "client"),
    ("sampling",         "Sampling Interval Limits",         "Security Misconfiguration", False, "client"),
    ("method-access",    "Method Access Control",            "Broken Access Control",     True,  "client"),
    ("node-write",       "Node Write Verification",          "Broken Access Control",     True,  "client"),
    ("sub-abuse",        "Subscription Limits",              "Security Misconfiguration", True,  "client"),
    ("register-abuse",   "RegisterNodes Abuse",              "Security Misconfiguration", True,  "client"),
    ("transfer-sub",     "Subscription Transfer Hijack",     "Broken Access Control",     True,  "client"),
    ("max-connections",  "Max Connections (DoS)",            "Security Misconfiguration", True,  "target"),
]


def run_check_by_slug(slug, target, client, report_data, timeout=5):
    dispatch = {
        "anonymous":         lambda: check_anonymous_access(target, report_data, timeout),
        "default-creds":     lambda: check_default_credentials(target, report_data, timeout),
        "security-policies": lambda: check_security_policies(report_data),
        "user-tokens":       lambda: check_user_token_policies(report_data),
        "server-cert":       lambda: check_server_certificate(target, report_data, timeout),
        "cert-hostname":     lambda: check_certificate_hostname(target, report_data, timeout),
        "cert-bypass":       lambda: check_certificate_trust_bypass(target, report_data, timeout),
        "nonce":             lambda: check_nonce_quality(target, client, report_data, timeout),
        "discovery":         lambda: check_discovery_exposure(target, report_data, timeout),
        "gds-discovery":     lambda: check_gds_network_discovery(target, report_data, timeout),
        "endpoint-url":      lambda: check_endpoint_url_mismatch(target, report_data, timeout),
        "lockout":           lambda: check_account_lockout(target, report_data, timeout),
        "audit":             lambda: check_audit_config(client, report_data),
        "session-limits":    lambda: check_session_limits(client, report_data),
        "session-timeout":   lambda: check_session_timeout_policy(client, report_data),
        "timestamp":         lambda: check_timestamp_accuracy(client, report_data),
        "writable-config":   lambda: check_writable_server_config(client, report_data),
        "max-limits":        lambda: check_max_limits(client, report_data),
        "history":           lambda: check_history_read_access(client, report_data),
        "browse-acl":        lambda: check_browse_access_control(client, report_data),
        "gds-trust":         lambda: check_gds_trust_list(client, report_data),
        "redundancy":        lambda: check_redundancy_exposure(client, report_data),
        "buildinfo":         lambda: check_buildinfo_exposure(client, report_data),
        "sensitive-data":    lambda: check_sensitive_data_exposure(client, report_data),
        "roles":             lambda: check_role_permissions(client, report_data),
        "namespaces":        lambda: check_namespace_exposure(client, report_data),
        "sampling":          lambda: check_min_sampling_interval(client, report_data),
        "method-access":     lambda: check_method_access_control(client, report_data),
        "node-write":        lambda: check_node_write_access(client, report_data),
        "sub-abuse":         lambda: check_subscription_abuse(client, report_data),
        "register-abuse":    lambda: check_register_nodes_abuse(client, report_data),
        "transfer-sub":      lambda: check_transfer_subscription(target, client, report_data, timeout),
        "max-connections":   lambda: check_max_connections(target, report_data, timeout),
    }

    fn = dispatch.get(slug)
    if fn:
        fn()
        return True
    return False
    
