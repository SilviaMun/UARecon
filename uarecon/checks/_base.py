import datetime
import math
import re


# ---------------------------------------------------------------------------
# IEC 62443 Foundational Requirements
# ---------------------------------------------------------------------------
FR1 = "FR1 – Identification & Authentication"
FR2 = "FR2 – Use Control"
FR3 = "FR3 – System Integrity"
FR4 = "FR4 – Data Confidentiality"
FR5 = "FR5 – Restricted Data Flow"
FR6 = "FR6 – Timely Response to Events"
FR7 = "FR7 – Resource Availability"

# ---------------------------------------------------------------------------
# OPC UA Part 2 Security Objectives
# ---------------------------------------------------------------------------
APP_AUTH = "Application Authentication"
USR_AUTH = "User Authentication"
AUTHZ = "Authorization"
CONFID = "Confidentiality"
INTEGRITY = "Integrity"
AUDIT = "Auditability"
AVAIL = "Availability"

# ---------------------------------------------------------------------------
# Per-check framework mapping
# ---------------------------------------------------------------------------
FRAMEWORK_MAP = {
    # --- authentication ---
    "anonymous":           ([FR1],         [USR_AUTH]),
    "user-tokens":         ([FR1, FR4],    [USR_AUTH, CONFID]),
    "default-creds":       ([FR1],         [USR_AUTH]),
    "provided-creds":      ([FR1, FR2],    [USR_AUTH, AUTHZ]),
    "lockout":             ([FR1],         [USR_AUTH]),
    # --- endpoint ---
    "security-policies":   ([FR4, FR3],    [CONFID, INTEGRITY]),
    "endpoint-url":        ([FR5],         [APP_AUTH]),
    "discovery":           ([FR5],         [CONFID]),
    # --- certificate ---
    "server-cert":         ([FR1, FR4],    [APP_AUTH]),
    "cert-hostname":       ([FR1],         [APP_AUTH]),
    "app-uri":             ([FR1],         [APP_AUTH]),
    "gds-trust":           ([FR1, FR2],    [APP_AUTH, AUTHZ]),
    "cert-bypass":         ([FR1],         [APP_AUTH]),
    # --- secure channel ---
    "nonce":               ([FR3, FR4],    [INTEGRITY, CONFID]),
    "secure-channel":      ([FR4, FR3],    [CONFID, INTEGRITY]),
    "session-timeout":     ([FR1, FR7],    [USR_AUTH, AVAIL]),
    "session-limits":      ([FR7],         [AVAIL]),
    # --- authorization ---
    "browse-acl":          ([FR2],         [AUTHZ]),
    "roles":               ([FR2],         [AUTHZ]),
    "history":             ([FR2, FR4],    [AUTHZ, CONFID]),
    "view-access":         ([FR2],         [AUTHZ]),
    "method-access":       ([FR2, FR3],    [AUTHZ, INTEGRITY]),
    "node-write":          ([FR2, FR3],    [AUTHZ, INTEGRITY]),
    "writable-config":     ([FR2, FR3],    [AUTHZ, INTEGRITY]),
    "access-restrictions": ([FR2],         [AUTHZ]),
    "transfer-sub":        ([FR2, FR4],    [AUTHZ, CONFID]),
    # --- disclosure ---
    "buildinfo":           ([FR5],         [CONFID]),
    "namespaces":          ([FR5],         [CONFID]),
    "redundancy":          ([FR5],         [CONFID]),
    "sensitive-data":      ([FR4, FR5],    [CONFID]),
    # --- audit ---
    "audit":               ([FR6],         [AUDIT]),
    "timestamp":           ([FR6],         [AUDIT]),
    "diagnostics-consistency": ([FR6],     [AUDIT]),
    # --- availability ---
    "max-limits":          ([FR7],         [AVAIL]),
    "max-response":        ([FR7],         [AVAIL]),
    "max-connections":     ([FR7],         [AVAIL]),
    "sub-abuse":           ([FR7],         [AVAIL]),
    "publish-flood":       ([FR7],         [AVAIL]),
    "translate-dos":       ([FR7],         [AVAIL]),
    # --- deployment ---
    "gds-discovery":       ([FR5],         [CONFID]),
    # --- extra (outside CHECK_CATALOG) ---
    "bruteforce":          ([FR1],         [USR_AUTH]),
    "register-abuse":      ([FR7],         [AVAIL]),
}


def _lookup_frameworks(check_slug):
    if not check_slug or check_slug not in FRAMEWORK_MAP:
        return [], []
    return FRAMEWORK_MAP[check_slug]


# ---------------------------------------------------------------------------
# Centralized findings catalog — single source of truth for title, severity,
# category, and check slug.  Dynamic descriptions stay in check files.
# ---------------------------------------------------------------------------
def _f(t, s, c, k):
    return {"title": t, "severity": s, "category": c, "check": k}


def _o(t, c, k):
    return {"title": t, "severity": "Info", "category": c, "check": k, "observation": True}


FINDINGS_CATALOG = {
    # ── authentication_posture ──────────────────────────────────────
    "anon-access":                _f("Anonymous Access Allowed",                              "Critical", "Identification and Authentication Failures",     "anonymous"),
    "anon-session-only":          _o("Anonymous Session Accepted (No Data Access)",                        "Identification and Authentication Failures",     "anonymous"),
    "plaintext-password":         _f("Plaintext Password Transmission",                       "Critical", "Cryptographic Failures",    "user-tokens"),
    "potential-plaintext":        _f("Potential Plaintext Password Transmission",              "High",     "Cryptographic Failures",    "user-tokens"),
    "issued-token-unencrypted":   _f("IssuedToken Over Unencrypted Endpoint",                 "High",     "Cryptographic Failures",    "user-tokens"),
    "cert-token-unencrypted":     _o("Certificate Token on Unencrypted Endpoint",                          "Cryptographic Failures",    "user-tokens"),
    "default-creds-accepted":     _f("Default Credentials Accepted",                          "Critical", "Identification and Authentication Failures",     "default-creds"),
    "creds-on-none":              _f("Credentials Accepted on Unencrypted Endpoint",          "Critical", "Cryptographic Failures",    "provided-creds"),
    "elevated-access":            _o("Elevated Access Level Detected",                                     "Broken Access Control",     "provided-creds"),
    "hardening-issues":           _f("Endpoint Hardening Issues for Authenticated Session",   "Medium",   "Security Misconfiguration", "provided-creds"),
    "no-lockout":                 _o("No Visible Account Lockout Observed",                                "Identification and Authentication Failures",     "lockout"),
    "bruteforce-creds":           _f("Valid Credentials Found (Brute-Force)",                 "Critical", "Identification and Authentication Failures",     "bruteforce"),
    # ── endpoint_security_posture ───────────────────────────────────
    "policy-none":                _f("SecurityPolicy None Available",                         "Medium",   "Cryptographic Failures",    "security-policies"),
    "deprecated-policy":          _f("Deprecated Security Policy",                            "High",     "Cryptographic Failures",    "security-policies"),
    "legacy-policy":              _f("Legacy Security Policy",                                "Medium",   "Cryptographic Failures",    "security-policies"),
    "unknown-policy":             _f("Unknown Security Policy",                               "Medium",   "Cryptographic Failures",    "security-policies"),
    "sign-only-mode":             _f("Sign-Only Mode Available (No Encryption)",              "Medium",   "Cryptographic Failures",    "security-policies"),
    "downgrade-path":             _f("Weaker Security Modes Coexist with Strong Endpoints",   "Medium",   "Cryptographic Failures",    "security-policies"),
    "endpoint-hostname-mismatch": _f("Endpoint URL Hostname Mismatch",                       "Medium",   "Security Misconfiguration", "endpoint-url"),
    "discovery-exposes-servers":  _f("Discovery Service Exposes Additional Servers",          "Medium",   "Information Disclosure",    "discovery"),
    "multi-app-same-host":        _o("Multiple Applications on Same Host",                                 "Information Disclosure",    "discovery"),
    # ── certificate_posture ─────────────────────────────────────────
    "self-signed-cert":           _o("Self-Signed Server Certificate",                                     "Cryptographic Failures",    "server-cert"),
    "expired-cert":               _f("Expired Server Certificate",                            "High",     "Cryptographic Failures",    "server-cert"),
    "weak-cert-key":              _f("Weak Server Certificate Key",                           "High",     "Cryptographic Failures",    "server-cert"),
    "cert-name-mismatch":         _o("Certificate Name Does Not Match Access Path",                        "Cryptographic Failures",    "cert-hostname"),
    "no-san-uri":                 _o("No ApplicationUri in Certificate SAN",                               "Cryptographic Failures",    "app-uri"),
    "app-uri-mismatch":           _f("ApplicationUri Does Not Match Certificate",             "High",     "Cryptographic Failures",    "app-uri"),
    "cert-mgmt-methods":          _o("Certificate Management Methods Visible",                             "Information Disclosure",    "gds-trust"),
    "cert-trust-data":            _o("Certificate Trust Data Readable",                                    "Information Disclosure",    "gds-trust"),
    "expired-cert-accepted":      _f("Expired Client Certificate Accepted",                   "High",     "Cryptographic Failures",    "cert-bypass"),
    "wrong-uri-cert-accepted":    _f("Wrong URI Client Certificate Accepted",                 "High",     "Cryptographic Failures",    "cert-bypass"),
    # ── secure_channel_posture ──────────────────────────────────────
    "weak-nonce-short":           _f("Weak Server Nonce (Short Length)",                      "High",     "Cryptographic Failures",    "nonce"),
    "low-entropy-nonce":          _f("Low Entropy Server Nonce",                              "Critical", "Cryptographic Failures",    "nonce"),
    "nonce-reuse":                _f("Server Nonce Reuse",                                    "Critical", "Cryptographic Failures",    "nonce"),
    "predictable-nonce":          _o("Potentially Predictable Server Nonce",                               "Cryptographic Failures",    "nonce"),
    "excessive-channel-lifetime": _f("Excessive SecureChannel Token Lifetime",                "Medium",   "Cryptographic Failures",    "secure-channel"),
    "long-channel-lifetime":      _o("Long SecureChannel Token Lifetime",                                  "Cryptographic Failures",    "secure-channel"),
    "excessive-session-timeout":  _o("Excessive Session Timeout",                                          "Security Misconfiguration", "session-timeout"),
    "session-count-unlimited":    _o("Session Count Not Explicitly Limited",                               "Security Misconfiguration", "session-limits"),
    # ── authorization_posture ───────────────────────────────────────
    "session-diag-exposed":       _f("Session Diagnostics Exposed",                           "Medium",   "Information Disclosure",    "browse-acl"),
    "admin-surface-exposed":      _o("Administrative Security Surface Exposed",                            "Information Disclosure",    "browse-acl"),
    "roles-browsable":            _o("Role Configuration Browsable",                                       "Information Disclosure",    "roles"),
    "process-history-accessible": _f("Process Node Historical Data Accessible",               "Medium",   "Information Disclosure",    "history"),
    "history-service-available":  _o("HistoryRead Service Available",                                      "Information Disclosure",    "history"),
    "no-view-segregation":        _o("No View-Based Namespace Segregation",                                "Security Misconfiguration", "view-access"),
    "executable-zero-arg":        _f("Executable Zero-Argument Methods (Not Called)",         "High",     "Broken Access Control",     "method-access"),
    "methods-reachable":          _f("Methods Reachable by Current Role",                     "High",     "Broken Access Control",     "method-access"),
    "additional-methods-reachable": _o("Additional Methods Proven Reachable",                              "Broken Access Control",     "method-access"),
    "confirmed-write-access":     _f("Confirmed Write Access",                                "High",     "Broken Access Control",     "node-write"),
    "safety-critical-writable":   _f("Write Access to Safety-Critical Nodes (Unverified)",    "High",     "Broken Access Control",     "node-write"),
    "writable-nodes-unverified":  _f("Writable Nodes Detected (Unverified)",                  "Medium",   "Broken Access Control",     "node-write"),
    "writable-server-config":     _f("Server Config Writable",                                "High",     "Broken Access Control",     "writable-config"),
    "no-authz-metadata":          _o("Authorization Metadata Not Exposed on Sensitive Nodes",              "Security Misconfiguration", "access-restrictions"),
    "partial-restriction-coverage": _o("Partial Access Restriction Coverage",                              "Security Misconfiguration", "access-restrictions"),
    "restrictions-no-encryption": _o("Access Restrictions Without Encryption Requirement",                 "Security Misconfiguration", "access-restrictions"),
    "write-role-permissions":     _f("Write Role Permissions on Sensitive Nodes",              "Medium",   "Broken Access Control",     "access-restrictions"),
    "no-authz-process-nodes":     _o("No Authorization Metadata on Process Nodes",                         "Security Misconfiguration", "access-restrictions"),
    "subscription-hijack":        _f("Subscription Transfer Hijack Possible",                 "Critical", "Broken Access Control",     "transfer-sub"),
    # ── information_disclosure ──────────────────────────────────────
    "buildinfo-available":        _o("Build Information Available",                                        "Information Disclosure",    "buildinfo"),
    "namespace-internal-info":    _f("Namespace URIs Expose Internal Structure",              "Medium",   "Information Disclosure",    "namespaces"),
    "redundancy-internal-leaks":  _f("Redundancy Info Leaks Internal Addresses",              "Medium",   "Information Disclosure",    "redundancy"),
    "redundancy-topology-visible": _o("Redundancy Topology Visible",                                      "Information Disclosure",    "redundancy"),
    "sensitive-data-high":        _f("Sensitive Data Exposed (High Confidence)",              "High",     "Information Disclosure",    "sensitive-data"),
    "sensitive-data-medium":      _f("Potentially Sensitive Data Exposed",                    "Medium",   "Information Disclosure",    "sensitive-data"),
    # ── audit_posture ───────────────────────────────────────────────
    "auditing-disabled":          _f("Auditing Disabled",                                     "High",     "Security Logging and Monitoring Failures", "audit"),
    "time-desync":                _o("Time Desynchronization Observed",                                    "Security Logging and Monitoring Failures", "timestamp"),
    "diag-counters-inaccessible": _o("Diagnostic Counters Not Accessible",                                 "Security Logging and Monitoring Failures", "diagnostics-consistency"),
    "diag-counter-inconsistencies": _f("Diagnostic Counter Inconsistencies",                  "Medium",   "Security Logging and Monitoring Failures", "diagnostics-consistency"),
    "diag-telemetry-anomalies":   _f("Diagnostic Telemetry Anomalies",                        "Medium",   "Security Logging and Monitoring Failures", "diagnostics-consistency"),
    # ── availability_posture ────────────────────────────────────────
    "unrestricted-size-limits":   _o("Potentially Unrestricted Message Size Limits",                       "Security Misconfiguration", "max-limits"),
    "unlimited-response-size":    _f("Unlimited Response Message Size (Amplification Risk)",  "Medium",   "Security Misconfiguration", "max-response"),
    "large-response-limits":      _o("Large Response Message Limits",                                      "Security Misconfiguration", "max-response"),
    "multiple-anon-connections":  _o("Multiple Simultaneous Anonymous Connections Accepted",                "Security Misconfiguration", "max-connections"),
    "no-monitored-item-limit":    _o("No Visible Monitored Item Limit",                                    "Security Misconfiguration", "sub-abuse"),
    "fast-publish-flood":         _f("Fast Publish Interval Accepted (Network Flood Risk)",   "Medium",   "Security Misconfiguration", "publish-flood"),
    "fast-publish-obs":           _o("Fast Publish Interval Accepted",                                     "Security Misconfiguration", "publish-flood"),
    "bulk-translate-accepted":    _o("Bulk TranslateBrowsePaths Accepted",                                 "Security Misconfiguration", "translate-dos"),
    # ── deployment_posture ──────────────────────────────────────────
    "find-servers-on-network":    _f("FindServersOnNetwork Exposes OT Network",               "Medium",   "Information Disclosure",    "gds-discovery"),
    # ── connection (pre-check) ──────────────────────────────────────
    "conn-policy-none":           _f("SecurityPolicy None Accepted",                          "Critical", "Cryptographic Failures",    "security-policies"),
    "conn-auto-cert":             _o("Auto-Generated Client Certificate Accepted During Enumeration",      "Cryptographic Failures",    "cert-bypass"),
    "conn-cert-rejected":         _o("Untrusted Client Certificate Rejected",                              "Cryptographic Failures",    "cert-bypass"),
    "conn-failed":                _o("Connection Failed",                                                  "Connection",                "connection"),
    # ── extra (outside CHECK_CATALOG) ───────────────────────────────
    "register-nodes-accepted":    _o("RegisterNodes Accepted Test Registrations",                          "Security Misconfiguration", "register-abuse"),
}

del _f, _o


def was_emitted(report_data, fid):
    return fid in report_data.get("_emitted_fids", set())


def emit(report_data, fid, description, **kw):
    entry = FINDINGS_CATALOG[fid]
    iec, opcua = _lookup_frameworks(entry["check"])
    report_data.setdefault("_emitted_fids", set()).add(fid)
    report_data["findings"].append({
        "title": kw.pop("title", entry["title"]),
        "severity": entry["severity"],
        "category": entry["category"],
        "description": description,
        "check": entry["check"],
        "confidence": kw.pop("confidence", "medium"),
        "verification_status": kw.pop("verification_status", None),
        "safe_check": kw.pop("safe_check", None),
        "destructive": kw.pop("destructive", None),
        "evidence": kw.pop("evidence", None),
        "observation": entry.get("observation", False),
        "iec62443": iec,
        "opcua_security": opcua,
    })


def build_finding(fid, description, report_data=None, **kw):
    entry = FINDINGS_CATALOG[fid]
    iec, opcua = _lookup_frameworks(entry["check"])
    if report_data is not None:
        report_data.setdefault("_emitted_fids", set()).add(fid)
    return {
        "title": kw.pop("title", entry["title"]),
        "severity": entry["severity"],
        "category": entry["category"],
        "description": description,
        "check": entry["check"],
        "confidence": kw.pop("confidence", "medium"),
        "verification_status": kw.pop("verification_status", None),
        "safe_check": kw.pop("safe_check", None),
        "destructive": kw.pop("destructive", None),
        "evidence": kw.pop("evidence", None),
        "observation": entry.get("observation", False),
        "iec62443": iec,
        "opcua_security": opcua,
    }


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
    iec62443, opcua_sec = _lookup_frameworks(check)
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
        "iec62443": iec62443,
        "opcua_security": opcua_sec,
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
    "pwd": 4,
    "secret": 4,
    "token": 3,
    "api_key": 6,
    "apikey": 6,
    "client_secret": 6,
    "private_key": 8,
    "connection_string": 5,
    "connectionstring": 5,
    "credential": 5,
    "mqtt_password": 6,
    "ftp_password": 6,
    "db_password": 6,
    "database_password": 6,
    "license_key": 4,
    "activation_key": 4,
    "serial_number": 3,
    "plc_password": 7,
    "scada_password": 7,
    "modbus_password": 6,
    "bacnet_password": 6,
    "snmp_community": 5,
    "auth_token": 5,
    "refresh_token": 5,
    "access_token": 5,
    "signing_key": 7,
    "encryption_key": 7,
    "symmetric_key": 7,
    "shared_secret": 6,
    "preshared_key": 6,
    "historian_password": 6,
    "sql_password": 6,
    "vpn_secret": 6,
    "wifi_password": 6,
    "wpa_key": 6,
}

BENIGN_KEYWORDS = {
    "token_type": -4,
    "public_key": -5,
    "keycode": -3,
    "keyboard": -3,
    "password_policy": -4,
    "password_length": -4,
    "has_password": -3,
    "require_password": -3,
    "session_timeout": -3,
    "build_number": -3,
    "serial_number_data_type": -4,
    "token_policy": -4,
    "security_token": -3,
    "max_token": -3,
    "version": -4,
    "status": -3,
    "state": -3,
    "build_info": -4,
    "product_name": -4,
    "manufacturer_name": -4,
    "software_version": -5,
    "build_date": -4,
    "operating_status": -4,
    "broker_url": -3,
}

CONFIG_CONTEXT_KEYWORDS = {
    "configuration", "config", "settings", "connection",
    "credentials", "authentication", "database",
    "network", "communication", "plc", "driver",
}

EMAIL_RE = re.compile(r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b", re.I)
JWT_RE = re.compile(r"^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$")
PRIVATE_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
)
CONNSTR_RE = re.compile(r"(password\s*=|pwd\s*=|user id\s*=|uid\s*=|server\s*=.*password)", re.I)
PEM_RE = re.compile(r"-----BEGIN (?:RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----")
BEARER_RE = re.compile(r"^Bearer\s+[A-Za-z0-9\-_\.=]+$", re.I)
URL_CREDS_RE = re.compile(r"://[^:/@]+:[^:/@]+@", re.I)
AWS_KEY_RE = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
HEX_SECRET_RE = re.compile(r"^[0-9a-fA-F]{32,}$")
AZURE_CONNSTR_RE = re.compile(r"(AccountKey|SharedAccessKey|Endpoint)\s*=", re.I)


def normalize_text(s):
    if s is None:
        return ""
    s = str(s).strip()
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", s)
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


def _is_non_secret_type(value):
    if isinstance(value, (bool, int, float)):
        return True
    if isinstance(value, datetime.datetime):
        return True
    if isinstance(value, list) and value and isinstance(value[0], (bool, int, float)):
        return True
    return False


def _decode_bytestring(value):
    if not isinstance(value, (bytes, bytearray)):
        return None
    try:
        decoded = value.decode("utf-8", errors="ignore")
        if decoded and any(c.isprintable() for c in decoded[:50]):
            return decoded
    except Exception:
        pass
    return value.hex() if len(value) <= 256 else value[:256].hex()


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

    in_config_context = any(kw in key_material for kw in CONFIG_CONTEXT_KEYWORDS)
    if in_config_context and score > 0:
        score += 2
        reasons.append("context:config_subtree")

    if _is_non_secret_type(value):
        if score >= 5 and in_config_context:
            pass
        else:
            return max(score - 3, 0), reasons

    if isinstance(value, (bytes, bytearray)):
        decoded = _decode_bytestring(value)
        if decoded and PEM_RE.search(str(decoded)):
            score += 10
            reasons.append("value:private_key_bytes")
            return score, reasons
        if isinstance(value, (bytes, bytearray)) and len(value) >= 16:
            entropy = shannon_entropy(value.hex())
            if entropy >= 3.8 and score >= 3:
                score += 3
                reasons.append(f"value:high_entropy_bytes:{len(value)}B")
        sval = str(decoded) if decoded else ""
    else:
        sval = "" if value is None else str(value).strip()

    if not sval:
        return score, reasons

    if PEM_RE.search(sval):
        score += 10
        reasons.append("value:private_key_pem")
        return score, reasons

    if URL_CREDS_RE.search(sval):
        score += 7
        reasons.append("value:url_with_credentials")

    if CONNSTR_RE.search(sval):
        score += 6
        reasons.append("value:connection_string")

    if AZURE_CONNSTR_RE.search(sval):
        score += 6
        reasons.append("value:azure_connection_string")

    if JWT_RE.match(sval) and len(sval) > 40:
        score += 6
        reasons.append("value:jwt")

    if BEARER_RE.match(sval) and len(sval) > 20:
        score += 5
        reasons.append("value:bearer_token")

    if AWS_KEY_RE.search(sval):
        score += 8
        reasons.append("value:aws_access_key")

    if HEX_SECRET_RE.match(sval) and len(sval) >= 32 and score >= 3:
        score += 4
        reasons.append(f"value:hex_secret:{len(sval)}chars")

    if EMAIL_RE.search(sval):
        score += 2
        reasons.append("value:email")

    if PRIVATE_IP_RE.search(sval) and in_config_context:
        score += 2
        reasons.append("value:private_ip_in_config")

    if len(sval) >= 20 and score >= 3:
        entropy = shannon_entropy(sval)
        if entropy >= 4.0:
            score += 3
            reasons.append(f"value:high_entropy:{entropy:.2f}")
        elif entropy >= 3.5 and score >= 5:
            score += 2
            reasons.append(f"value:moderate_entropy:{entropy:.2f}")

    placeholders = {"test", "example", "dummy", "changeme", "password", "admin", "guest", "none", "n/a", "null", ""}
    if sval.lower() in placeholders:
        score -= 3
        reasons.append("value:placeholder")

    opcua_uri_noise = ("http://opcfoundation.org/", "urn:opcfoundation", "opc.tcp://")
    if any(sval.startswith(p) for p in opcua_uri_noise):
        score -= 4
        reasons.append("value:opcua_standard_uri")

    return score, reasons
