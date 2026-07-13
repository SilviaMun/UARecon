import datetime
import math
import re


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
