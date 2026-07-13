"""
Default Credentials Check (lockout-safe).

Tries well-known username/password pairs to detect default credentials.

SAFETY: To avoid triggering account lockout policies, this check limits
attempts to a maximum of 3 passwords per username.  Typical OPC UA server
lockout thresholds are 5-10 consecutive failures, so 3 attempts stays
safely below that boundary.
"""

from asyncua.sync import Client

from ._base import add_finding
from ..banner import critical, good, info, section, tag
from ..helpers import safe_disconnect


# Credentials grouped by username.  Order matters: most likely passwords first.
# Maximum 3 entries per user to stay below lockout thresholds.
DEFAULT_CREDENTIALS = [
    ("admin",    "admin"),
    ("admin",    "password"),
    ("admin",    ""),
    ("user",     "user"),
    ("user",     "password"),
    ("operator", "operator"),
    ("guest",    "guest"),
    ("root",     "root"),
    ("opcua",    "opcua"),
]

# Hard cap: never try more than this many passwords for the same username
_MAX_PER_USER = 3


def check_default_credentials(target, report_data, timeout=5):
    section("DEFAULT CREDENTIALS CHECK")
    found = []

    # Track attempts per username to enforce the lockout-safe cap
    attempts_by_user = {}

    for user, pwd in DEFAULT_CREDENTIALS:
        count = attempts_by_user.get(user, 0)
        if count >= _MAX_PER_USER:
            continue
        attempts_by_user[user] = count + 1

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
            # On success, skip remaining passwords for this user
            attempts_by_user[user] = _MAX_PER_USER
        except Exception:
            safe_disconnect(client)

    tested = sum(attempts_by_user.values())

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
            destructive=False,
            evidence={"accepted_credentials": found, "tested": tested},
        )
    else:
        good(f"None of {tested} default credential attempts accepted "
             f"(max {_MAX_PER_USER} per user to avoid lockout)")
