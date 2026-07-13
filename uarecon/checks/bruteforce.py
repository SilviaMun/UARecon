import time

from asyncua.sync import Client

from ._base import add_finding
from ..banner import critical, bad, good, info, section, tag
from ..helpers import safe_disconnect


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
    info(f"Testing {len(users)} users x {len(passwords)} passwords = {total} combinations")

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
