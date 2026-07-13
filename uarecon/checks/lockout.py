"""
Account Lockout Detection (non-destructive).

Tests whether the server enforces account lockout by sending repeated wrong
passwords for a FAKE username that cannot be a real account.

SAFETY: Uses the synthetic username '_uarecon_lockout_probe_' which is
extremely unlikely to exist on any real server.  If the server tracks
lockout state for non-existent accounts, the probe account getting locked
has zero operational impact.  Real user accounts are never touched.
"""

from asyncua.sync import Client

from ._base import add_observation
from ..banner import warn, good, info, section
from ..helpers import safe_disconnect, classify_error


# Synthetic username -- must not collide with any real account
_PROBE_USER = "_uarecon_lockout_probe_"
_PROBE_PWD = "UARecon_wrong_pwd_!"
_MAX_ATTEMPTS = 10


def check_account_lockout(target, report_data, timeout=5):
    section("ACCOUNT LOCKOUT DETECTION")

    info(f"Testing with synthetic user '{_PROBE_USER}' ({_MAX_ATTEMPTS} attempts)")

    observed_failed = 0
    last_error = ""
    inconclusive = False

    for attempt in range(_MAX_ATTEMPTS):
        client = None
        try:
            client = Client(target, timeout=timeout)
            client.set_user(_PROBE_USER)
            client.set_password(_PROBE_PWD)
            client.connect()
            # Unexpected success -- the fake user exists?
            safe_disconnect(client)
            info(f"Probe user unexpectedly accepted (attempt {attempt + 1})")
            observed_failed = 0
            inconclusive = True
            break
        except Exception as e:
            err = classify_error(e)
            last_error = err
            safe_disconnect(client)

            err_lower = err.lower()
            if "baduseraccessdenied" in err_lower or "badidentitytoken" in err_lower:
                observed_failed += 1
            elif "badtoomanyessions" in err_lower or "connection" in err_lower:
                # Server may be rate-limiting at connection level
                inconclusive = True
                break
            else:
                # Unknown error -- could be lockout kicking in
                if observed_failed >= 3 and attempt > 0:
                    # We had some auth failures then a different error -- possible lockout
                    info(f"Error changed after {observed_failed} failures: {err}")
                    break
                else:
                    inconclusive = True
                    break

    if inconclusive:
        info(f"Lockout detection inconclusive (last error: {last_error})")
    elif observed_failed >= _MAX_ATTEMPTS:
        warn(f"No lockout observed after {_MAX_ATTEMPTS} failed attempts "
             f"(synthetic user '{_PROBE_USER}')")
        add_observation(
            report_data,
            "No Visible Account Lockout Observed",
            "Broken Authentication",
            f"Server returned authentication failures for {_MAX_ATTEMPTS} consecutive "
            f"invalid login attempts on synthetic user '{_PROBE_USER}' without visible "
            f"lockout or error change. This does not exclude server-side throttling, "
            f"upstream controls, or delayed lockout mechanisms.",
            check="lockout",
            confidence="low",
            verification_status="inconclusive-no-lockout-observed",
            safe_check=False,
            destructive=False,
            evidence={
                "attempts": _MAX_ATTEMPTS,
                "probe_user": _PROBE_USER,
                "last_error": last_error,
            },
        )
    elif observed_failed > 0 and observed_failed < _MAX_ATTEMPTS:
        good(f"Possible lockout/throttling detected after {observed_failed} failures "
             f"(error changed: {last_error})")
    else:
        info(f"Could not determine lockout behavior (error: {last_error})")
