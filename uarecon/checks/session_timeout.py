from ._base import add_observation
from ..banner import bad, warn, good, info, section, tag


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
