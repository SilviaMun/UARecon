from ._base import add_observation
from ..banner import warn, info, section


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
