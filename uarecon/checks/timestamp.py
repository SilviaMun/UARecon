import datetime

from ._base import add_observation
from ..banner import warn, good, info, section, tag


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
                    "Time Desynchronization Observed",
                    "Security Misconfiguration",
                    f"Server clock differs from local time by {drift:.0f} seconds. "
                    f"This may reflect NTP misconfiguration, timezone mismatch, or network latency. "
                    f"Security relevance depends on whether the deployment relies on strict time-based "
                    f"validation (e.g. certificate expiry, nonce freshness, audit log correlation).",
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
