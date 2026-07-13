from asyncua import ua

from ._base import add_finding, add_observation
from ..banner import bad, warn, good, info, section, tag
from ..helpers import classify_error


def check_publish_rate_abuse(client, report_data):
    section("PUBLISH RATE ABUSE")

    # CreateSubscription allows clients to request a
    # PublishingInterval. If the server accepts very fast intervals (< 10ms)
    # without revision, it may be exploitable for network flooding.
    # An attacker can create subscriptions with 1ms intervals to overwhelm
    # network bandwidth with Publish responses.

    subs_created = []
    fast_accepted = 0
    fastest_revised = None

    test_intervals = [1, 5, 10]  # milliseconds - aggressively fast

    for interval_ms in test_intervals:
        sub = None
        try:
            sub = client.create_subscription(interval_ms)
            # The library stores the revised interval back into the parameters object
            # after CreateSubscription completes. Access via the async inner object.
            revised = None
            aio_sub = getattr(sub, "aio_obj", None)
            if aio_sub:
                params = getattr(aio_sub, "parameters", None)
                if params:
                    revised = getattr(params, "RequestedPublishingInterval", None)
            if revised is None:
                revised = interval_ms

            subs_created.append(sub)

            if revised <= 10:
                fast_accepted += 1
                if fastest_revised is None or revised < fastest_revised:
                    fastest_revised = revised
                info(f"Requested {interval_ms}ms, server granted {revised}ms")
            else:
                info(f"Requested {interval_ms}ms, server revised to {revised}ms")
                if fastest_revised is None or revised < fastest_revised:
                    fastest_revised = revised

        except ua.UaStatusCodeError as e:
            status = str(e).lower()
            if "badtoomanysubscriptions" in status:
                good("Server limits subscription creation")
                break
            else:
                info(f"Subscription at {interval_ms}ms: {e}")
                break
        except Exception as e:
            info(f"Subscription at {interval_ms}ms: {classify_error(e)}")
            break

    # Cleanup
    for sub in subs_created:
        try:
            sub.delete()
        except Exception:
            pass

    if fast_accepted >= 2 and fastest_revised is not None and fastest_revised <= 5:
        warn(f"Server accepts very fast publish intervals ({fastest_revised}ms)")
        tag("Security Misconfiguration")
        add_finding(
            report_data,
            "Fast Publish Interval Accepted (Network Flood Risk)",
            "Medium",
            "Security Misconfiguration",
            f"Server accepted publish intervals as low as {fastest_revised}ms without meaningful revision. "
            f"Combined with monitored items on high-frequency variables, this can generate sustained network "
            f"flooding. Servers should enforce a minimum publishing interval (typically >= 100ms).",
            check="publish-flood",
            confidence="medium",
            verification_status="confirmed-read",
            safe_check=False,
            destructive=False,
            evidence={
                "fastest_revised_ms": fastest_revised,
                "fast_intervals_accepted": fast_accepted,
                "tested_intervals_ms": test_intervals,
            },
        )
    elif fast_accepted >= 1 and fastest_revised is not None and fastest_revised <= 10:
        warn(f"Server accepts fast publish interval ({fastest_revised}ms)")
        add_observation(
            report_data,
            "Fast Publish Interval Accepted",
            "Security Misconfiguration",
            f"Server accepted a publish interval of {fastest_revised}ms. While some applications "
            f"require fast updates, this increases DoS surface when combined with many monitored items.",
            check="publish-flood",
            confidence="low",
            verification_status="capacity-observation",
            safe_check=False,
            destructive=False,
            evidence={
                "fastest_revised_ms": fastest_revised,
                "fast_intervals_accepted": fast_accepted,
            },
        )
    elif fastest_revised is not None:
        good(f"Server enforces minimum publish interval ({fastest_revised}ms)")
    else:
        info("Could not determine publish interval enforcement")
