"""
Subscription Limits Check.

Notes on false positive avoidance:
- Production OPC UA clients routinely use hundreds or thousands of monitored items.
- A threshold of 50 would flag every normal deployment.
- This check tests whether the server enforces ANY limit on subscriptions,
  not whether 50 items is "too many."
- Finding only raised if server accepts unreasonable quantities (>= 500 items)
  without rejection, indicating no per-session resource limiting.
"""

from asyncua import ua

from ._base import add_finding, add_observation
from ..banner import warn, good, info, section
from ..helpers import classify_error


def check_subscription_abuse(client, report_data):
    section("SUBSCRIPTION LIMITS")

    # Test 1: Create multiple subscriptions to check subscription-level limits
    subs_created = []
    max_subs = 10  # Reasonable test - most servers should allow at least this

    for _ in range(max_subs):
        try:
            sub = client.create_subscription(500)
            subs_created.append(sub)
        except ua.UaStatusCodeError as e:
            status = str(e).lower()
            if "badtoomanysubscriptions" in status:
                good(f"Server limits subscriptions ({len(subs_created)} allowed)")
                break
            else:
                break
        except Exception:
            break

    # Cleanup subscriptions from test 1
    for s in subs_created:
        try:
            s.delete()
        except Exception:
            pass

    # Test 2: Create many monitored items on a single subscription
    sub = None
    try:
        sub = client.create_subscription(500)
        node = client.get_node("i=2258")
        handles = []
        max_items = 500  # Realistic threshold - normal clients use 100-2000+

        for _ in range(max_items):
            try:
                h = sub.subscribe_data_change(node)
                handles.append(h)
            except ua.UaStatusCodeError as e:
                status = str(e).lower()
                if "badtoomanymonitored" in status or "badresourceexhausted" in status:
                    good(f"Server limits monitored items at {len(handles)}")
                    break
                else:
                    break
            except Exception:
                break

        created = len(handles)

        if created >= max_items:
            warn(f"Server accepted {created} monitored items without limit")
            add_observation(
                report_data,
                "No Visible Monitored Item Limit",
                "Security Misconfiguration",
                f"Server accepted at least {created} monitored items on a single subscription "
                f"without rejecting any. While production clients may legitimately use this many items, "
                f"the absence of explicit limits may indicate no per-session resource controls are configured.",
                check="sub-abuse",
                confidence="low",
                verification_status="capacity-observation",
                safe_check=False,
                destructive=False,
                evidence={"created_items": created, "max_tested": max_items},
            )
        elif created > 0:
            info(f"Server accepted {created} items before limit ({max_items} tested)")
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
