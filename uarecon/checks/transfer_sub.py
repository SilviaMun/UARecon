from asyncua import ua
from asyncua.sync import Client

from ._base import add_finding
from ..banner import bad, good, info, section, tag
from ..helpers import safe_disconnect, classify_error


def check_transfer_subscription(target, client, report_data, timeout=5):
    section("SUBSCRIPTION TRANSFER HIJACK")
    sub = None
    client2 = None
    try:
        sub = client.create_subscription(500)
        node = client.get_node("i=2258")
        handle = sub.subscribe_data_change(node)
        sub_id = sub.subscription_id
        info(f"Created subscription {sub_id} on primary session")

        client2 = Client(target, timeout=timeout)
        try:
            client2.connect()
        except Exception:
            info("Could not open second session for transfer test")
            try:
                sub.unsubscribe(handle)
                sub.delete()
            except Exception:
                pass
            return

        try:
            uac = client2.uaclient
            if hasattr(uac, "transfer_subscriptions"):
                uac.transfer_subscriptions([sub_id], False)
                bad(f"SUBSCRIPTION TRANSFER ACCEPTED: subscription {sub_id} moved to another session")
                tag("Broken Access Control")
                add_finding(
                    report_data,
                    "Subscription Transfer Hijack Possible",
                    "Critical",
                    "Broken Access Control",
                    f"Server allowed transferring subscription {sub_id} to another session. "
                    f"This may permit data-stream hijacking.",
                    check="transfer-sub",
                    confidence="medium",
                    verification_status="confirmed-exec",
                    safe_check=False,
                    destructive=False,
                    evidence={"subscription_id": sub_id},
                )
            else:
                info("TransferSubscriptions service not available in client library")
        except ua.UaStatusCodeError as e:
            status = str(e).lower()
            if "badsubscriptionidinvalid" in status or "badservicenotsupported" in status:
                good(f"Subscription transfer rejected ({e})")
            elif "baduseraccessdenied" in status:
                good("Subscription transfer denied by access control")
            else:
                info(f"Transfer result: {e}")
        except Exception as e:
            info(f"Transfer test: {classify_error(e)}")

        try:
            sub.unsubscribe(handle)
            sub.delete()
        except Exception:
            pass

    except Exception as e:
        info(f"Subscription transfer test: {classify_error(e)}")
    finally:
        safe_disconnect(client2)
