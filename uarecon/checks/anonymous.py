from asyncua.sync import Client

from ._base import add_finding
from ..banner import critical, bad, warn, good, info, section, tag
from ..helpers import safe_disconnect, classify_error


def check_anonymous_access(target, report_data, timeout=5):
    section("ANONYMOUS ACCESS CHECK")
    client = None
    try:
        client = Client(target, timeout=timeout)
        client.connect()

        can_browse = False
        can_read = False

        warn("Anonymous session accepted")

        try:
            objects = client.get_objects_node()
            children = objects.get_children()
            if children:
                can_browse = True
                bad(f"Anonymous user can browse Objects node ({len(children)} children)")
                tag("Broken Access Control")
        except Exception:
            pass

        try:
            current_time = client.get_node("i=2258").read_value()
            if current_time is not None:
                can_read = True
                info(f"Anonymous read succeeded (CurrentTime={current_time})")
        except Exception:
            pass

        if can_browse or can_read:
            critical("ANONYMOUS ACCESS CONFIRMED WITH REAL PRIVILEGES")
            tag("Broken Authentication")
            add_finding(
                report_data,
                "Anonymous Access Allowed",
                "Critical",
                "Broken Authentication",
                "Server accepted anonymous access and allowed browse/read operations. "
                "Any network-reachable attacker can access the OPC UA server without credentials.",
                check="anonymous",
                confidence="high",
                verification_status="confirmed-read",
                safe_check=True,
                destructive=False,
            )
        else:
            # Session accepted but no actual data access - this is common and expected
            # in OPC UA. Servers accept anonymous sessions for GetEndpoints/FindServers
            # but deny all data operations. This is NOT a vulnerability by itself.
            info("Anonymous session accepted but no data operations permitted (expected for discovery)")
            from ._base import add_observation
            add_observation(
                report_data,
                "Anonymous Session Accepted (No Data Access)",
                "Broken Authentication",
                "Server accepted an anonymous session but no browse or read operations succeeded. "
                "In OPC UA, anonymous sessions are often required for initial endpoint discovery "
                "(GetEndpoints, FindServers). This is standard protocol behavior and not a "
                "vulnerability unless data operations are also permitted.",
                check="anonymous",
                confidence="low",
                verification_status="session-only",
                safe_check=True,
                destructive=False,
            )

        safe_disconnect(client)
        return True

    except Exception as e:
        err = classify_error(e)
        if "badidentitytoken" in err or "baduseraccessdenied" in err:
            good(f"Anonymous access rejected ({err})")
        else:
            info(f"Anonymous connect failed: {err}")
        safe_disconnect(client)
        return False
