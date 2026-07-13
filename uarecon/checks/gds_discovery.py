from asyncua.sync import Client

from ._base import add_finding
from ..banner import warn, good, info, section, tag
from ..helpers import safe_disconnect, classify_error


def check_gds_network_discovery(target, report_data, timeout=5):
    section("NETWORK DISCOVERY (FindServersOnNetwork)")
    tmp = None
    try:
        tmp = Client(target, timeout=timeout)
        records = tmp.connect_and_find_servers_on_network()
        if records:
            warn(f"FindServersOnNetwork returned {len(records)} record(s)")
            tag("Information Disclosure")
            for rec in records[:20]:
                server_name = getattr(rec, "ServerName", "")
                discovery_url = getattr(rec, "DiscoveryUrl", "")
                caps = getattr(rec, "ServerCapabilities", []) or []
                cap_str = ", ".join(str(c) for c in caps) if caps else "none"
                info(f"  {server_name or '(unnamed)'} | {discovery_url} | caps: {cap_str}")

            add_finding(
                report_data,
                "FindServersOnNetwork Exposes OT Network",
                "Medium",
                "Information Disclosure",
                f"FindServersOnNetwork returned {len(records)} server(s). "
                f"This may help attackers map the OPC UA environment.",
                check="gds-discovery",
                confidence="medium",
                verification_status="confirmed-read",
                safe_check=True,
                destructive=False,
                evidence={"record_count": len(records)},
            )
        else:
            good("FindServersOnNetwork returned empty")
    except Exception as e:
        err = classify_error(e)
        if "badservicenotsupported" in err.lower():
            info("FindServersOnNetwork not supported (no LDS/GDS)")
        else:
            info(f"FindServersOnNetwork: {err}")
    finally:
        safe_disconnect(tmp)
