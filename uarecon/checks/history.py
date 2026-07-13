"""
History Read Access Check.

This check determines whether HistoryRead is available to the current user.
It tests historizing on enumerated process-level nodes (from deep enumeration)
rather than standard server status nodes, which are not sensitive.

Severity depends on the type of nodes that expose historical data:
- Process/application nodes: Medium (operational data exposure)
- Standard server infrastructure nodes: Info only (expected behavior)
"""

import datetime

from asyncua import ua

from ._base import add_finding, add_observation
from ..banner import warn, good, info, section, tag


# Standard server infrastructure nodes that are NOT security-sensitive
# when historized. These exist on every OPC UA server.
INFRASTRUCTURE_NODES = {
    "i=2258",  # Server.ServerStatus.CurrentTime
    "i=2259",  # Server.ServerStatus.State
    "i=2260",  # Server.ServerStatus.BuildInfo
    "i=2261",  # Server.ServerStatus.BuildInfo.ProductName
    "i=2262",  # Server.ServerStatus.BuildInfo.ProductUri
    "i=2263",  # Server.ServerStatus.BuildInfo.ManufacturerName
    "i=2264",  # Server.ServerStatus.BuildInfo.SoftwareVersion
    "i=2265",  # Server.ServerStatus.BuildInfo.BuildNumber
    "i=2266",  # Server.ServerStatus.BuildInfo.BuildDate
    "i=2992",  # Server.ServerStatus.SecondsTillShutdown
    "i=2993",  # Server.ServerStatus.ShutdownReason
    "i=2994",  # Server.Auditing
    "i=2274",  # Server.ServerDiagnostics.EnabledFlag
}


def check_history_read_access(client, report_data):
    section("HISTORY READ ACCESS")

    # Prefer process-level nodes from deep enumeration if available
    all_nodes = report_data.get("all_nodes", [])
    process_nodes = []
    for n in all_nodes:
        nid = n.get("node_id", "")
        if nid and nid not in INFRASTRUCTURE_NODES:
            # Skip nodes under ServerDiagnostics and ServerCapabilities
            path = n.get("path", "")
            if "ServerDiagnostics" in path or "ServerCapabilities" in path:
                continue
            if "ServerRedundancy" in path:
                continue
            process_nodes.append((nid, n.get("path", nid)))

    # Also add a few well-known infrastructure nodes for the capability test
    infra_test = [
        ("i=2258", "Server.ServerStatus.CurrentTime"),
    ]

    # Prioritize process nodes over infrastructure
    test_nodes = process_nodes[:15] + infra_test

    if not test_nodes:
        test_nodes = infra_test

    process_readable = []
    infra_readable = []

    for nid, label in test_nodes[:20]:
        try:
            node = client.get_node(nid)
            now = datetime.datetime.now(datetime.timezone.utc)
            start = now - datetime.timedelta(days=7)
            results = node.read_raw_history(start, now, numvalues=5)
            if results:
                count = len(results)
                if nid in INFRASTRUCTURE_NODES:
                    infra_readable.append(f"{label}({count} vals)")
                else:
                    process_readable.append(f"{label}({count} vals)")
                    warn(f"HISTORY READABLE: {label} ({nid}) - {count} historical value(s)")
                    tag("Information Disclosure")
        except ua.UaStatusCodeError as e:
            status = str(e).lower()
            if "badhistoryoperationunsupported" in status or "badhistoryoperationinvalid" in status:
                pass
            elif "baduseraccessdenied" in status or "badnotreadable" in status:
                good(f"History read denied: {label}")
            else:
                pass
        except Exception:
            pass

    if process_readable:
        add_finding(
            report_data,
            "Process Node Historical Data Accessible",
            "Medium",
            "Information Disclosure",
            f"Authenticated user can read historical values from {len(process_readable)} process-level node(s): "
            f"{', '.join(process_readable[:5])}. Historical process data may reveal operational patterns, "
            f"setpoints, and trends useful for attack planning.",
            check="history",
            confidence="high",
            verification_status="confirmed-read",
            safe_check=True,
            destructive=False,
            evidence={"readable_process_nodes": process_readable[:20]},
        )
    elif infra_readable:
        # Only infrastructure nodes have history - this is not a security finding
        info(f"HistoryRead available on standard server nodes only ({len(infra_readable)} nodes)")
        add_observation(
            report_data,
            "HistoryRead Service Available",
            "Information Disclosure",
            f"HistoryRead is available but only confirmed on standard server infrastructure nodes "
            f"({', '.join(infra_readable[:3])}). This is expected behavior and not a security concern "
            f"unless process-level nodes are also historized.",
            check="history",
            confidence="low",
            verification_status="confirmed-read",
            safe_check=True,
            destructive=False,
            evidence={"readable_infra_nodes": infra_readable[:10]},
        )
    else:
        good("No historical data accessible (or historizing not enabled)")
