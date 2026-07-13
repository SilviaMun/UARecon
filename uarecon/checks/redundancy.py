"""
Redundancy Information Exposure Check.

Notes on false positive avoidance:
- ServerArray (i=2254) must contain at least the server's own URI.
  Having >1 entry means the server is in a redundancy group, which is normal.
- ServerUriArray (i=2005) with multiple entries is normal for redundancy sets.
- Only flag when internal network information (IPs, hostnames) is leaked through
  these entries, OR when redundancy reveals previously unknown peers.
"""

import re

from ._base import add_finding, add_observation
from ..banner import warn, good, info, section, tag


_PRIVATE_IP_RE = re.compile(
    r'(?:192\.168|10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}'
)
_HOSTNAME_INTERNAL = re.compile(
    r'(?:localhost|\.local|\.internal|\.corp|\.lan)', re.IGNORECASE
)


def _has_internal_info(uri):
    """Check if a URI reveals internal network info."""
    return bool(_PRIVATE_IP_RE.search(str(uri)) or _HOSTNAME_INTERNAL.search(str(uri)))


def check_redundancy_exposure(client, report_data):
    section("SERVER REDUNDANCY INFORMATION")
    exposed_info = []
    internal_leaks = []
    peer_count = 0

    try:
        val = client.get_node("i=2035").read_value()
        if val is not None:
            level = str(val)
            info(f"RedundancySupport: {level}")
            if "none" not in level.lower() and str(val) != "0":
                exposed_info.append(f"RedundancySupport={level}")
    except Exception:
        pass

    try:
        uri_array = client.get_node("i=2005").read_value()
        if uri_array and len(uri_array) > 1:
            peer_count = len(uri_array) - 1  # Subtract self
            exposed_info.append(f"ServerUriArray ({len(uri_array)} servers)")
            for u in uri_array[:10]:
                info(f"  Redundancy peer: {u}")
                if _has_internal_info(u):
                    internal_leaks.append(str(u))
    except Exception:
        pass

    try:
        server_array = client.get_node("i=2254").read_value()
        if server_array and len(server_array) > 1:
            # ServerArray > 1 means redundancy peers exist - this is normal operations
            exposed_info.append(f"ServerArray ({len(server_array)} entries)")
            for s in server_array:
                info(f"  Server: {s}")
                if _has_internal_info(s):
                    internal_leaks.append(str(s))
    except Exception:
        pass

    if internal_leaks:
        # Real finding: redundancy info leaks internal network addresses
        warn(f"Redundancy information reveals internal addresses: {', '.join(internal_leaks[:5])}")
        tag("Information Disclosure")
        add_finding(
            report_data,
            "Redundancy Info Leaks Internal Addresses",
            "Medium",
            "Information Disclosure",
            f"Server redundancy/cluster information reveals internal network addresses: "
            f"{', '.join(internal_leaks[:5])}. This aids lateral movement planning in multi-server environments.",
            check="redundancy",
            confidence="high",
            verification_status="confirmed-read",
            safe_check=True,
            destructive=False,
            evidence={
                "internal_leaks": internal_leaks[:20],
                "exposed_info": exposed_info,
                "peer_count": peer_count,
            },
        )
    elif exposed_info and peer_count > 0:
        # Redundancy peers exist but no internal info leaked.
        # This is normal OPC UA deployment - observation only.
        add_observation(
            report_data,
            "Redundancy Topology Visible",
            "Information Disclosure",
            f"Server exposes redundancy/cluster information: {', '.join(exposed_info)}. "
            f"This is standard OPC UA redundancy behavior. No internal addresses were identified. "
            f"Review whether peer discovery URIs should be restricted in the deployment context.",
            check="redundancy",
            confidence="low",
            verification_status="confirmed-read",
            safe_check=True,
            destructive=False,
            evidence={"exposed_info": exposed_info, "peer_count": peer_count},
        )
    else:
        good("No redundancy topology information exposed")
