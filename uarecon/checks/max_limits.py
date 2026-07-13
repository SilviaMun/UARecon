from ._base import add_observation
from ..banner import warn, good, info, section


def check_max_limits(client, report_data):
    section("SERVER LIMITS (DoS SURFACE)")
    limits = [
        ("i=11702", "MaxArrayLength"),
        ("i=11703", "MaxStringLength"),
        ("i=12911", "MaxByteStringLength"),
        ("i=11705", "MaxNodesPerRead"),
        ("i=11707", "MaxNodesPerWrite"),
        ("i=11709", "MaxNodesPerMethodCall"),
        ("i=11710", "MaxNodesPerBrowse"),
        ("i=11714", "MaxMonitoredItemsPerCall"),
        ("i=2735", "MaxBrowseContinuationPoints"),
        ("i=2736", "MaxQueryContinuationPoints"),
        ("i=2737", "MaxHistoryContinuationPoints"),
    ]

    size_labels = {"MaxArrayLength", "MaxStringLength", "MaxByteStringLength"}
    suspicious = []

    for nid, label in limits:
        try:
            val = client.get_node(nid).read_value()
            if val is not None:
                if label in size_labels:
                    if val == 0:
                        warn(f"{label} = 0 (unlimited or unspecified)")
                        suspicious.append(f"{label}=0")
                    elif val > 67108864:
                        warn(f"{label} = {val:,} (>64MB)")
                        suspicious.append(f"{label}={val}")
                    else:
                        info(f"{label}: {val:,}")
                else:
                    if val == 0:
                        info(f"{label}: 0 (unlimited or unspecified)")
                    else:
                        info(f"{label}: {val:,}")
        except Exception:
            pass

    if suspicious:
        add_observation(
            report_data,
            "Potentially Unrestricted Message Size Limits",
            "Security Misconfiguration",
            f"Server reports unlimited or unusually large limits for: {', '.join(suspicious)}. "
            f"This may increase DoS surface, but impact depends on implementation-specific enforcement.",
            check="max-limits",
            confidence="low",
            verification_status="confirmed-read",
            safe_check=True,
            destructive=False,
            evidence={"suspicious_limits": suspicious},
        )
    else:
        good("Server size limits appear reasonable")
