from asyncua import ua

from ._base import add_finding, add_observation
from ..banner import warn, good, info, section, tag


def check_max_response_message_size(client, report_data):
    section("RESPONSE MESSAGE SIZE LIMITS")

    # MaxResponseMessageSize is negotiated during CreateSession.
    # A value of 0 means "no limit" which enables amplification attacks.
    # We also check related transport-level limits.

    response_size = None
    request_size = None

    # Try to get the negotiated session parameters
    try:
        aio = getattr(client, "aio_obj", None)
        if aio:
            response_size = getattr(aio, "max_response_message_size", None)
            request_size = getattr(aio, "max_request_message_size", None)
        if response_size is None:
            uac = getattr(client, "uaclient", None)
            if uac:
                inner = getattr(uac, "aio_obj", None)
                if inner:
                    response_size = getattr(inner, "max_response_message_size", None)
                    request_size = getattr(inner, "max_request_message_size", None)
    except Exception:
        pass

    # Also check server-side limits from the ServerCapabilities node
    max_browse_cp = None
    max_query_cp = None

    try:
        max_browse_cp = client.get_node("i=2735").read_value()
    except Exception:
        pass

    try:
        max_query_cp = client.get_node("i=2736").read_value()
    except Exception:
        pass

    # Check MaxMessageSize via transport configuration if exposed
    # Node i=11704 = MaxNodesPerHistoryReadData, i=11702 = MaxArrayLength
    max_array = None
    max_string = None
    max_bytestring = None
    try:
        max_array = client.get_node("i=11702").read_value()
        max_string = client.get_node("i=11703").read_value()
        max_bytestring = client.get_node("i=12911").read_value()
    except Exception:
        pass

    # Report findings
    if response_size is not None:
        if response_size == 0:
            info("MaxResponseMessageSize: 0 (unlimited)")
        else:
            info(f"MaxResponseMessageSize: {response_size:,} bytes ({response_size / 1048576:.1f} MB)")

    if request_size is not None:
        if request_size == 0:
            info("MaxRequestMessageSize: 0 (unlimited)")
        else:
            info(f"MaxRequestMessageSize: {request_size:,} bytes ({request_size / 1048576:.1f} MB)")

    # Analyze amplification risk
    unlimited_limits = []
    excessive_limits = []

    if response_size == 0:
        unlimited_limits.append("MaxResponseMessageSize=0")

    if max_array == 0:
        unlimited_limits.append("MaxArrayLength=0")
    elif max_array is not None and max_array > 67108864:  # > 64MB
        excessive_limits.append(f"MaxArrayLength={max_array:,}")

    if max_string == 0:
        unlimited_limits.append("MaxStringLength=0")
    elif max_string is not None and max_string > 67108864:
        excessive_limits.append(f"MaxStringLength={max_string:,}")

    if max_bytestring == 0:
        unlimited_limits.append("MaxByteStringLength=0")
    elif max_bytestring is not None and max_bytestring > 67108864:
        excessive_limits.append(f"MaxByteStringLength={max_bytestring:,}")

    if max_browse_cp == 0:
        unlimited_limits.append("MaxBrowseContinuationPoints=0")

    if unlimited_limits and len(unlimited_limits) >= 2:
        warn(f"Multiple unlimited response parameters: {', '.join(unlimited_limits)}")
        tag("Security Misconfiguration")
        add_finding(
            report_data,
            "Unlimited Response Message Size (Amplification Risk)",
            "Medium",
            "Security Misconfiguration",
            f"Server reports unlimited or unconfigured response limits: {', '.join(unlimited_limits)}. "
            f"Combined with unbounded arrays/strings, an attacker could craft requests that generate "
            f"disproportionately large responses, enabling amplification-style DoS attacks.",
            check="max-response",
            confidence="medium",
            verification_status="confirmed-read",
            safe_check=True,
            destructive=False,
            evidence={
                "unlimited_limits": unlimited_limits,
                "excessive_limits": excessive_limits,
                "max_response_size": response_size,
                "max_array_length": max_array,
                "max_string_length": max_string,
                "max_bytestring_length": max_bytestring,
            },
        )
    elif unlimited_limits:
        info(f"Unlimited parameter(s): {', '.join(unlimited_limits)} (single limit, lower risk)")
    elif excessive_limits:
        warn(f"Large response limits: {', '.join(excessive_limits)}")
        add_observation(
            report_data,
            "Large Response Message Limits",
            "Security Misconfiguration",
            f"Server allows unusually large values: {', '.join(excessive_limits)}. "
            f"This increases the theoretical amplification surface but may be bounded by transport limits.",
            check="max-response",
            confidence="low",
            verification_status="confirmed-read",
            safe_check=True,
            destructive=False,
            evidence={
                "excessive_limits": excessive_limits,
                "max_response_size": response_size,
            },
        )
    else:
        good("Response message size limits appear configured")
