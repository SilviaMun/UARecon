import re

from ._base import add_finding
from ..banner import bad, good, info, section, tag


def check_namespace_exposure(client, report_data):
    section("NAMESPACE ANALYSIS")
    try:
        ns_array = client.get_namespace_array()
        if not ns_array or len(ns_array) <= 2:
            info(f"Only standard namespaces ({len(ns_array or [])})")
            return

        standard_prefixes = ("http://opcfoundation.org/", "urn:opcfoundation.org:")
        vendor_ns = []
        for i, ns in enumerate(ns_array):
            if ns and not any(ns.startswith(p) for p in standard_prefixes):
                vendor_ns.append((i, ns))

        if not vendor_ns:
            good("Only standard OPC Foundation namespaces present")
            return

        for idx, ns in vendor_ns:
            info(f"Namespace [{idx}]: {ns}")

        ip_pattern = re.compile(r'(?:192\.168|10\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}')
        host_keywords = ["localhost", "internal"]
        sensitive = []
        for _, ns in vendor_ns:
            score = 0
            ns_lower = ns.lower()

            if ip_pattern.search(ns_lower):
                score += 3
            if "localhost" in ns_lower:
                score += 1
            if "internal" in ns_lower:
                score += 1

            if score >= 3:
                sensitive.append(ns)

        if sensitive:
            bad(f"Namespace URIs reveal internal info: {', '.join(sensitive)}")
            tag("Information Disclosure")
            add_finding(
                report_data,
                "Namespace URIs Expose Internal Structure",
                "Medium",
                "Information Disclosure",
                f"Vendor namespace URIs contain internal hostnames or network info: {', '.join(sensitive)}. "
                f"This may reveal infrastructure details.",
                check="namespaces",
                confidence="medium",
                verification_status="pattern-match",
                safe_check=True,
                destructive=False,
                evidence={"sensitive_namespaces": sensitive},
            )
    except Exception:
        info("Could not read namespace array")
