"""
GDS / Certificate Trust List Access Check.

Notes on false positive avoidance:
- Certificate group nodes (DefaultApplicationGroup, etc.) are standard
  address space objects. Being browsable is EXPECTED on any server that advertises
  GDS support. Browsability alone is NOT a finding.
- Only report when:
  1. Certificate management METHODS are visible (UpdateCertificate, etc.)
  2. Trust list VALUES are actually readable (not just the container node)
"""

from asyncua import ua

from ._base import add_finding, add_observation
from ..banner import bad, warn, good, info, section, tag
from ..helpers import sc, sn


def check_gds_trust_list(client, report_data):
    section("GDS / CERTIFICATE TRUST LIST ACCESS")

    trust_paths = [
        ("i=12555", "DefaultApplicationGroup"),
        ("i=12556", "DefaultHttpsGroup"),
        ("i=14088", "DefaultUserTokenGroup"),
    ]

    groups_with_methods = []
    groups_with_readable_data = []

    for nid, label in trust_paths:
        try:
            node = client.get_node(nid)
            children = sc(node)
            if not children:
                continue

            method_names = []
            readable_values = 0
            trust_list_readable = False

            for child in children[:20]:
                try:
                    child_name = sn(child)
                except Exception:
                    child_name = "?"

                try:
                    nc = child.read_node_class()
                except Exception:
                    nc = None

                if nc == ua.NodeClass.Method:
                    method_names.append(child_name)

                if nc == ua.NodeClass.Variable:
                    try:
                        val = child.read_value()
                        if val is not None:
                            readable_values += 1
                            # Check if this is an actual trust list (contains cert data)
                            if child_name == "TrustList" or "trust" in child_name.lower():
                                trust_list_readable = True
                    except Exception:
                        pass

            # Only flag if there's something actionable beyond standard browsability
            if method_names:
                warn(
                    f"CERT MANAGEMENT METHODS VISIBLE: {label} "
                    f"(methods: {', '.join(method_names[:5])})"
                )
                tag("Information Disclosure")
                groups_with_methods.append({
                    "node_id": nid,
                    "label": label,
                    "methods": method_names[:10],
                })

            if trust_list_readable or readable_values > 2:
                info(
                    f"Certificate data readable in {label} "
                    f"({readable_values} values, trust_list={trust_list_readable})"
                )
                groups_with_readable_data.append({
                    "node_id": nid,
                    "label": label,
                    "readable_values": readable_values,
                    "trust_list_readable": trust_list_readable,
                })

        except Exception:
            pass

    if groups_with_methods:
        # Methods like UpdateCertificate, AddCertificate, RemoveCertificate
        # being visible means the user could potentially modify the trust store
        method_list = []
        for g in groups_with_methods:
            method_list.extend(g["methods"])
        add_observation(
            report_data,
            "Certificate Management Methods Visible",
            "Information Disclosure",
            f"Certificate management methods are visible to the current user: "
            f"{', '.join(method_list[:8])}. Method visibility does not prove executability - "
            f"use the method-access check (testing-only) to verify if methods are callable.",
            check="gds-trust",
            confidence="medium",
            verification_status="surface-only",
            safe_check=True,
            destructive=False,
            evidence=groups_with_methods,
        )
    elif groups_with_readable_data:
        # Trust list data is readable but no methods visible
        add_observation(
            report_data,
            "Certificate Trust Data Readable",
            "Information Disclosure",
            "Certificate group data is readable by the current user. "
            "This may expose the server's trusted certificate list. "
            "Access control should restrict trust list reads to administrators.",
            check="gds-trust",
            confidence="medium",
            verification_status="confirmed-read",
            safe_check=True,
            destructive=False,
            evidence=groups_with_readable_data,
        )
    else:
        good("Certificate trust lists not accessible (or GDS not implemented)")
