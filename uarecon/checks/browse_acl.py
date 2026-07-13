from asyncua import ua

from ._base import add_finding, add_observation
from ..banner import bad, warn, good, section, tag
from ..helpers import sc, sn


def check_browse_access_control(client, report_data):
    section("BROWSE ACCESS CONTROL")

    sensitive_areas = [
        ("i=2996", "ServerConfiguration", "server security configuration"),
        ("i=13813", "CertificateGroups", "certificate management objects"),
        ("i=15606", "KeyCredentialConfiguration", "credential store"),
        ("i=15607", "AuthorizationServices", "authorization service configuration"),
    ]

    admin_evidence = []
    session_diag_exposed = False
    session_diag_count = 0
    session_diag_samples = []

    for nid, label, desc in sensitive_areas:
        try:
            node = client.get_node(nid)
            children = sc(node)
            if not children:
                continue

            readable_children = 0
            method_children = 0
            sample_children = []

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
                    method_children += 1

                try:
                    _ = child.read_value()
                    readable_children += 1
                except Exception:
                    pass

                if len(sample_children) < 5:
                    sample_children.append(child_name)

            warn(
                f"BROWSABLE ADMIN OBJECT: {label} "
                f"(children={len(children)}, readable={readable_children}, methods={method_children})"
            )
            tag("Information Disclosure")

            admin_evidence.append({
                "node_id": nid,
                "label": label,
                "description": desc,
                "child_count": len(children),
                "readable_children": readable_children,
                "method_children": method_children,
                "sample_children": sample_children,
            })

        except Exception:
            pass

    # Check SessionDiagnosticsArray (i=3708) which is the actual array of
    # per-session diagnostic records. Node i=3707 (SessionsDiagnosticsSummary)
    # is a container whose children are the array nodes, NOT individual sessions.
    try:
        diag_array_node = client.get_node("i=3708")
        diag_array = diag_array_node.read_value()
        if diag_array and hasattr(diag_array, '__len__') and len(diag_array) > 1:
            session_diag_exposed = True
            session_diag_count = len(diag_array)

            for entry in diag_array[:5]:
                sample = {}
                try:
                    if hasattr(entry, 'SessionName'):
                        sample["session_name"] = str(entry.SessionName)[:80]
                    if hasattr(entry, 'ClientDescription'):
                        cd = entry.ClientDescription
                        if hasattr(cd, 'ApplicationName'):
                            sample["client_app"] = str(cd.ApplicationName)[:80]
                    if hasattr(entry, 'ServerUri'):
                        sample["server_uri"] = str(entry.ServerUri)[:80]
                except Exception:
                    sample["raw"] = str(entry)[:160]
                session_diag_samples.append(sample)

            bad(f"Session diagnostics visible: {session_diag_count} sessions (including other clients)")
            tag("Information Disclosure")
        elif diag_array and hasattr(diag_array, '__len__') and len(diag_array) == 1:
            pass
    except Exception:
        pass

    # Fallback: enum_sessions may have found other sessions via child-object
    # browsing of i=3706, even if the array read above failed or returned ≤1.
    if not session_diag_exposed:
        enumerated_sessions = report_data.get("sessions", [])
        if len(enumerated_sessions) > 1:
            session_diag_exposed = True
            session_diag_count = len(enumerated_sessions)
            for s in enumerated_sessions[:5]:
                sample = {}
                if s.get("SessionName"):
                    sample["session_name"] = str(s["SessionName"])[:80]
                if s.get("name"):
                    sample["client_app"] = str(s["name"])[:80]
                if s.get("EndpointUrl"):
                    sample["endpoint_url"] = str(s["EndpointUrl"])[:80]
                session_diag_samples.append(sample)
            bad(f"Session diagnostics visible: {session_diag_count} sessions (from enumeration)")
            tag("Information Disclosure")

    if session_diag_exposed:
        add_finding(
            report_data,
            "Session Diagnostics Exposed",
            "Medium",
            "Information Disclosure",
            f"Current user can browse {session_diag_count} session diagnostic entries, including other clients. "
            f"This may expose client identities, connection times, endpoint usage, and operational metadata.",
            check="browse-acl",
            confidence="high",
            verification_status="confirmed-read",
            safe_check=True,
            destructive=False,
            evidence={
                "session_entry_count": session_diag_count,
                "samples": session_diag_samples,
            },
        )

    if admin_evidence:
        add_observation(
            report_data,
            "Administrative Security Surface Exposed",
            "Information Disclosure",
            "Administrative or security-relevant objects are browsable by the current user. "
            "This is based on read-only enumeration only and does not prove write access or dangerous method execution.",
            check="browse-acl",
            confidence="medium",
            verification_status="surface-only",
            safe_check=True,
            destructive=False,
            evidence=admin_evidence,
        )

    if not session_diag_exposed and not admin_evidence:
        good("Sensitive server areas not accessible to current user")
