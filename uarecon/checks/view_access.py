from asyncua import ua

from ._base import add_observation
from ..banner import warn, good, info, section
from ..helpers import sc, sn


def check_view_access_control(client, report_data):
    section("VIEW-BASED ACCESS CONTROL")

    # Views (i=87) provide a mechanism to present subsets of the
    # AddressSpace to different users/roles. If no Views are defined, all users
    # browse the same complete namespace without segregation.

    views_found = []
    try:
        views_node = client.get_node("i=87")  # Views folder
        children = sc(views_node)

        for child in children[:30]:
            try:
                name = sn(child)
                nid = child.nodeid.to_string()
                views_found.append({"name": name, "node_id": nid})
            except Exception:
                pass

    except Exception:
        info("Could not access Views folder (i=87)")
        return

    if views_found:
        info(f"Views defined: {len(views_found)}")
        for v in views_found[:10]:
            info(f"  View: {v['name']} ({v['node_id']})")

        # Check if the views are meaningful (have browse targets)
        meaningful_views = 0
        for v in views_found[:5]:
            try:
                view_node = client.get_node(v["node_id"])
                view_children = sc(view_node)
                if view_children:
                    meaningful_views += 1
            except Exception:
                pass

        if meaningful_views > 0:
            good(f"Server implements Views for namespace segregation ({meaningful_views} with content)")
        else:
            warn("Views are defined but appear empty (may not provide effective segregation)")
    else:
        # No views means everyone sees the full address space
        # This is only relevant if the server has multiple user roles

        # Check if RBAC appears to be in use by looking at earlier check results
        has_role_findings = any(
            f.get("check") == "roles" for f in report_data.get("findings", [])
        )

        if has_role_findings:
            warn("No Views defined despite role-based access model detected")
            add_observation(
                report_data,
                "No View-Based Namespace Segregation",
                "Security Misconfiguration",
                "Server defines roles but does not implement Views for namespace segregation. "
                "All authenticated users may browse the same address space regardless of role. "
                "Views provide a mechanism to restrict namespace visibility per role/context.",
                check="view-access",
                confidence="medium",
                verification_status="confirmed-read",
                safe_check=True,
                destructive=False,
                evidence={"views_count": 0, "has_roles": True},
            )
        else:
            info("No Views defined (all users browse full address space)")
