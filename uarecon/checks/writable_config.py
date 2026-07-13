"""
Server Configuration Write Access Check.

Checks if the current user has write access to critical server configuration
nodes: Auditing EnabledFlag and Diagnostics EnabledFlag.

This check reads the UserAccessLevel attribute (which is user-specific and
set by the server's authorization model). It does NOT attempt to actually
write to these nodes to avoid impacting server behavior.

If the UserAccessLevel includes Write, an attacker with the same credentials
could disable auditing or diagnostics to cover their tracks.
"""

from ._base import add_finding
from ..banner import bad, good, info, section, tag


def check_writable_server_config(client, report_data):
    section("SERVER CONFIGURATION WRITE ACCESS")
    config_nodes = [
        ("i=2994", "Auditing EnabledFlag", "Disabling auditing erases attack traces"),
        ("i=2274", "Diagnostics EnabledFlag", "Disabling diagnostics hides server state"),
    ]

    writable_found = []

    for nid, label, impact in config_nodes:
        try:
            node = client.get_node(nid)
            ual = node.get_user_access_level()
            access = str(ual)
            writable = "Write" in access or (isinstance(ual, int) and (ual & 0x02))
            if writable:
                bad(f"WRITABLE CONFIG NODE: {label} ({nid})")
                tag("Broken Access Control")
                writable_found.append({
                    "node_id": nid,
                    "label": label,
                    "impact": impact,
                    "user_access_level": access,
                })
            else:
                good(f"{label} ({nid}) is read-only for current user")
        except Exception:
            pass

    if writable_found:
        labels = [w["label"] for w in writable_found]
        add_finding(
            report_data,
            f"Server Config Writable: {', '.join(labels)}",
            "High",
            "Broken Access Control",
            f"The current user's UserAccessLevel includes Write on critical configuration node(s): "
            f"{', '.join(labels)}. This is based on the server-reported UserAccessLevel attribute "
            f"(no actual write was attempted). An attacker with these credentials could modify "
            f"server security settings.",
            check="writable-config",
            confidence="high",
            verification_status="access-level-read",
            safe_check=True,
            destructive=False,
            evidence=writable_found,
        )
