from ._base import add_observation
from ..banner import bad, info, section, tag
from ..helpers import sc, sn


def check_role_permissions(client, report_data):
    section("ROLE / PERMISSION MODEL")
    roles_found = []
    for nid in ["i=15606", "i=23470", "i=16036"]:
        try:
            node = client.get_node(nid)
            children = sc(node)
            if children:
                for c in children:
                    name = sn(c)
                    if name and name != "?" and name not in roles_found:
                        roles_found.append(name)
        except Exception:
            pass

    if roles_found:
        bad(f"ROLES BROWSABLE: {', '.join(roles_found)}")
        tag("Information Disclosure")
        add_observation(
            report_data,
            "Role Configuration Browsable",
            "Information Disclosure",
            f"Server role configuration is browsable. Roles found: {', '.join(roles_found)}. "
            f"This may help attackers understand the authorization model.",
            check="roles",
            confidence="medium",
            verification_status="surface-only",
            safe_check=True,
            destructive=False,
            evidence={"roles": roles_found},
        )
    else:
        info("Role configuration not accessible (or RBAC not implemented)")
