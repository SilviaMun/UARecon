"""
Access Restrictions & Role Permissions Check.

Reads the OPC UA Part 5 authorization metadata attributes on sensitive nodes:

  - AccessRestrictions  (AttributeId 26): bitmask — SigningRequired,
    EncryptionRequired, SessionRequired, ApplyRestrictionsToBrowse
  - RolePermissions     (AttributeId 24): array of (RoleId, PermissionBitmask)
  - UserRolePermissions (AttributeId 25): same, filtered for the current user

This check assesses authorization *modelling maturity*, not just observed
behavior.  It answers: does the server explicitly declare restriction metadata
on security-sensitive nodes, and is that metadata consistent with hardening
recommendations?

Pure read-only — never writes or modifies anything.

Framework alignment:
  - OPC UA Part 2/5: Authorization, Role, Permission, AccessRestriction
  - Practical Security Guidelines: granular authorization, role-based access
  - IEC 62443: FR2 (Use Control), FR1 (link permissions to identities)
"""

from asyncua import ua

from ._base import add_finding, add_observation
from ..banner import bad, warn, good, info, section, tag
from ..helpers import sc, sn


# Sensitive nodes where we expect to find explicit access restrictions
# in a well-configured server (from the OPC UA standard address space)
SENSITIVE_NODES = [
    ("i=2253",  "Server",                        "server root object"),
    ("i=2994",  "Server.Auditing",               "audit enable flag"),
    ("i=2274",  "Server.ServerDiagnostics.EnabledFlag", "diagnostics enable flag"),
    ("i=2996",  "ServerConfiguration",            "server security configuration"),
    ("i=13813", "CertificateGroups",              "certificate management"),
    ("i=15606", "KeyCredentialConfiguration",     "credential store"),
    ("i=15607", "AuthorizationServices",          "authorization service config"),
    ("i=11704", "OperationLimits",                "server operation limits"),
]

# Additional nodes to sample from deep enumeration (control/safety-related)
SENSITIVE_PATH_KEYWORDS = {
    "command", "control", "setpoint", "output", "safety",
    "interlock", "alarm", "motor", "valve", "pump",
    "password", "credential", "certificate", "key",
    "config", "configuration", "settings",
}

# AccessRestrictions flag names (OPC UA Part 3, 8.55)
ACCESS_RESTRICTION_FLAGS = {
    1: "SigningRequired",
    2: "EncryptionRequired",
    4: "SessionRequired",
    8: "ApplyRestrictionsToBrowse",
}

# PermissionType flag names (OPC UA Part 3, 8.56)
PERMISSION_FLAGS = {
    1:     "Browse",
    2:     "ReadRolePermissions",
    4:     "WriteAttribute",
    8:     "WriteRolePermissions",
    16:    "WriteHistorizing",
    32:    "Read",
    64:    "Write",
    128:   "ReadHistory",
    256:   "InsertHistory",
    512:   "ModifyHistory",
    1024:  "DeleteHistory",
    2048:  "ReceiveEvents",
    4096:  "Call",
    8192:  "AddReference",
    16384: "RemoveReference",
    32768: "DeleteNode",
    65536: "AddNode",
}

WRITE_PERMISSIONS = {"Write", "WriteAttribute", "WriteRolePermissions",
                     "WriteHistorizing", "InsertHistory", "ModifyHistory",
                     "DeleteHistory", "AddNode", "DeleteNode",
                     "AddReference", "RemoveReference"}


def _decode_flags(value, flag_map):
    if value is None:
        return []
    try:
        v = int(value)
    except (TypeError, ValueError):
        return []
    return [name for bit, name in sorted(flag_map.items()) if v & bit]


def _decode_permissions(mask):
    return _decode_flags(mask, PERMISSION_FLAGS)


def _decode_restrictions(mask):
    return _decode_flags(mask, ACCESS_RESTRICTION_FLAGS)


def _read_access_restrictions(node):
    try:
        result = node.read_attribute(ua.AttributeIds.AccessRestrictions)
        if result.Value and result.Value.Value is not None:
            return int(result.Value.Value)
    except Exception:
        pass
    return None


def _read_role_permissions(node):
    try:
        result = node.read_attribute(ua.AttributeIds.RolePermissions)
        if result.Value and result.Value.Value is not None:
            return result.Value.Value
    except Exception:
        pass
    return None


def _read_user_role_permissions(node):
    try:
        result = node.read_attribute(ua.AttributeIds.UserRolePermissions)
        if result.Value and result.Value.Value is not None:
            return result.Value.Value
    except Exception:
        pass
    return None


def _parse_role_permission_entry(entry):
    """Parse a RolePermissionType structure into a dict."""
    result = {"role_id": None, "permissions": [], "raw_mask": None}
    try:
        if hasattr(entry, "RoleId"):
            rid = entry.RoleId
            result["role_id"] = rid.to_string() if hasattr(rid, "to_string") else str(rid)
        if hasattr(entry, "Permissions"):
            mask = int(entry.Permissions)
            result["raw_mask"] = mask
            result["permissions"] = _decode_permissions(mask)
    except Exception:
        pass
    return result


def _analyze_node(client, node_id, label):
    """Read all access restriction metadata for a single node."""
    try:
        node = client.get_node(node_id)
    except Exception:
        return None

    result = {
        "node_id": node_id,
        "label": label,
        "accessible": False,
        "access_restrictions": None,
        "access_restrictions_flags": [],
        "role_permissions": [],
        "user_role_permissions": [],
        "has_explicit_restrictions": False,
        "has_role_permissions": False,
        "has_user_role_permissions": False,
    }

    # Verify the node is accessible at all
    try:
        node.read_node_class()
        result["accessible"] = True
    except Exception:
        return result

    # AccessRestrictions
    ar = _read_access_restrictions(node)
    if ar is not None:
        result["access_restrictions"] = ar
        result["access_restrictions_flags"] = _decode_restrictions(ar)
        result["has_explicit_restrictions"] = True

    # RolePermissions
    rp = _read_role_permissions(node)
    if rp is not None and hasattr(rp, "__iter__"):
        for entry in rp:
            parsed = _parse_role_permission_entry(entry)
            if parsed["role_id"]:
                result["role_permissions"].append(parsed)
        result["has_role_permissions"] = len(result["role_permissions"]) > 0

    # UserRolePermissions
    urp = _read_user_role_permissions(node)
    if urp is not None and hasattr(urp, "__iter__"):
        for entry in urp:
            parsed = _parse_role_permission_entry(entry)
            if parsed["role_id"]:
                result["user_role_permissions"].append(parsed)
        result["has_user_role_permissions"] = len(result["user_role_permissions"]) > 0

    return result


def check_access_restrictions(client, report_data):
    section("ACCESS RESTRICTIONS & ROLE PERMISSIONS")

    results = []
    process_samples = []

    # --- Phase 1: Check standard sensitive nodes ---
    for nid, label, desc in SENSITIVE_NODES:
        r = _analyze_node(client, nid, label)
        if r and r["accessible"]:
            results.append(r)

    # --- Phase 2: Sample process nodes from deep enumeration ---
    all_nodes = report_data.get("all_nodes", [])
    sampled = 0
    for n in all_nodes:
        if sampled >= 10:
            break
        path = n.get("path", "").lower()
        nid = n.get("node_id", "")
        if not nid:
            continue
        if any(kw in path for kw in SENSITIVE_PATH_KEYWORDS):
            r = _analyze_node(client, nid, n.get("path", nid))
            if r and r["accessible"]:
                process_samples.append(r)
                sampled += 1

    total_checked = len(results) + len(process_samples)
    if total_checked == 0:
        info("No sensitive nodes accessible for access restriction analysis")
        return

    # --- Analysis ---
    nodes_with_restrictions = [r for r in results if r["has_explicit_restrictions"]]
    nodes_with_roles = [r for r in results if r["has_role_permissions"]]
    nodes_with_user_roles = [r for r in results if r["has_user_role_permissions"]]
    process_with_restrictions = [r for r in process_samples if r["has_explicit_restrictions"]]
    process_with_roles = [r for r in process_samples if r["has_role_permissions"]]

    accessible_count = len(results)
    info(f"Sensitive nodes checked: {accessible_count}")
    info(f"Process nodes sampled: {len(process_samples)}")

    # --- Output per-node details ---
    for r in results:
        label = r["label"]
        if r["has_explicit_restrictions"]:
            flags = ", ".join(r["access_restrictions_flags"]) or "none"
            good(f"{label}: AccessRestrictions = {flags}")
        else:
            if r["accessible"]:
                warn(f"{label}: no AccessRestrictions attribute set")

        if r["has_role_permissions"]:
            for rp in r["role_permissions"][:5]:
                perms = ", ".join(rp["permissions"][:6])
                extra = f" +{len(rp['permissions']) - 6}" if len(rp["permissions"]) > 6 else ""
                info(f"  RolePermission: {rp['role_id']} -> [{perms}{extra}]")
        if r["has_user_role_permissions"]:
            for urp in r["user_role_permissions"][:5]:
                perms = ", ".join(urp["permissions"][:6])
                extra = f" +{len(urp['permissions']) - 6}" if len(urp["permissions"]) > 6 else ""
                info(f"  UserRolePermission: {urp['role_id']} -> [{perms}{extra}]")

    # --- Classify authorization maturity ---
    has_any_restrictions = len(nodes_with_restrictions) > 0 or len(process_with_restrictions) > 0
    has_any_roles = len(nodes_with_roles) > 0 or len(process_with_roles) > 0

    # --- Findings ---

    evidence = {
        "sensitive_nodes_checked": accessible_count,
        "process_nodes_sampled": len(process_samples),
        "nodes_with_access_restrictions": len(nodes_with_restrictions),
        "nodes_with_role_permissions": len(nodes_with_roles),
        "nodes_with_user_role_permissions": len(nodes_with_user_roles),
        "process_with_restrictions": len(process_with_restrictions),
        "process_with_roles": len(process_with_roles),
        "node_details": [
            {
                "node_id": r["node_id"],
                "label": r["label"],
                "restrictions": r["access_restrictions_flags"],
                "role_count": len(r["role_permissions"]),
                "user_role_count": len(r["user_role_permissions"]),
            }
            for r in results
        ],
    }

    # Finding 1: No access restriction metadata at all
    # This is common: AccessRestrictions and RolePermissions are OPC UA 1.04+
    # features that many servers (including major commercial products) don't
    # implement. Most use vendor-specific ACLs instead. Reported as observation.
    if not has_any_restrictions and not has_any_roles and accessible_count > 0:
        info(f"No AccessRestrictions or RolePermissions on {accessible_count} sensitive node(s)")
        add_observation(
            report_data,
            "Authorization Metadata Not Exposed on Sensitive Nodes",
            "Broken Access Control",
            f"None of the {accessible_count} checked sensitive nodes define "
            f"AccessRestrictions or RolePermissions attributes (OPC UA Part 5, added in 1.04). "
            f"The server may rely on vendor-specific or application-level authorization instead. "
            f"This is common and does not imply missing access control — verify through "
            f"behavioral checks (browse-acl, node-write, method-access).",
            check="access-restrictions",
            confidence="low",
            verification_status="confirmed-read",
            safe_check=True,
            destructive=False,
            evidence=evidence,
        )

    # Finding 2: Partial coverage — some nodes protected, some not
    if has_any_restrictions and accessible_count > 0:
        unprotected = [r for r in results if not r["has_explicit_restrictions"] and r["accessible"]]
        if unprotected:
            labels = [r["label"] for r in unprotected[:5]]
            warn(f"{len(unprotected)} sensitive node(s) lack AccessRestrictions")
            add_observation(
                report_data,
                "Partial Access Restriction Coverage",
                "Security Misconfiguration",
                f"{len(nodes_with_restrictions)} of {accessible_count} sensitive nodes have "
                f"AccessRestrictions, but {len(unprotected)} do not: {', '.join(labels)}. "
                f"Inconsistent restriction coverage may leave gaps in the authorization model.",
                check="access-restrictions",
                confidence="medium",
                verification_status="confirmed-read",
                safe_check=True,
                destructive=False,
                evidence=evidence,
            )

    # Finding 3: Restrictions present but missing encryption/signing requirement
    if nodes_with_restrictions:
        no_encryption = []
        no_signing = []
        for r in nodes_with_restrictions:
            flags = r["access_restrictions_flags"]
            if "EncryptionRequired" not in flags:
                no_encryption.append(r["label"])
            if "SigningRequired" not in flags:
                no_signing.append(r["label"])

        if no_encryption:
            warn(f"{len(no_encryption)} node(s) with restrictions but no EncryptionRequired")
            add_observation(
                report_data,
                "Access Restrictions Without Encryption Requirement",
                "Security Misconfiguration",
                f"{len(no_encryption)} sensitive node(s) define AccessRestrictions but do not "
                f"require encryption: {', '.join(no_encryption[:5])}. Without EncryptionRequired, "
                f"these nodes can be accessed over unencrypted channels.",
                check="access-restrictions",
                confidence="medium",
                verification_status="confirmed-read",
                safe_check=True,
                destructive=False,
                evidence=evidence,
            )

    # Finding 4: User has write permissions on sensitive nodes via RolePermissions
    user_write_nodes = []
    for r in results:
        for urp in r.get("user_role_permissions", []):
            write_perms = WRITE_PERMISSIONS & set(urp["permissions"])
            if write_perms:
                user_write_nodes.append({
                    "label": r["label"],
                    "node_id": r["node_id"],
                    "role": urp["role_id"],
                    "write_permissions": list(write_perms),
                })

    if user_write_nodes:
        warn(f"Current user has write RolePermissions on {len(user_write_nodes)} sensitive node(s)")
        tag("Broken Access Control")
        add_finding(
            report_data,
            "Write Role Permissions on Sensitive Nodes",
            "Medium",
            "Broken Access Control",
            f"The current user's UserRolePermissions include write-class permissions on "
            f"{len(user_write_nodes)} sensitive node(s): "
            f"{', '.join(n['label'] for n in user_write_nodes[:5])}. "
            f"This is based on server-declared metadata (no write was attempted). "
            f"If the provided credentials are for an administrative role, this may be expected. "
            f"Review whether this access level is appropriate for the intended user role.",
            check="access-restrictions",
            confidence="medium",
            verification_status="confirmed-read",
            safe_check=True,
            destructive=False,
            evidence={**evidence, "user_write_nodes": user_write_nodes[:10]},
        )

    # Finding 5: Process nodes without any authorization metadata
    if process_samples and not process_with_restrictions and not process_with_roles:
        if len(process_samples) >= 3:
            sample_labels = [r["label"] for r in process_samples[:5]]
            warn(f"Process-level nodes also lack authorization metadata")
            add_observation(
                report_data,
                "No Authorization Metadata on Process Nodes",
                "Security Misconfiguration",
                f"Sampled {len(process_samples)} process-level nodes with sensitive keywords, "
                f"none define AccessRestrictions or RolePermissions: "
                f"{', '.join(sample_labels[:3])}... "
                f"Authorization modelling does not extend to process-level nodes.",
                check="access-restrictions",
                confidence="medium",
                verification_status="confirmed-read",
                safe_check=True,
                destructive=False,
                evidence=evidence,
            )

    # Good outcome
    if has_any_restrictions and has_any_roles and not user_write_nodes:
        good(f"Authorization metadata present: "
             f"{len(nodes_with_restrictions)} with restrictions, "
             f"{len(nodes_with_roles)} with role permissions")
