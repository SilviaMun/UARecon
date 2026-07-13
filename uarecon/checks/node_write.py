"""
Node Write Access Verification (non-destructive).

NON-DESTRUCTIVE STRATEGY:
This check confirms write access by writing back the SAME value it just read
(idempotent write-back).  To guarantee zero operational impact it uses a
two-tier approach:

  Tier 1 -- VERIFIED (actual write-back on inert nodes only):
    The check ONLY performs writes on nodes whose path matches a strict
    allowlist of purely descriptive / metadata attributes where writing
    back the same value is provably harmless:
      description, label, displayname, engineeringunits, eurange,
      instrumentrange, deadband, hysteresis, title, comment, annotation,
      note, remark

    These nodes MUST also pass the deny-list filter (no control,
    safety, actuator, counter, or infrastructure keywords).

  Tier 2 -- REPORTED (UserAccessLevel only, no write attempted):
    All other writable nodes (control commands, safety interlocks,
    setpoints, outputs, infrastructure) are reported based on the
    server-reported UserAccessLevel attribute.  No Write service call
    is ever made to these nodes.

The net effect: proven write capability on harmless metadata nodes, plus
a risk-classified inventory of all writable nodes the user could affect.
"""

from asyncua import ua

from ._base import add_finding, add_observation
from ..banner import bad, warn, good, info, section, tag


# ---------------------------------------------------------------------------
# SAFE ALLOWLIST: only nodes whose path contains one of these keywords AND
# does not contain any dangerous keyword will be write-tested.
# These are passive metadata/configuration values where writing back the
# same value has no observable effect on the process.
# ---------------------------------------------------------------------------
SAFE_WRITE_KEYWORDS = {
    "description", "label", "displayname",
    "engineeringunits", "eurange", "instrumentrange",
    "deadband", "hysteresis",
    "title", "comment", "annotation", "note", "remark",
}

# ---------------------------------------------------------------------------
# DENY LIST: nodes containing these keywords are NEVER write-tested,
# regardless of whether they also match the safe allowlist.
# ---------------------------------------------------------------------------
DANGEROUS_PATH_KEYWORDS = {
    # Control/command nodes
    "command", "cmd", "start", "stop", "reset", "halt", "abort",
    "shutdown", "reboot", "restart", "emergency", "estop", "e-stop",
    "enable", "disable", "activate", "deactivate", "trigger",
    "execute", "run", "kill", "force", "override",
    # Safety-critical
    "safety", "interlock", "alarm", "fault", "error", "trip",
    "protect", "guard", "limit", "watchdog",
    # Motor/actuator control
    "motor", "actuator", "valve", "pump", "drive", "servo",
    "speed", "torque", "position", "setpoint",
    # Output/control words
    "output", "controlword", "control_word", "statusword",
    "plc_output", "digital_output", "analog_output",
    # Counters and accumulators (write may reset)
    "counter", "accumulator", "totalizer", "count",
    # Communication
    "disconnect", "connect", "close", "open",
}

# Standard server infrastructure node IDs -- never touch
NEVER_WRITE_NODEIDS = {
    "i=2994",   # Server.Auditing
    "i=2274",   # Server.ServerDiagnostics.EnabledFlag
    "i=11704",  # OperationLimits
}


def _is_safe_to_write_test(node_id, path):
    """
    Strict safety gate: returns True ONLY if the node is on the safe
    allowlist AND not on the deny list.
    """
    if node_id in NEVER_WRITE_NODEIDS:
        return False

    path_lower = path.lower()

    # Deny list takes absolute priority
    for kw in DANGEROUS_PATH_KEYWORDS:
        if kw in path_lower:
            return False

    # Must be on the safe allowlist
    return any(kw in path_lower for kw in SAFE_WRITE_KEYWORDS)


def _classify_node(node_id, path):
    """
    Classify a writable node by risk tier (for reporting on untested nodes).
    """
    if node_id in NEVER_WRITE_NODEIDS:
        return "infra"
    path_lower = path.lower()
    for kw in DANGEROUS_PATH_KEYWORDS:
        if kw in path_lower:
            return "safety"
    return "data"


def check_node_write_access(client, report_data):
    section("NODE WRITE VERIFICATION")

    writable_nodes = report_data.get("writable_nodes", [])
    if not writable_nodes:
        info("No writable nodes discovered (run deep enumeration first)")
        return

    # Partition nodes into safe-to-test vs report-only
    safe_candidates = []
    safety_critical = []
    infra_nodes = []
    other_writable = []

    for n in writable_nodes:
        nid = n.get("node_id", "")
        path = n.get("path", "")
        if not nid:
            continue

        if _is_safe_to_write_test(nid, path):
            safe_candidates.append(n)
        else:
            tier = _classify_node(nid, path)
            entry = {"node_id": nid, "path": path}
            if tier == "infra":
                infra_nodes.append(entry)
            elif tier == "safety":
                safety_critical.append(entry)
            else:
                other_writable.append(entry)

    # ---- Tier 1: write-test safe candidates (up to 10) ----
    confirmed_writable = []
    denied_at_runtime = []
    tested = 0

    for n in safe_candidates[:10]:
        nid = n.get("node_id", "")
        path = n.get("path", "")

        try:
            node = client.get_node(nid)
            current_val = node.read_value()
            tested += 1

            try:
                # Write back the EXACT same value -- idempotent, zero state change
                node.write_value(current_val)
                confirmed_writable.append(path or nid)
                bad(f"WRITE CONFIRMED: {path or nid} (same-value writeback)")
                tag("Broken Access Control")
            except ua.UaStatusCodeError as e:
                status = str(e).lower()
                if "baduseraccessdenied" in status or "badnotwritable" in status:
                    denied_at_runtime.append(path or nid)
                    good(f"Write denied at runtime: {path or nid}")
                else:
                    info(f"Write test {path or nid}: {e}")
            except Exception:
                pass
        except Exception:
            pass

    # ---- Tier 2: report untested writable nodes ----
    if safety_critical:
        for e in safety_critical[:10]:
            warn(f"WRITABLE (not tested): {e['path'] or e['node_id']}")
    if infra_nodes:
        for e in infra_nodes[:5]:
            warn(f"WRITABLE (infrastructure, not tested): {e['path'] or e['node_id']}")

    # ---- Summary line ----
    untested_total = len(safety_critical) + len(infra_nodes) + len(other_writable)
    info(f"Write-tested: {tested} inert node(s), confirmed: {len(confirmed_writable)}, "
         f"denied: {len(denied_at_runtime)}")
    info(f"Reported (UserAccessLevel only): {untested_total} node(s) "
         f"(safety={len(safety_critical)}, infra={len(infra_nodes)}, "
         f"other={len(other_writable)})")

    # ---- Findings ----

    # Finding 1: write confirmed on safe nodes -- proves the user role can write
    if confirmed_writable:
        extra_parts = []
        if safety_critical:
            extra_parts.append(
                f"{len(safety_critical)} safety-critical node(s) also report "
                f"writable UserAccessLevel (not write-tested)")
        if infra_nodes:
            extra_parts.append(
                f"{len(infra_nodes)} infrastructure node(s) also writable")
        extra = ". " + ". ".join(extra_parts) if extra_parts else ""

        add_finding(
            report_data,
            "Confirmed Write Access",
            "High",
            "Broken Access Control",
            f"Write access confirmed on {len(confirmed_writable)} node(s) via "
            f"same-value writeback on inert metadata nodes: "
            f"{', '.join(confirmed_writable[:5])}. "
            f"This proves the current user role has active write capability"
            f"{extra}.",
            check="node-write",
            confidence="high",
            verification_status="confirmed-write",
            safe_check=True,
            destructive=False,
            evidence={
                "confirmed_writable": confirmed_writable[:20],
                "safety_critical_count": len(safety_critical),
                "safety_critical_paths": [
                    e["path"] or e["node_id"] for e in safety_critical[:20]
                ],
                "infra_count": len(infra_nodes),
                "other_writable_count": len(other_writable),
                "tested": tested,
                "denied": len(denied_at_runtime),
            },
        )

    # Finding 2: safety-critical nodes writable but not write-tested
    if safety_critical and not confirmed_writable:
        paths = [e["path"] or e["node_id"] for e in safety_critical]
        add_finding(
            report_data,
            "Write Access to Safety-Critical Nodes (Unverified)",
            "High",
            "Broken Access Control",
            f"{len(safety_critical)} safety-critical node(s) report writable "
            f"UserAccessLevel: {', '.join(paths[:5])}. These include control "
            f"commands, interlocks, or actuator outputs. Write was NOT attempted "
            f"to avoid operational impact. No inert metadata nodes were available "
            f"to verify write capability independently.",
            check="node-write",
            confidence="medium",
            verification_status="access-level-read",
            safe_check=True,
            destructive=False,
            evidence={
                "safety_critical_writable": paths[:20],
                "total_writable": len(writable_nodes),
            },
        )

    # Finding 3: only generic writable nodes, no safety-critical, no confirmed
    if other_writable and not confirmed_writable and not safety_critical and not infra_nodes:
        paths = [e["path"] or e["node_id"] for e in other_writable]
        add_finding(
            report_data,
            "Writable Nodes Detected (Unverified)",
            "Medium",
            "Broken Access Control",
            f"{len(other_writable)} node(s) report writable UserAccessLevel: "
            f"{', '.join(paths[:5])}. No safe candidates were available for "
            f"write verification. Review whether write access is appropriate "
            f"for this user role.",
            check="node-write",
            confidence="medium",
            verification_status="access-level-read",
            safe_check=True,
            destructive=False,
            evidence={
                "writable_paths": paths[:20],
                "total_writable": len(writable_nodes),
            },
        )

    # Good: all safe candidates denied at runtime
    if tested > 0 and not confirmed_writable and denied_at_runtime:
        good(f"All {len(denied_at_runtime)} tested node(s) denied write at runtime")

    # Nothing writable at all
    if not confirmed_writable and not safety_critical and not infra_nodes and not other_writable:
        good("No writable nodes after filtering")
