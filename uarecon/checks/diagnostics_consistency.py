"""
Diagnostics Consistency Check.

Reads the server's security and session diagnostic counters, then correlates
them with each other and with state observed by other checks to assess:

  - Are the counters internally consistent?
  - Do they match what we actually observe?
  - Is there evidence of untracked security events?
  - Is the diagnostic pipeline functional or broken/misleading?

This is a pure read-only check. It never writes any value.

Framework alignment:
  - OPC UA Part 2: Auditability, Availability
  - Practical Security Guidelines: auditing enabled, security event visibility
  - IEC 62443: FR6 (Timely Response to Events), FR7 (Resource Availability),
    FR1 (correlate auth failures)
"""

from ._base import add_finding, add_observation
from ..banner import bad, warn, good, info, section, tag


# Node IDs for server diagnostic counters
DIAG_NODES = {
    "ServerViewCount":                "i=2276",
    "CurrentSessionCount":            "i=2277",
    "CumulatedSessionCount":          "i=2278",
    "SecurityRejectedSessionCount":   "i=2279",
    "RejectedSessionCount":           "i=2280",
    "SessionTimeoutCount":            "i=2281",
    "SessionAbortCount":              "i=2282",
    "CurrentSubscriptionCount":       "i=2284",
    "CumulatedSubscriptionCount":     "i=2285",
    "SecurityRejectedRequestsCount":  "i=2287",
    "RejectedRequestsCount":          "i=2288",
}


def _read_counter(client, node_id):
    try:
        val = client.get_node(node_id).read_value()
        if val is not None:
            return int(val)
    except Exception:
        pass
    return None


def _read_all_counters(client):
    counters = {}
    for label, nid in DIAG_NODES.items():
        counters[label] = _read_counter(client, nid)
    return counters


def check_diagnostics_consistency(client, report_data):
    section("DIAGNOSTICS CONSISTENCY")

    # --- Read diagnostic enabled flag ---
    diag_enabled = None
    try:
        diag_enabled = client.get_node("i=2274").read_value()
    except Exception:
        pass

    audit_enabled = None
    try:
        audit_enabled = client.get_node("i=2994").read_value()
    except Exception:
        pass

    # --- Read counters (prefer already-enumerated data, fall back to live read) ---
    cached = report_data.get("security_diag", {})
    if cached:
        counters = {}
        for label in DIAG_NODES:
            val = cached.get(label)
            counters[label] = int(val) if val is not None else None
    else:
        counters = _read_all_counters(client)

    # --- How many counters are readable? ---
    readable = {k: v for k, v in counters.items() if v is not None}
    unreadable = [k for k, v in counters.items() if v is None]

    if not readable:
        warn("No diagnostic counters are readable")
        add_observation(
            report_data,
            "Diagnostic Counters Not Accessible",
            "Security Misconfiguration",
            "None of the standard server diagnostic counters (ServerDiagnosticsSummary) "
            "could be read. Security telemetry is unavailable to the current session, "
            "which may indicate restricted access or disabled diagnostics.",
            check="diagnostics-consistency",
            confidence="medium",
            verification_status="confirmed-read",
            safe_check=True,
            destructive=False,
            evidence={"diag_enabled": diag_enabled, "unreadable": unreadable},
        )
        return

    info(f"Readable counters: {len(readable)}/{len(DIAG_NODES)}")
    if unreadable:
        info(f"Unreadable: {', '.join(unreadable)}")

    # --- Consistency checks ---
    issues = []
    anomalies = []

    cur_sessions = counters.get("CurrentSessionCount")
    cum_sessions = counters.get("CumulatedSessionCount")
    rej_sessions = counters.get("RejectedSessionCount")
    sec_rej_sessions = counters.get("SecurityRejectedSessionCount")
    timeout_sessions = counters.get("SessionTimeoutCount")
    abort_sessions = counters.get("SessionAbortCount")

    cur_subs = counters.get("CurrentSubscriptionCount")
    cum_subs = counters.get("CumulatedSubscriptionCount")

    sec_rej_requests = counters.get("SecurityRejectedRequestsCount")
    rej_requests = counters.get("RejectedRequestsCount")

    # Check 1: CurrentSessionCount <= CumulatedSessionCount
    if cur_sessions is not None and cum_sessions is not None:
        if cur_sessions > cum_sessions:
            issues.append(
                f"CurrentSessionCount ({cur_sessions}) > CumulatedSessionCount ({cum_sessions}) "
                f"— logically impossible, counter implementation may be broken"
            )

    # Check 2: SecurityRejectedSessionCount <= RejectedSessionCount
    if sec_rej_sessions is not None and rej_sessions is not None:
        if sec_rej_sessions > rej_sessions:
            issues.append(
                f"SecurityRejectedSessionCount ({sec_rej_sessions}) > RejectedSessionCount ({rej_sessions}) "
                f"— security rejections should be a subset of total rejections"
            )

    # Check 3: SecurityRejectedRequestsCount <= RejectedRequestsCount
    if sec_rej_requests is not None and rej_requests is not None:
        if sec_rej_requests > rej_requests:
            issues.append(
                f"SecurityRejectedRequestsCount ({sec_rej_requests}) > RejectedRequestsCount ({rej_requests}) "
                f"— security rejections should be a subset of total rejections"
            )

    # Check 4: CurrentSubscriptionCount <= CumulatedSubscriptionCount
    if cur_subs is not None and cum_subs is not None:
        if cur_subs > cum_subs:
            issues.append(
                f"CurrentSubscriptionCount ({cur_subs}) > CumulatedSubscriptionCount ({cum_subs}) "
                f"— logically impossible"
            )

    # Check 5: CumulatedSessionCount should be >= 1 (our own session)
    # Treated as anomaly rather than inconsistency: could be lazy init, race
    # condition with counter update, or minimal implementation returning 0.
    if cum_sessions is not None and cum_sessions == 0:
        anomalies.append(
            "CumulatedSessionCount is 0 despite having an active session "
            "— counter may not be incrementing or may use lazy initialization"
        )

    # Check 6: CurrentSessionCount should be >= 1 (our own session)
    if cur_sessions is not None and cur_sessions == 0:
        anomalies.append(
            "CurrentSessionCount is 0 despite having an active session "
            "— counter may not be tracking or may use lazy initialization"
        )

    # Check 7: Cross-validate with observed sessions
    observed_sessions = report_data.get("sessions", [])
    if cur_sessions is not None and observed_sessions:
        observed_count = len(observed_sessions)
        if cur_sessions < observed_count:
            issues.append(
                f"CurrentSessionCount ({cur_sessions}) < observed sessions ({observed_count}) "
                f"— counter underreports active sessions"
            )

    # --- Anomaly detection ---

    # Anomaly 1: High rejection rate
    if cum_sessions is not None and rej_sessions is not None and cum_sessions > 0:
        total_attempts = cum_sessions + rej_sessions
        if total_attempts > 10 and rej_sessions / total_attempts > 0.3:
            anomalies.append(
                f"High session rejection rate: {rej_sessions}/{total_attempts} "
                f"({rej_sessions / total_attempts:.0%}) — may indicate active attacks or misconfiguration"
            )

    # Anomaly 2: Security rejections present but audit disabled
    if (sec_rej_sessions is not None and sec_rej_sessions > 0
            and audit_enabled is not None and not audit_enabled):
        anomalies.append(
            f"SecurityRejectedSessionCount={sec_rej_sessions} but auditing is disabled "
            f"— security events are occurring but not being logged"
        )

    if (sec_rej_requests is not None and sec_rej_requests > 0
            and audit_enabled is not None and not audit_enabled):
        anomalies.append(
            f"SecurityRejectedRequestsCount={sec_rej_requests} but auditing is disabled "
            f"— security-relevant request rejections are not being logged"
        )

    # Anomaly 3: High timeout/abort ratio
    if (timeout_sessions is not None and cum_sessions is not None
            and cum_sessions > 10 and timeout_sessions > 0):
        ratio = timeout_sessions / cum_sessions
        if ratio > 0.2:
            anomalies.append(
                f"SessionTimeoutCount/CumulatedSessionCount = {timeout_sessions}/{cum_sessions} "
                f"({ratio:.0%}) — high timeout ratio may indicate connectivity issues or poor session management"
            )

    if (abort_sessions is not None and cum_sessions is not None
            and cum_sessions > 10 and abort_sessions > 0):
        ratio = abort_sessions / cum_sessions
        if ratio > 0.2:
            anomalies.append(
                f"SessionAbortCount/CumulatedSessionCount = {abort_sessions}/{cum_sessions} "
                f"({ratio:.0%}) — high abort ratio may indicate instability or attacks"
            )

    # Anomaly 4: Diagnostics enabled but all counters are zero
    if diag_enabled and all(v == 0 for v in readable.values()):
        anomalies.append(
            "All diagnostic counters are zero despite diagnostics being enabled "
            "— counters may not be properly implemented (cosmetic diagnostics)"
        )

    # Anomaly 5: Request rejections without session rejections
    if (rej_requests is not None and rej_requests > 0
            and rej_sessions is not None and rej_sessions == 0
            and sec_rej_sessions is not None and sec_rej_sessions == 0):
        anomalies.append(
            f"RejectedRequestsCount={rej_requests} but no rejected sessions "
            f"— requests are being denied within established sessions (authorization failures?)"
        )

    # --- Output ---
    for issue in issues:
        bad(f"INCONSISTENCY: {issue}")
        tag("Security Misconfiguration")

    for anomaly in anomalies:
        warn(f"ANOMALY: {anomaly}")

    evidence = {
        "counters": readable,
        "unreadable_counters": unreadable,
        "diag_enabled": diag_enabled,
        "audit_enabled": audit_enabled,
        "observed_session_count": len(observed_sessions) if observed_sessions else None,
        "issues": issues,
        "anomalies": anomalies,
    }

    # --- Findings ---

    if issues:
        add_finding(
            report_data,
            "Diagnostic Counter Inconsistencies",
            "Medium",
            "Security Misconfiguration",
            f"{len(issues)} internal inconsistency(ies) found in server diagnostic counters: "
            f"{issues[0]}"
            + (f" (+{len(issues) - 1} more)" if len(issues) > 1 else "")
            + ". Inconsistent counters undermine incident detection and forensic capability.",
            check="diagnostics-consistency",
            confidence="high",
            verification_status="confirmed-read",
            safe_check=True,
            destructive=False,
            evidence=evidence,
        )

    if anomalies:
        add_finding(
            report_data,
            "Diagnostic Telemetry Anomalies",
            "Medium",
            "Security Misconfiguration",
            f"{len(anomalies)} anomaly(ies) detected in security diagnostics: "
            f"{anomalies[0]}"
            + (f" (+{len(anomalies) - 1} more)" if len(anomalies) > 1 else "")
            + ". Review diagnostic configuration and investigate potential security events.",
            check="diagnostics-consistency",
            confidence="medium",
            verification_status="confirmed-read",
            safe_check=True,
            destructive=False,
            evidence=evidence,
        )

    if not issues and not anomalies:
        if len(readable) >= 4:
            good(f"Diagnostic counters consistent and plausible ({len(readable)} counters checked)")
        else:
            info(f"Limited counters available ({len(readable)}/{len(DIAG_NODES)}), "
                 f"no inconsistencies found — server may be a minimal implementation")
