"""
Provided Credentials Assessment.

Evaluates user-supplied credentials across all advertised endpoints to produce
a unified access profile:

  - Which endpoints accept the credentials (and which reject them)
  - Security policy, mode, and user token type used on each
  - Effective access level: browse, read, history, method reachability, write
  - Whether the endpoint configuration is consistent with hardening guidelines

This check is prod-safe: it only uses credentials explicitly provided by the
operator and performs no guessing, brute-force, or write operations beyond
same-value writeback on inert metadata nodes (same strategy as node_write.py).

Framework alignment:
  - OPC UA Part 2: Application Authentication + User Authentication + Authorization
  - Practical Security Guidelines: credentials over secure channels, least privilege
  - IEC 62443: FR1 (Identification & Authentication), FR2 (Use Control)
"""

import datetime

from asyncua import ua
from asyncua.sync import Client

from ._base import add_finding, add_observation
from ..banner import critical, bad, warn, good, info, section, tag
from ..helpers import (
    safe_disconnect, classify_error, sc, sn,
    generate_self_signed_cert, cleanup_temp_artifacts,
)


def _probe_access(client):
    """Probe what the authenticated session can actually do. Returns a dict."""
    access = {
        "can_browse": False,
        "browse_count": 0,
        "can_read": False,
        "read_sample": None,
        "can_history": False,
        "history_count": 0,
        "executable_methods": 0,
        "can_write": False,
        "write_node": None,
    }

    # --- Browse ---
    try:
        objects = client.get_objects_node()
        children = sc(objects)
        if children:
            access["can_browse"] = True
            access["browse_count"] = len(children)
    except Exception:
        pass

    # --- Read ---
    try:
        val = client.get_node("i=2258").read_value()
        if val is not None:
            access["can_read"] = True
            access["read_sample"] = "CurrentTime"
    except Exception:
        pass

    # --- History ---
    try:
        node = client.get_node("i=2258")
        now = datetime.datetime.now(datetime.timezone.utc)
        start = now - datetime.timedelta(days=1)
        results = node.read_raw_history(start, now, numvalues=3)
        if results:
            access["can_history"] = True
            access["history_count"] = len(results)
    except Exception:
        pass

    # --- Method reachability (check UserExecutable on Objects children) ---
    try:
        if access["can_browse"]:
            objects = client.get_objects_node()
            for child in sc(objects)[:30]:
                try:
                    nc = child.read_node_class()
                    if nc == ua.NodeClass.Method:
                        user_exec = child.read_attribute(ua.AttributeIds.UserExecutable)
                        if user_exec.Value and bool(user_exec.Value.Value):
                            access["executable_methods"] += 1
                except Exception:
                    continue
    except Exception:
        pass

    # --- Write capability (same-value writeback on ServerStatus.CurrentTime description) ---
    # Uses the same safe strategy as node_write.py: only inert metadata nodes
    SAFE_WRITE_TARGETS = [
        "i=2258",  # CurrentTime (try reading Description attribute)
    ]
    for nid in SAFE_WRITE_TARGETS:
        try:
            node = client.get_node(nid)
            ual = node.read_attribute(ua.AttributeIds.UserAccessLevel)
            if ual.Value and int(ual.Value.Value) & 0x02:
                access["can_write"] = True
                access["write_node"] = nid
        except Exception:
            pass

    return access


def _classify_access_level(access):
    """Classify the overall access as minimal, moderate, or elevated.

    Conservative scoring: browse + read on standard nodes is expected for any
    authenticated user, so it counts as minimal.  Write capability is based on
    the server-reported UserAccessLevel attribute (not a confirmed write), so
    it only bumps one tier.
    """
    score = 0
    if access["can_browse"]:
        score += 1
    if access["can_read"]:
        score += 1
    if access["can_history"]:
        score += 1
    if access["executable_methods"] > 0:
        score += 1
    if access["can_write"]:
        score += 2

    if score == 0:
        return "none"
    if score <= 2:
        return "minimal"
    if score <= 4:
        return "moderate"
    return "elevated"


def _endpoint_hardening_issues(policy, mode, tokens):
    """Check if the endpoint configuration has hardening issues for authenticated access.

    Only flags issues that are clearly problematic.  Sign-only mode and
    Anonymous+UserName coexistence are standard OPC UA configurations and are
    NOT flagged here (Sign-only may still encrypt the password via per-token
    SecurityPolicyUri, and Anonymous is required for endpoint discovery).
    """
    issues = []

    if policy == "None" and mode == "None":
        issues.append("credentials transmitted without any transport encryption")

    if policy == "None" and mode != "None":
        issues.append(f"SecurityPolicy None with mode {mode}")

    if "Basic128Rsa15" in policy:
        issues.append(f"deprecated security policy {policy}")
    elif policy == "Basic256":
        issues.append(f"legacy security policy {policy} (SHA-1 based)")

    return issues


def check_provided_credentials(target, user, pwd, report_data, timeout=5):
    section("PROVIDED CREDENTIALS ASSESSMENT")
    info(f"Evaluating credentials for user: {user}")

    endpoints = report_data.get("endpoints", [])
    if not endpoints:
        info("No endpoint data available — attempting direct connection only")

    accepted = []
    rejected = []

    # Track which (policy, mode) combos we've already tested on the target
    tested_combos = set()

    for ep in endpoints:
        ep_url = ep.get("url", target)
        policy = ep.get("policy", "")
        mode = ep.get("mode", "")
        tokens = ep.get("tokens", [])

        if "UserName" not in tokens:
            continue

        combo_key = (policy, mode)
        if combo_key in tested_combos:
            continue
        tested_combos.add(combo_key)

        client = None
        auto_cert = auto_key = cnf_path = out_dir = None
        created_tmp = False
        try:
            client = Client(target, timeout=timeout)
            client.set_user(user)
            client.set_password(pwd)

            if policy != "None" and mode != "None":
                auto_cert, auto_key, cnf_path, out_dir, created_tmp = generate_self_signed_cert()
                if auto_cert:
                    try:
                        client.set_security_string(f"{policy},{mode},{auto_cert},{auto_key}")
                    except Exception:
                        cleanup_temp_artifacts(auto_cert, auto_key, cnf_path, out_dir, remove_dir=created_tmp)
                        safe_disconnect(client)
                        continue
                else:
                    safe_disconnect(client)
                    continue

            client.connect()
            access = _probe_access(client)
            access_level = _classify_access_level(access)
            hardening_issues = _endpoint_hardening_issues(policy, mode, tokens)

            entry = {
                "endpoint_url": ep_url,
                "policy": policy,
                "mode": mode,
                "tokens": tokens,
                "access": access,
                "access_level": access_level,
                "hardening_issues": hardening_issues,
            }
            accepted.append(entry)

            level_colors = {
                "none": good,
                "minimal": info,
                "moderate": warn,
                "elevated": warn,
            }
            display_fn = level_colors.get(access_level, info)

            capabilities = []
            if access["can_browse"]:
                capabilities.append(f"browse({access['browse_count']})")
            if access["can_read"]:
                capabilities.append("read")
            if access["can_history"]:
                capabilities.append(f"history({access['history_count']})")
            if access["executable_methods"] > 0:
                capabilities.append(f"methods({access['executable_methods']})")
            if access["can_write"]:
                capabilities.append("write")

            cap_str = ", ".join(capabilities) if capabilities else "session-only"
            display_fn(
                f"ACCEPTED on {policy}/{mode}: "
                f"access={access_level} [{cap_str}]"
            )

            if hardening_issues:
                for issue in hardening_issues:
                    warn(f"  hardening: {issue}")
                tag("Security Misconfiguration")

            safe_disconnect(client)
            if auto_cert:
                cleanup_temp_artifacts(auto_cert, auto_key, cnf_path, out_dir, remove_dir=created_tmp)

        except Exception as e:
            err = classify_error(e)
            rejected.append({
                "endpoint_url": ep_url,
                "policy": policy,
                "mode": mode,
                "error": err,
            })
            info(f"Rejected on {policy}/{mode}: {err}")
            safe_disconnect(client)
            if auto_cert:
                cleanup_temp_artifacts(auto_cert, auto_key, cnf_path, out_dir, remove_dir=created_tmp)

    # --- If no endpoints were tested (no endpoint data), try direct connect ---
    if not tested_combos:
        client = None
        try:
            client = Client(target, timeout=timeout)
            client.set_user(user)
            client.set_password(pwd)
            client.connect()
            access = _probe_access(client)
            access_level = _classify_access_level(access)
            accepted.append({
                "endpoint_url": target,
                "policy": "unknown",
                "mode": "unknown",
                "tokens": [],
                "access": access,
                "access_level": access_level,
                "hardening_issues": [],
            })
            info(f"Direct connection accepted: access={access_level}")
            safe_disconnect(client)
        except Exception as e:
            rejected.append({
                "endpoint_url": target,
                "policy": "unknown",
                "mode": "unknown",
                "error": classify_error(e),
            })
            safe_disconnect(client)

    # --- Summary ---
    section("CREDENTIAL ASSESSMENT SUMMARY")
    info(f"Endpoints tested: {len(tested_combos) or 1}")
    info(f"Accepted: {len(accepted)}, Rejected: {len(rejected)}")

    if not accepted:
        # Distinguish cert/URI gating from actual credential rejection
        cert_gating_errors = {
            "badcertificateuriinvalid", "badcertificateuntrusted",
            "badcertificateinvalid", "badapplicationsignatureinvalid",
            "badsecuritypolicyrejected", "badsecuritymodeinsufficient",
        }
        auth_errors = {
            "baduseraccessdenied", "badidentitytokenrejected",
            "badidentitytokeninvalid",
        }
        rej_errors = [r.get("error", "") for r in rejected]
        cert_gated = [e for e in rej_errors if e in cert_gating_errors]
        auth_denied = [e for e in rej_errors if e in auth_errors]

        if cert_gated and not auth_denied:
            warn("Provided credentials could not be validated — all endpoints "
                 "rejected at the application certificate / URI stage")
            info(f"Rejection causes: {', '.join(sorted(set(cert_gated)))}")
            info("This does not confirm or deny the validity of the username/password; "
                 "the session was blocked before user authentication could occur.")
        elif auth_denied:
            good(f"Provided credentials rejected by user authentication "
                 f"({', '.join(sorted(set(auth_denied)))})")
        else:
            good("Provided credentials were not accepted on any endpoint")
        return

    # --- Build evidence ---
    evidence = {
        "user": user,
        "accepted_endpoints": [],
        "rejected_endpoints": [
            {"policy": r["policy"], "mode": r["mode"], "error": r["error"]}
            for r in rejected[:10]
        ],
    }

    for a in accepted:
        evidence["accepted_endpoints"].append({
            "policy": a["policy"],
            "mode": a["mode"],
            "access_level": a["access_level"],
            "can_browse": a["access"]["can_browse"],
            "browse_count": a["access"]["browse_count"],
            "can_read": a["access"]["can_read"],
            "can_history": a["access"]["can_history"],
            "executable_methods": a["access"]["executable_methods"],
            "can_write": a["access"]["can_write"],
            "hardening_issues": a["hardening_issues"],
        })

    # --- Determine worst-case access level across all accepted endpoints ---
    levels_order = {"none": 0, "minimal": 1, "moderate": 2, "elevated": 3}
    worst_level = max(accepted, key=lambda a: levels_order.get(a["access_level"], 0))["access_level"]

    # --- Determine hardening issues ---
    all_hardening = []
    for a in accepted:
        all_hardening.extend(a["hardening_issues"])

    creds_on_none = any(
        a["policy"] == "None" and a["mode"] == "None"
        for a in accepted
    )

    # --- Finding 1: Credentials accepted on insecure endpoint ---
    if creds_on_none:
        critical(f"Credentials for '{user}' accepted on SecurityPolicy None")
        tag("Cryptographic Failures")
        add_finding(
            report_data,
            "Credentials Accepted on Unencrypted Endpoint",
            "Critical",
            "Cryptographic Failures",
            f"User '{user}' credentials are accepted on an endpoint with SecurityPolicy None / "
            f"SecurityMode None. Credentials are transmitted in plaintext and can be intercepted "
            f"by any network-level attacker. This violates OPC UA Part 2 and Practical Security "
            f"Guidelines recommendations.",
            check="provided-creds",
            confidence="high",
            verification_status="confirmed-auth",
            safe_check=True,
            destructive=False,
            evidence=evidence,
        )

    # --- Finding 2: Elevated access ---
    if worst_level == "elevated":
        warn(f"User '{user}' has ELEVATED access level")
        add_observation(
            report_data,
            "Elevated Access Level Detected",
            "Broken Access Control",
            f"User '{user}' has elevated access: the server reports write-capable "
            f"UserAccessLevel and/or executable methods. Note: this is based on server-reported "
            f"attributes, not confirmed operations. Review whether this access level is "
            f"appropriate for the intended user role (IEC 62443 FR2).",
            check="provided-creds",
            confidence="medium",
            verification_status="confirmed-auth",
            safe_check=True,
            destructive=False,
            evidence=evidence,
        )

    # --- Finding 3: Hardening misconfigurations ---
    if all_hardening and not creds_on_none:
        unique_issues = list(dict.fromkeys(all_hardening))
        warn(f"{len(unique_issues)} hardening issue(s) detected")
        tag("Security Misconfiguration")
        add_finding(
            report_data,
            "Endpoint Hardening Issues for Authenticated Session",
            "Medium",
            "Security Misconfiguration",
            f"The authenticated session for user '{user}' uses endpoint configurations with "
            f"hardening weaknesses: {'; '.join(unique_issues[:5])}. "
            f"Review endpoint security policies per OPC UA Practical Security Guidelines.",
            check="provided-creds",
            confidence="high",
            verification_status="confirmed-auth",
            safe_check=True,
            destructive=False,
            evidence=evidence,
        )

    # --- Store the credential profile in report_data for other checks ---
    report_data.setdefault("credential_profiles", []).append({
        "user": user,
        "worst_access_level": worst_level,
        "accepted_count": len(accepted),
        "rejected_count": len(rejected),
        "creds_on_none": creds_on_none,
        "hardening_issues": list(dict.fromkeys(all_hardening)),
    })
