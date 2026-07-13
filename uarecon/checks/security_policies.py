"""
Security Policy Analysis.
BSI TR-03116-3: Cryptographic requirements for OPC UA.
OPC Foundation Security Bulletin (2022): Deprecation of Basic128Rsa15.

Policy classification:
    INSECURE:   SecurityPolicy None (no protection)
    DEPRECATED: Basic128Rsa15 (uses SHA-1, small symmetric keys, deprecated since OPC UA 1.04)
    LEGACY:     Basic256 (uses SHA-1 for asymmetric signatures)
    ACCEPTABLE: Basic256Sha256 (minimum modern, SHA-256 throughout)
    STRONG:     Aes128_Sha256_RsaOaep, Aes256_Sha256_RsaPss (current best practice)

Mode classification:
    None:           No security at all (only valid with SecurityPolicy None)
    Sign:           Integrity-only (no confidentiality - data readable on the wire)
    SignAndEncrypt:  Full protection (integrity + confidentiality)
"""

from ._base import add_finding, add_observation
from ..banner import bad, warn, good, info, section, tag


# Known policies and their security classification
POLICY_CLASSIFICATION = {
    "None":                 "insecure",
    "Basic128Rsa15":        "deprecated",
    "Basic256":             "legacy",
    "Basic256Sha256":       "acceptable",
    "Aes128Sha256RsaOaep":  "strong",
    "Aes256Sha256RsaPss":   "strong",
}


def _classify_policy(policy):
    """Classify a policy as insecure/deprecated/legacy/acceptable/strong/unknown."""
    return POLICY_CLASSIFICATION.get(policy, "unknown")


def check_security_policies(report_data):
    section("SECURITY POLICY ANALYSIS")
    endpoints = report_data.get("endpoints", [])
    if not endpoints:
        info("No endpoints to analyze (run endpoint enumeration first)")
        return

    has_none = False
    deprecated_policies = set()
    legacy_policies = set()
    unknown_policies = set()
    sign_only_policies = set()
    has_strong = False
    has_acceptable = False

    for ep in endpoints:
        policy = ep.get("policy", "")
        mode = ep.get("mode", "")
        classification = _classify_policy(policy)

        if classification == "insecure":
            has_none = True

        elif classification == "deprecated":
            deprecated_policies.add(policy)
            bad(f"DEPRECATED POLICY: {ep['url']} | {mode} | {policy}")
            tag("Cryptographic Failures")

        elif classification == "legacy":
            legacy_policies.add(policy)
            warn(f"LEGACY POLICY: {ep['url']} | {mode} | {policy}")
            tag("Cryptographic Failures")

        elif classification == "unknown":
            # Unknown policy - could be custom/vendor-specific or very old
            unknown_policies.add(policy)
            warn(f"UNKNOWN POLICY: {ep['url']} | {mode} | {policy}")
            tag("Cryptographic Failures")

        elif classification == "strong":
            if mode == "SignAndEncrypt":
                has_strong = True
            elif mode == "Sign":
                sign_only_policies.add(policy)
                warn(f"SIGN-ONLY (no encryption): {ep['url']} | {policy}")
                tag("Cryptographic Failures")

        elif classification == "acceptable":
            if mode == "SignAndEncrypt":
                has_acceptable = True
            elif mode == "Sign":
                sign_only_policies.add(policy)
                warn(f"SIGN-ONLY (no encryption): {ep['url']} | {policy}")
                tag("Cryptographic Failures")

    # --- Findings ---

    if has_none:
        bad("SecurityPolicy None is available")
        tag("Cryptographic Failures")
        add_finding(
            report_data,
            "SecurityPolicy None Available",
            "Medium",
            "Cryptographic Failures",
            "Server advertises at least one endpoint with SecurityPolicy None (no security). "
            "Communication on this endpoint is unencrypted and unauthenticated at the transport level. "
            "Many OPC UA servers advertise None for endpoint discovery, but it should be disabled "
            "when not required. Actual impact depends on whether credentials or data are transmitted "
            "over this endpoint (see anonymous, user-tokens, provided-creds checks).",
            check="security-policies",
            confidence="high",
            verification_status="endpoint-analysis",
            safe_check=True,
            destructive=False,
            evidence={"has_none": True},
        )

    if deprecated_policies:
        add_finding(
            report_data,
            f"Deprecated Security Policy: {', '.join(sorted(deprecated_policies))}",
            "High",
            "Cryptographic Failures",
            f"Server offers deprecated policies: {', '.join(sorted(deprecated_policies))}. "
            f"Basic128Rsa15 was deprecated by OPC Foundation in 2022 due to use of SHA-1 and "
            f"inadequate symmetric key length (128-bit). It MUST be disabled per BSI TR-03116-3.",
            check="security-policies",
            confidence="high",
            verification_status="endpoint-analysis",
            safe_check=True,
            destructive=False,
            evidence={"deprecated_policies": sorted(deprecated_policies)},
        )

    if legacy_policies:
        add_finding(
            report_data,
            f"Legacy Security Policy: {', '.join(sorted(legacy_policies))}",
            "Medium",
            "Cryptographic Failures",
            f"Server offers legacy policy {', '.join(sorted(legacy_policies))}. "
            f"Basic256 uses SHA-1 for asymmetric signatures which is vulnerable to collision attacks. "
            f"Upgrade to Basic256Sha256 or newer. Acceptable only if no clients require it.",
            check="security-policies",
            confidence="high",
            verification_status="endpoint-analysis",
            safe_check=True,
            destructive=False,
            evidence={"legacy_policies": sorted(legacy_policies)},
        )

    if unknown_policies:
        add_finding(
            report_data,
            f"Unknown Security Policy: {', '.join(sorted(unknown_policies))}",
            "Medium",
            "Cryptographic Failures",
            f"Server offers unrecognized security policies: {', '.join(sorted(unknown_policies))}. "
            f"These are not part of the standard OPC UA security policy set and their cryptographic "
            f"properties cannot be verified. They may be vendor-specific, obsolete, or misconfigured.",
            check="security-policies",
            confidence="medium",
            verification_status="endpoint-analysis",
            safe_check=True,
            destructive=False,
            evidence={"unknown_policies": sorted(unknown_policies)},
        )

    if sign_only_policies:
        add_finding(
            report_data,
            "Sign-Only Mode Available (No Encryption)",
            "Medium",
            "Cryptographic Failures",
            f"Endpoints with Sign-only mode (no encryption) are available for: "
            f"{', '.join(sorted(sign_only_policies))}. "
            f"Message integrity is protected but data confidentiality is NOT. "
            f"Process values, credentials, and operational data are readable on the network. "
            f"SignAndEncrypt should be mandatory for secure deployments.",
            check="security-policies",
            confidence="high",
            verification_status="endpoint-analysis",
            safe_check=True,
            destructive=False,
            evidence={"sign_only_policies": sorted(sign_only_policies)},
        )

    # --- Summary ---

    if has_strong:
        good("At least one strong endpoint available (SignAndEncrypt with modern policy)")
    elif has_acceptable:
        good("At least one acceptable endpoint available (Basic256Sha256 + SignAndEncrypt)")
    elif not has_none:
        warn("No strong SignAndEncrypt endpoints with modern policies found")

    # --- Downgrade Path Detection ---
    has_good = has_strong or has_acceptable
    has_weak = has_none or deprecated_policies or legacy_policies or sign_only_policies or unknown_policies

    if has_good and has_weak:
        weak_options = []
        if has_none:
            weak_options.append("SecurityPolicy None")
        if deprecated_policies:
            weak_options.extend(sorted(deprecated_policies))
        if legacy_policies:
            weak_options.extend(sorted(legacy_policies))
        if unknown_policies:
            weak_options.extend(sorted(unknown_policies))
        if sign_only_policies:
            weak_options.append("Sign-only mode")

        warn(f"WEAKER MODES: strong endpoints coexist with: {', '.join(weak_options)}")
        tag("Cryptographic Failures")
        add_finding(
            report_data,
            "Weaker Security Modes Coexist with Strong Endpoints",
            "Medium",
            "Cryptographic Failures",
            f"Server offers strong endpoints (SignAndEncrypt with modern policies) alongside "
            f"weaker options ({', '.join(weak_options)}). This increases downgrade risk if "
            f"endpoint selection is not strictly enforced by clients — a network-level attacker "
            f"could manipulate the GetEndpoints response to suppress strong options. "
            f"Best practice recommends removing weaker endpoints "
            f"when strong alternatives are available.",
            check="security-policies",
            confidence="high",
            verification_status="endpoint-analysis",
            safe_check=True,
            destructive=False,
            evidence={
                "has_strong": has_strong,
                "has_acceptable": has_acceptable,
                "weak_options": weak_options,
            },
        )

    anon_endpoints = [ep for ep in endpoints if "Anonymous" in ep.get("tokens", [])]
    if anon_endpoints:
        info(
            f"Anonymous token advertised on {len(anon_endpoints)}/{len(endpoints)} endpoint(s) "
            "(actual access must be confirmed separately)"
        )
    else:
        good("No endpoints advertise anonymous tokens")
