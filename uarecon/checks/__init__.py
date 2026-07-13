"""
UARecon Security Checks - organized into 10 assessment families.

Families:
    1. authentication_posture     - Identity and credential security
    2. endpoint_security_posture  - Transport/endpoint configuration
    3. certificate_posture        - PKI and certificate validation
    4. secure_channel_posture     - Channel quality, nonces, session binding
    5. authorization_posture      - Access control enforcement
    6. information_disclosure     - Data exposure and fingerprinting
    7. audit_posture              - Logging, diagnostics, time integrity
    8. availability_posture       - Resource limits and DoS surface
    9. deployment_posture         - Network topology and architecture leaks
   10. advisory_validation        - CVE matching (handled by cve.py module)

Each check is tagged as prod-safe or testing-only:
    - prod-safe: read-only, no state changes, no brute-force, no resource pressure
    - testing-only: active probes, write attempts, resource abuse, credential attacks
"""

import time

from .anonymous import check_anonymous_access
from .default_creds import check_default_credentials, DEFAULT_CREDENTIALS
from .bruteforce import check_bruteforce
from .lockout import check_account_lockout
from .provided_creds import check_provided_credentials
from .security_policies import check_security_policies
from .user_tokens import check_user_token_policies
from .server_cert import check_server_certificate
from .cert_hostname import check_certificate_hostname
from .cert_bypass import check_certificate_trust_bypass
from .app_uri import check_application_uri_consistency
from .nonce import check_nonce_quality
from .discovery import check_discovery_exposure
from .gds_discovery import check_gds_network_discovery
from .endpoint_url import check_endpoint_url_mismatch
from .audit import check_audit_config
from .diagnostics_consistency import check_diagnostics_consistency
from .session_limits import check_session_limits
from .session_timeout import check_session_timeout_policy
from .timestamp import check_timestamp_accuracy
from .writable_config import check_writable_server_config
from .max_limits import check_max_limits
from .max_response import check_max_response_message_size
from .history import check_history_read_access
from .browse_acl import check_browse_access_control
from .gds_trust import check_gds_trust_list
from .redundancy import check_redundancy_exposure
from .buildinfo import check_buildinfo_exposure
from .sensitive_data import check_sensitive_data_exposure
from .roles import check_role_permissions
from .namespaces import check_namespace_exposure
from .secure_channel import check_secure_channel_lifetime
from .view_access import check_view_access_control
from .access_restrictions import check_access_restrictions
from .method_access import check_method_access_control
from .node_write import check_node_write_access
from .sub_abuse import check_subscription_abuse
from .publish_flood import check_publish_rate_abuse
from .translate_dos import check_translate_dos
from .transfer_sub import check_transfer_subscription
from .max_connections import check_max_connections

# NOTE: check_bruteforce is intentionally NOT in CHECK_CATALOG.
# It requires external wordlists (--wordlist / --passlist) and is invoked
# separately via CLI flags. It is re-exported for direct use.

from ..banner import info, section


# ---------------------------------------------------------------------------
# Family constants
# ---------------------------------------------------------------------------
FAMILY_AUTHENTICATION = "authentication_posture"
FAMILY_ENDPOINT = "endpoint_security_posture"
FAMILY_CERTIFICATE = "certificate_posture"
FAMILY_CHANNEL = "secure_channel_posture"
FAMILY_AUTHORIZATION = "authorization_posture"
FAMILY_DISCLOSURE = "information_disclosure"
FAMILY_AUDIT = "audit_posture"
FAMILY_AVAILABILITY = "availability_posture"
FAMILY_DEPLOYMENT = "deployment_posture"
FAMILY_ADVISORY = "advisory_validation"

FAMILIES = [
    FAMILY_AUTHENTICATION,
    FAMILY_ENDPOINT,
    FAMILY_CERTIFICATE,
    FAMILY_CHANNEL,
    FAMILY_AUTHORIZATION,
    FAMILY_DISCLOSURE,
    FAMILY_AUDIT,
    FAMILY_AVAILABILITY,
    FAMILY_DEPLOYMENT,
    FAMILY_ADVISORY,
]

# ---------------------------------------------------------------------------
# Short aliases for CLI --family selection
# ---------------------------------------------------------------------------
FAMILY_ALIASES = {
    "auth":         FAMILY_AUTHENTICATION,
    "endpoint":     FAMILY_ENDPOINT,
    "cert":         FAMILY_CERTIFICATE,
    "channel":      FAMILY_CHANNEL,
    "authz":        FAMILY_AUTHORIZATION,
    "disclosure":   FAMILY_DISCLOSURE,
    "audit":        FAMILY_AUDIT,
    "availability": FAMILY_AVAILABILITY,
    "deployment":   FAMILY_DEPLOYMENT,
}

# Reverse map: full family name -> alias (for display)
FAMILY_ALIAS_REVERSE = {v: k for k, v in FAMILY_ALIASES.items()}

# ---------------------------------------------------------------------------
# CHECK_CATALOG
# Each entry: (slug, name, category, testing_only, scope, family)
#   - testing_only: True = skipped in --prod mode
#   - scope: "target" | "endpoints" | "client"
#   - family: one of the FAMILY_* constants
# ---------------------------------------------------------------------------
CHECK_CATALOG = [
    # --- Family 1: authentication_posture ---
    ("anonymous",        "Anonymous Access",                 "Broken Authentication",     False, "target",    FAMILY_AUTHENTICATION),
    ("user-tokens",      "User Token Policies",              "Cryptographic Failures",    False, "endpoints", FAMILY_AUTHENTICATION),
    ("default-creds",    "Default Credentials",              "Broken Authentication",     True,  "target",    FAMILY_AUTHENTICATION),
    ("provided-creds",   "Provided Credentials Assessment",  "Broken Authentication",     False, "target",    FAMILY_AUTHENTICATION),
    ("lockout",          "Account Lockout Detection",        "Broken Authentication",     True,  "target",    FAMILY_AUTHENTICATION),

    # --- Family 2: endpoint_security_posture ---
    ("security-policies","Security Policy Analysis",         "Cryptographic Failures",    False, "endpoints", FAMILY_ENDPOINT),
    ("endpoint-url",     "Endpoint URL Validation",          "Security Misconfiguration", False, "target",    FAMILY_ENDPOINT),
    ("discovery",        "Discovery Service Exposure",       "Information Disclosure",    False, "target",    FAMILY_ENDPOINT),

    # --- Family 3: certificate_posture ---
    ("server-cert",      "Server Certificate Analysis",      "Cryptographic Failures",    False, "target",    FAMILY_CERTIFICATE),
    ("cert-hostname",    "Certificate Hostname Validation",  "Cryptographic Failures",    False, "target",    FAMILY_CERTIFICATE),
    ("app-uri",          "ApplicationUri Consistency",       "Cryptographic Failures",    False, "target",    FAMILY_CERTIFICATE),
    ("gds-trust",        "GDS / Trust List Access",          "Broken Access Control",     False, "client",    FAMILY_CERTIFICATE),
    ("cert-bypass",      "Certificate Trust Bypass",         "Cryptographic Failures",    True,  "target",    FAMILY_CERTIFICATE),

    # --- Family 4: secure_channel_posture ---
    ("nonce",            "Server Nonce Quality",             "Cryptographic Failures",    False, "client",    FAMILY_CHANNEL),
    ("secure-channel",   "SecureChannel Token Lifetime",     "Cryptographic Failures",    False, "client",    FAMILY_CHANNEL),
    ("session-timeout",  "Session Timeout Policy",           "Security Misconfiguration", False, "client",    FAMILY_CHANNEL),
    ("session-limits",   "Session Limits",                   "Security Misconfiguration", False, "client",    FAMILY_CHANNEL),

    # --- Family 5: authorization_posture ---
    ("browse-acl",       "Browse Access Control",            "Broken Access Control",     False, "client",    FAMILY_AUTHORIZATION),
    ("roles",            "Role / Permission Model",          "Information Disclosure",    False, "client",    FAMILY_AUTHORIZATION),
    ("history",          "History Read Access",              "Information Disclosure",    False, "client",    FAMILY_AUTHORIZATION),
    ("view-access",      "View-Based Access Control",        "Security Misconfiguration", False, "client",    FAMILY_AUTHORIZATION),
    ("method-access",    "Method Access Control",            "Broken Access Control",     True,  "client",    FAMILY_AUTHORIZATION),
    ("node-write",       "Node Write Verification",          "Broken Access Control",     True,  "client",    FAMILY_AUTHORIZATION),
    ("writable-config",  "Server Config Write Access",       "Broken Access Control",     False, "client",    FAMILY_AUTHORIZATION),
    ("access-restrictions", "Access Restrictions Analysis",  "Security Misconfiguration", False, "client",    FAMILY_AUTHORIZATION),
    ("transfer-sub",     "Subscription Transfer Hijack",     "Broken Access Control",     True,  "client",    FAMILY_AUTHORIZATION),

    # --- Family 6: information_disclosure ---
    ("buildinfo",        "Build Information Exposure",       "Information Disclosure",    False, "client",    FAMILY_DISCLOSURE),
    ("namespaces",       "Namespace Exposure Analysis",      "Information Disclosure",    False, "client",    FAMILY_DISCLOSURE),
    ("redundancy",       "Redundancy Info Exposure",         "Information Disclosure",    False, "client",    FAMILY_DISCLOSURE),
    ("sensitive-data",   "Sensitive Data Exposure",          "Information Disclosure",    False, "client",    FAMILY_DISCLOSURE),

    # --- Family 7: audit_posture ---
    ("audit",            "Audit Configuration",              "Security Misconfiguration", False, "client",    FAMILY_AUDIT),
    ("timestamp",        "Timestamp Accuracy",               "Security Misconfiguration", False, "client",    FAMILY_AUDIT),
    ("diagnostics-consistency", "Diagnostics Consistency",   "Security Misconfiguration", False, "client",    FAMILY_AUDIT),

    # --- Family 8: availability_posture ---
    ("max-limits",       "Server Limits (DoS Surface)",      "Security Misconfiguration", False, "client",    FAMILY_AVAILABILITY),
    ("max-response",     "Response Size Amplification",      "Security Misconfiguration", False, "client",    FAMILY_AVAILABILITY),
    ("max-connections",  "Max Connections (DoS)",            "Security Misconfiguration", True,  "target",    FAMILY_AVAILABILITY),
    ("sub-abuse",        "Subscription Limits",              "Security Misconfiguration", True,  "client",    FAMILY_AVAILABILITY),
    ("publish-flood",    "Publish Rate Abuse",               "Security Misconfiguration", True,  "client",    FAMILY_AVAILABILITY),
    ("translate-dos",    "TranslateBrowsePaths DoS",         "Security Misconfiguration", True,  "client",    FAMILY_AVAILABILITY),

    # --- Family 9: deployment_posture ---
    ("gds-discovery",    "FindServersOnNetwork",             "Information Disclosure",    False, "target",    FAMILY_DEPLOYMENT),

    # --- Family 10: advisory_validation ---
    # CVE matching is handled by uarecon.cve module (not in this check flow).
    # BuildInfo exposure (family 6) provides the fingerprinting data for CVE matching.
]


# ---------------------------------------------------------------------------
# Pre-auth slugs: these checks run before authentication in the main flow
# and are dispatched separately by uarecon.py (not by run_security_checks).
# ---------------------------------------------------------------------------
PRE_AUTH_SLUGS = {"anonymous", "default-creds", "provided-creds"}


# ---------------------------------------------------------------------------
# Execution engine  (metadata-driven)
# ---------------------------------------------------------------------------

def run_security_checks(target, client, report_data, timeout=5, safe=False, delay=0, families=None):
    """
    Metadata-driven security check runner.

    Iterates CHECK_CATALOG and dispatches each check using its metadata:
        - family:       groups checks; prints a header when the family changes
        - testing_only: skipped when safe=True (--prod mode)
        - scope:        "target" (no auth needed), "endpoints" (needs
                        pre-enumerated endpoint data), "client" (needs an
                        authenticated OPC UA session)

    Pre-auth checks (anonymous, default-creds) are excluded here because
    they are dispatched separately before the authenticated session exists.

    Args:
        target:      OPC UA endpoint URL (opc.tcp://...)
        client:      Authenticated asyncua.sync.Client, or None
        report_data: Shared report dict
        timeout:     Per-operation timeout in seconds
        safe:        True = --prod mode, skip testing-only checks
        delay:       Seconds to wait between consecutive checks
        families:    Set of full family names to run (None = all families)
    """
    ran = []
    skipped_prod = []
    skipped_no_client = []
    skipped_family = []
    current_family = None
    first_in_run = True

    for slug, name, _cat, testing_only, scope, family in CHECK_CATALOG:
        # Pre-auth checks are dispatched by uarecon.py before connection
        if slug in PRE_AUTH_SLUGS:
            continue

        # ---- family filter ----
        if families and family not in families:
            skipped_family.append(slug)
            continue

        # ---- family header ----
        if family != current_family:
            current_family = family
            family_label = family.upper().replace("_", " ")
            section(f"FAMILY: {family_label}")

        # ---- prod gate ----
        if testing_only and safe:
            skipped_prod.append(slug)
            info(f"  [SKIP] {slug} (testing-only)")
            continue

        # ---- scope gate ----
        if scope == "client" and client is None:
            skipped_no_client.append(slug)
            continue

        # ---- inter-check delay ----
        if delay > 0 and not first_in_run:
            time.sleep(delay)

        # ---- dispatch ----
        mode_tag = "TEST" if testing_only else "PROD"
        info(f"  [{mode_tag}] {slug}")
        run_check_by_slug(slug, target, client, report_data, timeout)
        ran.append(slug)
        first_in_run = False

    # ---- runner summary ----
    prod_total = sum(1 for s, _, _, t, _, _ in CHECK_CATALOG
                     if not t and s not in PRE_AUTH_SLUGS)
    test_total = sum(1 for s, _, _, t, _, _ in CHECK_CATALOG
                     if t and s not in PRE_AUTH_SLUGS)

    section("RUNNER SUMMARY")
    mode_parts = []
    if safe:
        mode_parts.append("PROD (safe)")
    else:
        mode_parts.append("FULL (prod + testing)")
    if families:
        aliases = [FAMILY_ALIAS_REVERSE.get(f, f) for f in sorted(families)]
        mode_parts.append(f"families: {', '.join(aliases)}")
    info(f"Mode: {' | '.join(mode_parts)}")
    info(f"Executed: {len(ran)} check(s)")

    if skipped_family:
        info(f"Skipped (--family filter): {len(skipped_family)} check(s)")

    if skipped_prod:
        info(f"Skipped (--prod): {len(skipped_prod)} testing-only check(s)")
        for s in skipped_prod:
            info(f"  - {s}")

    if skipped_no_client:
        info(f"Skipped (no session): {len(skipped_no_client)} check(s)")
        for s in skipped_no_client:
            info(f"  - {s}")

    info(f"Catalog: {prod_total} prod-safe + {test_total} testing-only "
         f"(excl. {len(PRE_AUTH_SLUGS)} pre-auth)")


def run_check_by_slug(slug, target, client, report_data, timeout=5):
    """Run a single check by its slug identifier."""
    dispatch = {
        "anonymous":         lambda: check_anonymous_access(target, report_data, timeout),
        "default-creds":     lambda: check_default_credentials(target, report_data, timeout),
        "provided-creds":    lambda: check_provided_credentials(
            target,
            report_data.get("_user", ""),
            report_data.get("_password", ""),
            report_data,
            timeout,
        ),
        "security-policies": lambda: check_security_policies(report_data),
        "user-tokens":       lambda: check_user_token_policies(report_data),
        "server-cert":       lambda: check_server_certificate(target, report_data, timeout),
        "cert-hostname":     lambda: check_certificate_hostname(target, report_data, timeout),
        "app-uri":           lambda: check_application_uri_consistency(target, report_data, timeout),
        "cert-bypass":       lambda: check_certificate_trust_bypass(target, report_data, timeout),
        "nonce":             lambda: check_nonce_quality(target, client, report_data, timeout),
        "secure-channel":    lambda: check_secure_channel_lifetime(target, client, report_data, timeout),
        "discovery":         lambda: check_discovery_exposure(target, report_data, timeout),
        "gds-discovery":     lambda: check_gds_network_discovery(target, report_data, timeout),
        "endpoint-url":      lambda: check_endpoint_url_mismatch(target, report_data, timeout),
        "lockout":           lambda: check_account_lockout(target, report_data, timeout),
        "audit":             lambda: check_audit_config(client, report_data),
        "diagnostics-consistency": lambda: check_diagnostics_consistency(client, report_data),
        "session-limits":    lambda: check_session_limits(client, report_data),
        "session-timeout":   lambda: check_session_timeout_policy(client, report_data),
        "timestamp":         lambda: check_timestamp_accuracy(client, report_data),
        "writable-config":   lambda: check_writable_server_config(client, report_data),
        "max-limits":        lambda: check_max_limits(client, report_data),
        "max-response":      lambda: check_max_response_message_size(client, report_data),
        "history":           lambda: check_history_read_access(client, report_data),
        "browse-acl":        lambda: check_browse_access_control(client, report_data),
        "gds-trust":         lambda: check_gds_trust_list(client, report_data),
        "redundancy":        lambda: check_redundancy_exposure(client, report_data),
        "buildinfo":         lambda: check_buildinfo_exposure(client, report_data),
        "sensitive-data":    lambda: check_sensitive_data_exposure(client, report_data),
        "roles":             lambda: check_role_permissions(client, report_data),
        "namespaces":        lambda: check_namespace_exposure(client, report_data),
        "view-access":       lambda: check_view_access_control(client, report_data),
        "access-restrictions": lambda: check_access_restrictions(client, report_data),
        "method-access":     lambda: check_method_access_control(client, report_data),
        "node-write":        lambda: check_node_write_access(client, report_data),
        "sub-abuse":         lambda: check_subscription_abuse(client, report_data),
        "publish-flood":     lambda: check_publish_rate_abuse(client, report_data),
        "translate-dos":     lambda: check_translate_dos(client, report_data),
        "transfer-sub":      lambda: check_transfer_subscription(target, client, report_data, timeout),
        "max-connections":   lambda: check_max_connections(target, report_data, timeout),
    }

    fn = dispatch.get(slug)
    if fn:
        fn()
        return True
    return False
