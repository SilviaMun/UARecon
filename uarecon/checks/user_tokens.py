"""
User Token Policy Analysis.

Each UserTokenPolicy can specify its own SecurityPolicyUri. If present and non-None,
the token is encrypted independently of the endpoint's SecurityPolicy. If absent or
empty, the endpoint's SecurityPolicy is used for token encryption.

A UserName token on SecurityPolicy None WITHOUT a token-level SecurityPolicyUri is a
confirmed plaintext credential transmission. With a valid SecurityPolicyUri on the
token, it may still be protected.
"""

from ._base import add_finding, add_observation
from ..banner import bad, warn, good, info, section, tag


def check_user_token_policies(report_data):
    section("USER TOKEN POLICY ANALYSIS")
    endpoints = report_data.get("endpoints", [])
    if not endpoints:
        return

    confirmed_plaintext = []
    possible_plaintext = []
    issued_token_unprotected = []

    for ep in endpoints:
        policy = ep.get("policy", "")
        mode = ep.get("mode", "")
        tokens = ep.get("tokens", [])
        token_details = ep.get("token_details", [])

        # Only relevant for endpoints with no transport-level encryption
        if not (policy == "None" and mode == "None"):
            continue

        for i, tt in enumerate(tokens):
            # Get the per-token SecurityPolicyUri if available
            token_sec_policy = ""
            if token_details and i < len(token_details):
                token_sec_policy = token_details[i].get("security_policy_uri", "")

            # Determine if token-level encryption is in place
            has_token_encryption = (
                token_sec_policy
                and "None" not in token_sec_policy
                and "#" in token_sec_policy  # Valid policy URIs contain '#'
            )

            if tt == "UserName":
                entry = {
                    "url": ep.get("url"),
                    "policy": policy,
                    "mode": mode,
                    "token_security_policy": token_sec_policy or "(empty - inherits endpoint)",
                }
                if has_token_encryption:
                    # Token has its own encryption - not plaintext
                    info(
                        f"UserName token on None endpoint has token-level protection: "
                        f"{token_sec_policy}"
                    )
                else:
                    # No token-level encryption AND no endpoint encryption = plaintext
                    if not token_sec_policy or token_sec_policy.endswith("#None"):
                        confirmed_plaintext.append(entry)
                    else:
                        possible_plaintext.append(entry)

            elif tt == "IssuedToken":
                if not has_token_encryption:
                    issued_token_unprotected.append({
                        "url": ep.get("url"),
                        "policy": policy,
                        "mode": mode,
                        "token_security_policy": token_sec_policy or "(empty - inherits endpoint)",
                    })

    if confirmed_plaintext:
        bad("CONFIRMED plaintext username/password transport")
        tag("Cryptographic Failures")
        add_finding(
            report_data,
            "Plaintext Password Transmission",
            "Critical",
            "Cryptographic Failures",
            "At least one endpoint accepts UserName authentication over SecurityPolicy None "
            "with no token-level SecurityPolicyUri. Credentials are transmitted in plaintext. "
            "Credentials are transmitted in plaintext, violating token encryption requirements.",
            check="user-tokens",
            confidence="high",
            verification_status="confirmed-read",
            safe_check=True,
            destructive=False,
            evidence={"confirmed_plaintext_endpoints": confirmed_plaintext},
        )
    elif possible_plaintext:
        warn("Potential plaintext username/password transport (unrecognized token policy)")
        tag("Cryptographic Failures")
        add_finding(
            report_data,
            "Potential Plaintext Password Transmission",
            "High",
            "Cryptographic Failures",
            "At least one endpoint accepts UserName authentication over SecurityPolicy None. "
            "The token-level SecurityPolicyUri could not be confirmed as providing encryption. "
            "Manual verification is recommended.",
            check="user-tokens",
            confidence="medium",
            verification_status="endpoint-analysis",
            safe_check=True,
            destructive=False,
            evidence={"possible_plaintext_endpoints": possible_plaintext},
        )
    else:
        good("No plaintext password transport detected")

    if issued_token_unprotected:
        warn("IssuedToken (SAML/JWT) available on unencrypted endpoint without token-level protection")
        tag("Cryptographic Failures")
        add_finding(
            report_data,
            "IssuedToken Over Unencrypted Endpoint",
            "High",
            "Cryptographic Failures",
            "At least one endpoint accepts IssuedToken (SAML/JWT/Kerberos) over SecurityPolicy None "
            "without token-level SecurityPolicyUri. Bearer tokens transmitted without any encryption "
            "can be intercepted and replayed.",
            check="user-tokens",
            confidence="high",
            verification_status="endpoint-analysis",
            safe_check=True,
            destructive=False,
            evidence={"affected_endpoints": issued_token_unprotected},
        )

    # --- Additional check: Certificate tokens without encryption ---
    cert_token_unprotected = []
    for ep in endpoints:
        policy = ep.get("policy", "")
        mode = ep.get("mode", "")
        tokens = ep.get("tokens", [])
        token_details = ep.get("token_details", [])

        if not (policy == "None" and mode == "None"):
            continue

        for i, tt in enumerate(tokens):
            if tt == "Certificate":
                token_sec_policy = ""
                if token_details and i < len(token_details):
                    token_sec_policy = token_details[i].get("security_policy_uri", "")
                has_token_encryption = (
                    token_sec_policy
                    and "None" not in token_sec_policy
                    and "#" in token_sec_policy
                )
                if not has_token_encryption:
                    cert_token_unprotected.append({
                        "url": ep.get("url"),
                        "token_security_policy": token_sec_policy or "(empty)",
                    })

    if cert_token_unprotected:
        warn("X509 certificate token offered on unencrypted endpoint")
        add_observation(
            report_data,
            "Certificate Token on Unencrypted Endpoint",
            "Cryptographic Failures",
            "X509 certificate authentication is offered on an endpoint with SecurityPolicy None. "
            "While the certificate itself is not a secret, the authentication exchange without "
            "encryption allows an attacker to observe which certificate identities are used.",
            check="user-tokens",
            confidence="medium",
            verification_status="endpoint-analysis",
            safe_check=True,
            destructive=False,
            evidence={"affected_endpoints": cert_token_unprotected},
        )
