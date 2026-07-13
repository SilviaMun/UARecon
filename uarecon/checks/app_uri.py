"""
ApplicationUri Consistency Check.

Verifies that the server's declared ApplicationUri matches the URI in the
certificate's SubjectAlternativeName.  If they diverge, clients cannot
reliably authenticate the server's identity, enabling rogue-server attacks.

Prod-safe, read-only (endpoint analysis only).
"""

from asyncua.sync import Client

from ._base import add_finding, add_observation
from ..banner import bad, warn, good, info, section, tag
from ..helpers import safe_disconnect


def check_application_uri_consistency(target, report_data, timeout=5):
    section("APPLICATION URI CONSISTENCY")
    tmp = None
    try:
        tmp = Client(target, timeout=timeout)
        endpoints = tmp.connect_and_get_server_endpoints()
    except Exception as e:
        warn(f"Could not retrieve endpoints for ApplicationUri check: {e}")
        return
    finally:
        safe_disconnect(tmp)

    if not endpoints:
        info("No endpoints available")
        return

    # Collect ApplicationUri from the endpoint descriptions
    app_uris = set()
    for ep in endpoints:
        try:
            uri = str(ep.Server.ApplicationUri or "")
            if uri:
                app_uris.add(uri)
        except Exception:
            pass

    if not app_uris:
        warn("No ApplicationUri found in endpoint descriptions")
        return

    info(f"Declared ApplicationUri(s): {', '.join(sorted(app_uris))}")

    # Parse each unique certificate and extract SAN URIs
    checked = set()
    cert_uris = set()
    parse_failed = False

    for ep in endpoints:
        cert_bytes = getattr(ep, "ServerCertificate", None)
        if not cert_bytes or bytes(cert_bytes) in checked:
            continue
        checked.add(bytes(cert_bytes))

        try:
            from cryptography import x509

            cert = x509.load_der_x509_certificate(bytes(cert_bytes))
            try:
                san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                uris = san.value.get_values_for_type(x509.UniformResourceIdentifier)
                for uri in uris:
                    cert_uris.add(uri)
            except x509.ExtensionNotFound:
                pass
        except ImportError:
            warn("cryptography library not available for URI check")
            return
        except Exception:
            parse_failed = True

    if parse_failed and not cert_uris:
        warn("Could not parse certificate to extract SAN URIs")
        return

    if not cert_uris:
        warn("No URI found in certificate SAN extension")
        add_observation(
            report_data,
            "No ApplicationUri in Certificate SAN",
            "Cryptographic Failures",
            "Server certificate does not contain a URI in the SubjectAlternativeName. "
            "The ApplicationUri is required to be in the SAN for identity binding. "
            "Clients cannot verify server identity.",
            check="app-uri",
            confidence="high",
            verification_status="confirmed-read",
            safe_check=True,
            destructive=False,
            evidence={
                "declared_app_uris": sorted(app_uris),
                "cert_san_uris": [],
            },
        )
        return

    info(f"Certificate SAN URI(s): {', '.join(sorted(cert_uris))}")

    # Check if any declared ApplicationUri matches any cert SAN URI
    matching = app_uris & cert_uris
    mismatched_app = app_uris - cert_uris

    if matching:
        good(f"ApplicationUri matches certificate SAN: {', '.join(sorted(matching))}")

    if mismatched_app:
        bad(f"ApplicationUri NOT in certificate SAN: {', '.join(sorted(mismatched_app))}")
        tag("Cryptographic Failures")
        add_finding(
            report_data,
            "ApplicationUri Does Not Match Certificate",
            "High",
            "Cryptographic Failures",
            f"Server declares ApplicationUri {', '.join(sorted(mismatched_app))} in its "
            f"ApplicationDescription but the certificate SAN only contains "
            f"{', '.join(sorted(cert_uris))}. The ApplicationUri must be in the certificate SAN "
            f"for identity binding. This mismatch means clients cannot reliably authenticate "
            f"the server, enabling rogue-server attacks.",
            check="app-uri",
            confidence="high",
            verification_status="confirmed-read",
            safe_check=True,
            destructive=False,
            evidence={
                "declared_app_uris": sorted(app_uris),
                "cert_san_uris": sorted(cert_uris),
                "mismatched": sorted(mismatched_app),
            },
        )
    elif not matching and cert_uris:
        # No app_uris match, but we do have cert URIs
        bad(f"ApplicationUri mismatch: declared={sorted(app_uris)}, cert={sorted(cert_uris)}")
        tag("Cryptographic Failures")
        add_finding(
            report_data,
            "ApplicationUri Does Not Match Certificate",
            "High",
            "Cryptographic Failures",
            f"Server declares ApplicationUri(s) {', '.join(sorted(app_uris))} but certificate "
            f"SAN contains different URI(s) {', '.join(sorted(cert_uris))}. "
            f"This violates OPC UA identity binding requirements.",
            check="app-uri",
            confidence="high",
            verification_status="confirmed-read",
            safe_check=True,
            destructive=False,
            evidence={
                "declared_app_uris": sorted(app_uris),
                "cert_san_uris": sorted(cert_uris),
            },
        )
