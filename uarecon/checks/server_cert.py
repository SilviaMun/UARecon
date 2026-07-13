import datetime

from asyncua.sync import Client

from ._base import add_finding, add_observation
from ..banner import bad, warn, good, info, section, tag
from ..helpers import safe_disconnect


def check_server_certificate(target, report_data, timeout=5):
    section("SERVER CERTIFICATE ANALYSIS")
    tmp = None
    try:
        tmp = Client(target, timeout=timeout)
        endpoints = tmp.connect_and_get_server_endpoints()
    except Exception as e:
        warn(f"Could not retrieve endpoints for cert analysis: {e}")
        return
    finally:
        safe_disconnect(tmp)

    checked = set()
    for ep in endpoints:
        cert_bytes = getattr(ep, "ServerCertificate", None)
        if not cert_bytes or bytes(cert_bytes) in checked:
            continue
        checked.add(bytes(cert_bytes))

        try:
            from cryptography import x509
            from cryptography.hazmat.primitives.asymmetric import rsa, ec

            cert = x509.load_der_x509_certificate(bytes(cert_bytes))
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            not_after = cert.not_valid_after_utc
            now = datetime.datetime.now(datetime.timezone.utc)

            info(f"Subject: {subject}")
            info(f"Issuer: {issuer}")
            info(f"Valid until: {not_after}")

            if subject == issuer:
                info("Server certificate is self-signed (common in OPC UA deployments)")
                add_observation(
                    report_data,
                    "Self-Signed Server Certificate",
                    "Cryptographic Failures",
                    f"Server uses a self-signed certificate ({subject}). "
                    f"This is common in OPC UA and does not necessarily indicate a vulnerability.",
                    check="server-cert",
                    confidence="high",
                    verification_status="confirmed-read",
                    safe_check=True,
                    destructive=False,
                    evidence={"subject": subject, "issuer": issuer},
                )

            if not_after < now:
                bad(f"Server certificate EXPIRED on {not_after}")
                tag("Cryptographic Failures")
                add_finding(
                    report_data,
                    "Expired Server Certificate",
                    "High",
                    "Cryptographic Failures",
                    f"Server certificate expired on {not_after}. Clients may skip validation to connect.",
                    check="server-cert",
                    confidence="high",
                    verification_status="confirmed-read",
                    safe_check=True,
                    destructive=False,
                    evidence={"not_after": str(not_after)},
                )
            else:
                days_left = (not_after - now).days
                if days_left < 30:
                    warn(f"Certificate expires in {days_left} days")
                else:
                    good(f"Certificate valid for {days_left} more days")

            pub_key = cert.public_key()
            if isinstance(pub_key, rsa.RSAPublicKey):
                key_size = pub_key.key_size
                info(f"Key: RSA {key_size}-bit")
                if key_size < 2048:
                    bad(f"WEAK RSA KEY: {key_size}-bit (minimum 2048 recommended)")
                    tag("Cryptographic Failures")
                    add_finding(
                        report_data,
                        "Weak Server Certificate Key",
                        "High",
                        "Cryptographic Failures",
                        f"Server certificate uses {key_size}-bit RSA. Keys < 2048 bits are weak by modern standards.",
                        check="server-cert",
                        confidence="high",
                        verification_status="confirmed-read",
                        safe_check=True,
                        destructive=False,
                        evidence={"rsa_key_bits": key_size},
                    )
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                key_size = pub_key.key_size
                info(f"Key: EC {key_size}-bit")
                if key_size < 256:
                    warn(f"Weak EC key: {key_size}-bit")

            try:
                from cryptography import x509 as x509_mod
                san = cert.extensions.get_extension_for_class(x509_mod.SubjectAlternativeName)
                uris = san.value.get_values_for_type(x509_mod.UniformResourceIdentifier)
                for uri in uris:
                    info(f"SAN URI: {uri}")
            except x509.ExtensionNotFound:
                warn("No SubjectAlternativeName extension (some clients may reject)")

        except ImportError:
            warn("cryptography library not available for cert analysis")
        except Exception as e:
            warn(f"Certificate parsing failed: {e}")
