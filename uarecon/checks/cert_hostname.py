from urllib.parse import urlparse

from asyncua.sync import Client

from ._base import add_observation
from ..banner import warn, good, info, section
from ..helpers import safe_disconnect, classify_error


def check_certificate_hostname(target, report_data, timeout=5):
    section("CERTIFICATE HOSTNAME VALIDATION")
    tmp = None
    try:
        tmp = Client(target, timeout=timeout)
        endpoints = tmp.connect_and_get_server_endpoints()

        target_parsed = urlparse(target)
        target_host = (target_parsed.hostname or "").lower()

        endpoint_hosts = set()
        for ep in endpoints:
            ep_url = str(getattr(ep, "EndpointUrl", "") or "")
            try:
                ep_host = (urlparse(ep_url).hostname or "").lower()
                if ep_host:
                    endpoint_hosts.add(ep_host)
            except Exception:
                pass

        checked = set()
        for ep in endpoints:
            cert_bytes = getattr(ep, "ServerCertificate", None)
            if not cert_bytes or bytes(cert_bytes) in checked:
                continue
            checked.add(bytes(cert_bytes))

            try:
                from cryptography import x509

                cert = x509.load_der_x509_certificate(bytes(cert_bytes))
                cert_hosts = set()

                try:
                    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    for dns in san.value.get_values_for_type(x509.DNSName):
                        cert_hosts.add(dns.lower())
                    for ip in san.value.get_values_for_type(x509.IPAddress):
                        cert_hosts.add(str(ip))
                except x509.ExtensionNotFound:
                    pass

                if not cert_hosts:
                    for attr in cert.subject:
                        if attr.oid == x509.oid.NameOID.COMMON_NAME:
                            cert_hosts.add(attr.value.lower())

                if not cert_hosts:
                    good("Certificate uses Application URI only (standard OPC UA practice)")
                    break

                info(f"Certificate names: {', '.join(sorted(cert_hosts))}")

                if target_host and target_host in cert_hosts:
                    good(f"Certificate covers target host ({target_host})")
                    break

                if endpoint_hosts and any(h in cert_hosts for h in endpoint_hosts):
                    info(
                        f"Certificate matches advertised endpoint hostname(s) ({', '.join(sorted(endpoint_hosts))}), "
                        f"while the scan used {target_host}. This is common when accessing the server via VPN, NAT, or IP."
                    )
                    break

                warn(
                    f"Certificate name mismatch: cert covers {', '.join(sorted(cert_hosts))}, "
                    f"target is {target_host}, advertised endpoint host(s): {', '.join(sorted(endpoint_hosts)) or 'n/a'}"
                )
                add_observation(
                    report_data,
                    "Certificate Name Does Not Match Access Path",
                    "Cryptographic Failures",
                    f"Server certificate names ({', '.join(sorted(cert_hosts))}) do not match the target host ({target_host}) "
                    f"or the advertised endpoint hostnames ({', '.join(sorted(endpoint_hosts)) or 'n/a'}). "
                    f"In OPC UA this may still be benign depending on Application URI validation and deployment topology, "
                    f"but it should be reviewed.",
                    check="cert-hostname",
                    confidence="low",
                    verification_status="endpoint-analysis",
                    safe_check=True,
                    destructive=False,
                    evidence={
                        "cert_hosts": sorted(cert_hosts),
                        "target_host": target_host,
                        "endpoint_hosts": sorted(endpoint_hosts),
                    },
                )
                break

            except ImportError:
                warn("cryptography library not available")
                break
            except Exception as e:
                warn(f"Certificate hostname check failed: {e}")

    except Exception as e:
        info(f"Could not check certificate hostname: {classify_error(e)}")
    finally:
        safe_disconnect(tmp)
