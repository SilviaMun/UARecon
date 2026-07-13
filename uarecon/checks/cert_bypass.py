from asyncua.sync import Client

from ._base import add_finding
from ..banner import bad, warn, good, info, section, tag
from ..helpers import (
    safe_disconnect, classify_error,
    generate_expired_cert, generate_wrong_uri_cert,
    cleanup_temp_artifacts,
)


def _try_cert_connect(target, cert, key, uri, policy, mode, timeout):
    client = None
    try:
        client = Client(target, timeout=timeout)
        client.application_uri = uri
        client.set_security_string(f"{policy},{mode},{cert},{key}")
        client.connect()
        safe_disconnect(client)
        return True
    except Exception as e:
        safe_disconnect(client)
        return classify_error(e)


def check_certificate_trust_bypass(target, report_data, timeout=5):
    section("CERTIFICATE TRUST BYPASS")
    from ..connection import get_endpoint_combinations

    endpoint_combos = get_endpoint_combinations(target, timeout=timeout)
    secure = [(p, m) for p, m in endpoint_combos if p != "None" and m != "None"]
    if not secure:
        info("No secure endpoints to test certificate bypass against")
        return

    pol, mod = secure[0]

    info("Testing expired certificate acceptance...")
    exp_cert, exp_key, exp_cnf, exp_dir, exp_tmp = generate_expired_cert(
        uri="urn:UARecon", out_dir=None
    )
    if exp_cert:
        result = _try_cert_connect(target, exp_cert, exp_key, "urn:UARecon", pol, mod, timeout)
        cleanup_temp_artifacts(exp_cert, exp_key, exp_cnf, exp_dir, remove_dir=exp_tmp)

        result_str = str(result).lower()
        if result is True:
            bad(f"EXPIRED CERTIFICATE ACCEPTED ({pol}/{mod})")
            tag("Cryptographic Failures")
            add_finding(
                report_data,
                "Expired Client Certificate Accepted",
                "High",
                "Cryptographic Failures",
                f"Server accepted an expired client certificate on {pol}/{mod}. "
                f"Certificate validity period does not appear to be enforced.",
                check="cert-bypass",
                confidence="high",
                verification_status="confirmed-auth-bypass",
                safe_check=False,
                destructive=False,
                evidence={"policy": pol, "mode": mod, "test": "expired-cert"},
            )
        elif "badcertificatetimeinvalid" in result_str:
            good(f"Expired certificate rejected ({result})")
        elif "badcertificateuntrusted" in result_str:
            info("Expired certificate test inconclusive: untrusted certificate was rejected before validity could be assessed")
        else:
            info(f"Expired cert result: {result}")
    else:
        warn("Could not generate expired certificate")

    info("Testing wrong Application URI certificate acceptance...")
    wu_cert, wu_key, wu_cnf, wu_dir, wu_tmp = generate_wrong_uri_cert(out_dir=None)
    if wu_cert:
        result = _try_cert_connect(target, wu_cert, wu_key, "urn:FAKE:InvalidApplication:NotReal", pol, mod, timeout)
        cleanup_temp_artifacts(wu_cert, wu_key, wu_cnf, wu_dir, remove_dir=wu_tmp)

        result_str = str(result).lower()
        if result is True:
            bad(f"WRONG URI CERTIFICATE ACCEPTED ({pol}/{mod})")
            tag("Cryptographic Failures")
            add_finding(
                report_data,
                "Wrong URI Client Certificate Accepted",
                "High",
                "Cryptographic Failures",
                f"Server accepted a certificate with a mismatched Application URI on {pol}/{mod}. "
                f"Application identity validation does not appear to be enforced.",
                check="cert-bypass",
                confidence="high",
                verification_status="confirmed-auth-bypass",
                safe_check=False,
                destructive=False,
                evidence={"policy": pol, "mode": mod, "test": "wrong-uri-cert"},
            )
        elif "badcertificateuriinvalid" in result_str:
            good(f"Wrong URI certificate rejected ({result})")
        elif "badcertificateuntrusted" in result_str:
            info("Wrong URI test inconclusive: untrusted certificate was rejected before URI validation could be assessed")
        else:
            info(f"Wrong URI cert result: {result}")
    else:
        warn("Could not generate wrong-URI certificate")
