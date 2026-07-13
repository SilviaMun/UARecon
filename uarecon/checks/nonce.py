from asyncua.sync import Client

from ._base import add_finding, add_observation
from ..banner import critical, bad, warn, good, info, section, tag
from ..helpers import safe_disconnect


def check_nonce_quality(target, client, report_data, timeout=5):
    section("SERVER NONCE ANALYSIS")
    nonces = []

    for src_label, src in [("current session", client), ("new session", None)]:
        try:
            if src is None:
                src = Client(target, timeout=timeout)
                src.connect()

            nonce = None
            aio = getattr(src, "aio_obj", None)
            if aio:
                nonce = getattr(aio, "_server_nonce", None)
            if nonce is None:
                uac = getattr(src, "uaclient", None)
                if uac:
                    inner = getattr(uac, "aio_obj", None)
                    if inner:
                        nonce = getattr(inner, "_server_nonce", None)

            if nonce:
                nonces.append(bytes(nonce))
                info(f"Nonce from {src_label}: {len(nonce)} bytes")

            if src is not client:
                safe_disconnect(src)
        except Exception:
            if src is not None and src is not client:
                safe_disconnect(src)

    if not nonces:
        warn("Could not extract server nonces for analysis")
        return

    for nonce in nonces:
        if len(nonce) < 32:
            bad(f"SHORT NONCE: {len(nonce)} bytes (minimum 32 expected)")
            tag("Cryptographic Failures")
            add_finding(
                report_data,
                "Weak Server Nonce (Short Length)",
                "High",
                "Cryptographic Failures",
                f"Server nonce is only {len(nonce)} bytes. Short nonces reduce replay resistance.",
                check="nonce",
                confidence="high",
                verification_status="confirmed-read",
                safe_check=True,
                destructive=False,
                evidence={"nonce_length": len(nonce)},
            )
            return

    for nonce in nonces:
        if len(set(nonce)) <= 2:
            bad(f"LOW ENTROPY NONCE: only {len(set(nonce))} unique byte value(s)")
            tag("Cryptographic Failures")
            add_finding(
                report_data,
                "Low Entropy Server Nonce",
                "Critical",
                "Cryptographic Failures",
                f"Server nonce has extremely low entropy ({len(set(nonce))} unique byte values). "
                f"This strongly suggests broken randomness.",
                check="nonce",
                confidence="high",
                verification_status="confirmed-read",
                safe_check=True,
                destructive=False,
                evidence={"unique_bytes": len(set(nonce)), "nonce_length": len(nonce)},
            )
            return

    if len(nonces) >= 2:
        if nonces[0] == nonces[1]:
            critical("SERVER NONCE REUSED across sessions")
            tag("Cryptographic Failures")
            add_finding(
                report_data,
                "Server Nonce Reuse",
                "Critical",
                "Cryptographic Failures",
                "Server returned identical nonces in separate sessions. This breaks replay protection.",
                check="nonce",
                confidence="high",
                verification_status="confirmed-read",
                safe_check=True,
                destructive=False,
                evidence={"sampled_nonces": 2, "reuse": True},
            )
        elif nonces[0][:8] == nonces[1][:8]:
            warn("Nonce prefix collision observed across two sessions")
            add_observation(
                report_data,
                "Potentially Predictable Server Nonce",
                "Cryptographic Failures",
                "Two sampled nonces shared the same 8-byte prefix. This is suspicious but does not by itself prove predictability.",
                check="nonce",
                confidence="low",
                verification_status="weak-signal",
                safe_check=True,
                destructive=False,
                evidence={"prefix_bytes_equal": 8, "sampled_nonces": 2},
            )
        else:
            good(f"Server nonces appear distinct ({len(nonces[0])} bytes each)")
    else:
        nonce = nonces[0]
        good(f"Nonce length OK ({len(nonce)} bytes), entropy appears reasonable ({len(set(nonce))} unique byte values)")
