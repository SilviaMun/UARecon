from asyncua.sync import Client

from ._base import emit
from ..banner import bad, warn, good, info, section, tag
from ..helpers import safe_disconnect, classify_error


def check_secure_channel_lifetime(target, client, report_data, timeout=5):
    section("SECURE CHANNEL TOKEN LIFETIME")

    revised_lifetime = None
    try:
        aio = getattr(client, "aio_obj", None)
        if aio:
            revised_lifetime = getattr(aio, "secure_channel_timeout", None)
        if revised_lifetime is None:
            uac = getattr(client, "uaclient", None)
            if uac:
                inner = getattr(uac, "aio_obj", None)
                if inner:
                    revised_lifetime = getattr(inner, "secure_channel_timeout", None)
    except Exception:
        pass

    if revised_lifetime and revised_lifetime > 0:
        hours = revised_lifetime / 3600000
        info(f"Current channel token lifetime: {revised_lifetime / 1000:.0f}s ({hours:.1f}h)")
    else:
        info("Could not determine current channel token lifetime")

    excessive_lifetime_ms = 172800000  # 48 hours
    test_client = None
    try:
        test_client = Client(target, timeout=timeout)

        aio = getattr(test_client, "aio_obj", None)
        if aio:
            aio.secure_channel_timeout = excessive_lifetime_ms
        else:
            uac = getattr(test_client, "uaclient", None)
            if uac:
                inner = getattr(uac, "aio_obj", None)
                if inner:
                    inner.secure_channel_timeout = excessive_lifetime_ms

        test_client.connect()

        granted = None
        aio = getattr(test_client, "aio_obj", None)
        if aio:
            granted = getattr(aio, "secure_channel_timeout", None)
        if granted is None:
            uac = getattr(test_client, "uaclient", None)
            if uac:
                inner = getattr(uac, "aio_obj", None)
                if inner:
                    granted = getattr(inner, "secure_channel_timeout", None)

        if granted and granted > 0:
            granted_hours = granted / 3600000
            info(f"Requested {excessive_lifetime_ms / 3600000:.0f}h, server granted {granted_hours:.1f}h")

            if granted >= excessive_lifetime_ms:
                bad(f"EXCESSIVE CHANNEL LIFETIME ACCEPTED: {granted_hours:.0f}h (requested {excessive_lifetime_ms / 3600000:.0f}h)")
                tag("Cryptographic Failures")
                emit(report_data, "excessive-channel-lifetime",
                     f"Server granted a SecurityToken lifetime of {granted_hours:.0f} hours without revision. "
                     f"Long token lifetimes reduce the frequency of key rotation, increasing the window "
                     f"for key compromise and replay attacks.",
                     confidence="high",
                     verification_status="confirmed-read",
                     safe_check=True,
                     destructive=False,
                     evidence={
                         "requested_ms": excessive_lifetime_ms,
                         "granted_ms": granted,
                         "granted_hours": granted_hours,
                     })
            elif granted > 14400000:  # > 4 hours
                warn(f"Server revised channel lifetime to {granted_hours:.1f}h (still relatively long)")
                emit(report_data, "long-channel-lifetime",
                     f"Server revised the requested token lifetime to {granted_hours:.1f} hours. "
                     f"While revised, this is still above the typical 1-hour recommendation. "
                     f"Longer lifetimes reduce key rotation frequency.",
                     confidence="medium",
                     verification_status="confirmed-read",
                     safe_check=True,
                     destructive=False,
                     evidence={
                         "requested_ms": excessive_lifetime_ms,
                         "granted_ms": granted,
                         "granted_hours": granted_hours,
                     })
            else:
                good(f"Server properly revised channel lifetime to {granted_hours:.1f}h")
        else:
            info("Could not determine granted channel lifetime after test")

    except Exception as e:
        info(f"SecureChannel lifetime test: {classify_error(e)}")
    finally:
        safe_disconnect(test_client)
