from ._base import emit
from ..banner import bad, warn, good, info, section, tag


def check_audit_config(client, report_data):
    section("AUDIT CONFIGURATION")
    try:
        auditing = client.get_node("i=2994").read_value()
        if auditing:
            good("Auditing is ENABLED")
        else:
            bad("AUDITING IS DISABLED - operations are not being logged")
            tag("Security Misconfiguration")
            emit(report_data, "auditing-disabled",
                 "Server auditing is disabled. Malicious operations will not be logged or traced.",
                 confidence="high",
                 verification_status="confirmed-read",
                 safe_check=True,
                 destructive=False)
    except Exception:
        warn("Could not read auditing status (node i=2994)")

    try:
        diag_enabled = client.get_node("i=2274").read_value()
        if diag_enabled:
            info("Server diagnostics enabled")
        else:
            info("Server diagnostics disabled")
    except Exception:
        pass
