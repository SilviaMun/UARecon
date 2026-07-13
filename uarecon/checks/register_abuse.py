from asyncua import ua

from ._base import add_observation
from ..banner import good, info, section
from ..helpers import classify_error


def check_register_nodes_abuse(client, report_data):
    section("RegisterNodes ABUSE")
    fake_nodes = [ua.NodeId(99990 + i, 0) for i in range(20)]
    try:
        result = client.register_nodes(fake_nodes)
        if result:
            registered = len(result)
            info(f"RegisterNodes accepted {registered} node registrations")
            add_observation(
                report_data,
                "RegisterNodes Accepted Test Registrations",
                "Security Misconfiguration",
                f"Server accepted {registered} test node registrations. This may be spec-compliant behavior and "
                f"should only be interpreted in the context of resource-consumption testing.",
                check="register-abuse",
                confidence="low",
                verification_status="service-accepted",
                safe_check=False,
                destructive=False,
                evidence={"registered_count": registered},
            )
            try:
                client.unregister_nodes(result)
            except Exception:
                pass
        else:
            good("RegisterNodes returned empty")
    except ua.UaStatusCodeError as e:
        status = str(e).lower()
        if "badnodeidunknown" in status or "badservicenotsupported" in status:
            good(f"RegisterNodes properly rejected ({e})")
        else:
            info(f"RegisterNodes: {e}")
    except Exception as e:
        info(f"RegisterNodes: {classify_error(e)}")
