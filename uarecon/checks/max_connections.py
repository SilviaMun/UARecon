from asyncua.sync import Client

from ._base import add_observation
from ..banner import warn, info, section
from ..helpers import safe_disconnect


def check_max_connections(target, report_data, timeout=5):
    section("MAX CONNECTIONS (DoS SURFACE)")
    clients = []
    max_test = 20
    try:
        for _ in range(max_test):
            c = Client(target, timeout=timeout)
            try:
                c.connect()
                clients.append(c)
            except Exception:
                break

        count = len(clients)

        if count >= max_test:
            warn(f"At least {count} simultaneous anonymous connections accepted")
            add_observation(
                report_data,
                "Multiple Simultaneous Anonymous Connections Accepted",
                "Security Misconfiguration",
                f"Server accepted at least {count} simultaneous anonymous connections during this limited test. "
                f"This is an observation relevant to DoS assessment, not proof of unsafe connection limits.",
                check="max-connections",
                confidence="low",
                verification_status="capacity-observation",
                safe_check=False,
                destructive=False,
                evidence={"accepted_connections": count, "max_test": max_test},
            )
        elif count > 0:
            info(f"Server accepted {count} anonymous connections before rejecting")
        else:
            info("Anonymous connections not allowed (test requires anonymous access)")
    finally:
        for c in clients:
            safe_disconnect(c)
