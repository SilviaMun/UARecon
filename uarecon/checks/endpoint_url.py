from urllib.parse import urlparse

from asyncua.sync import Client

from ._base import add_finding
from ..banner import bad, good, info, section, tag
from ..helpers import safe_disconnect, classify_error, uniq


def check_endpoint_url_mismatch(target, report_data, timeout=5):
    section("ENDPOINT URL VALIDATION")
    tmp = None
    try:
        tmp = Client(target, timeout=timeout)
        endpoints = tmp.connect_and_get_server_endpoints()

        target_parsed = urlparse(target)
        target_host = (target_parsed.hostname or "").lower()

        mismatched = []
        for ep in endpoints:
            ep_url = str(getattr(ep, "EndpointUrl", ""))
            if not ep_url:
                continue
            ep_parsed = urlparse(ep_url)
            ep_host = (ep_parsed.hostname or "").lower()

            if ep_host and target_host and ep_host != target_host:
                local = {"localhost", "127.0.0.1", "::1"}
                if ep_host in local or target_host in local:
                    continue

                ipv4_private = (
                    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
                    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                    "172.30.", "172.31.", "192.168."
                )
                ipv6_private = ("fd", "fe80:")
                ep_is_private = (
                    any(ep_host.startswith(p) for p in ipv4_private)
                    or (":" in ep_host and any(ep_host.startswith(p) for p in ipv6_private))
                )
                target_is_private = (
                    any(target_host.startswith(p) for p in ipv4_private)
                    or (":" in target_host and any(target_host.startswith(p) for p in ipv6_private))
                )
                if ep_is_private and not target_is_private:
                    mismatched.append((ep_url, ep_host))
                    bad(f"INTERNAL ADDRESS LEAKED: server advertises {ep_url} (reached via {target_host})")
                    tag("Security Misconfiguration")

        if mismatched:
            hosts = uniq([h for _, h in mismatched])
            add_finding(
                report_data,
                "Endpoint URL Hostname Mismatch",
                "Medium",
                "Security Misconfiguration",
                f"Server advertises endpoints with internal address(es) {', '.join(hosts)} "
                f"but was reached via {target_host}. This leaks internal network topology.",
                check="endpoint-url",
                confidence="high",
                verification_status="endpoint-analysis",
                safe_check=True,
                destructive=False,
                evidence={"mismatched_hosts": hosts, "target_host": target_host},
            )
        else:
            good(f"All endpoint URLs match target hostname ({target_host})")
    except Exception as e:
        info(f"Could not validate endpoint URLs: {classify_error(e)}")
    finally:
        safe_disconnect(tmp)
