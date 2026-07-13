"""
Discovery Service Exposure Check.

Notes on false positive avoidance:
- FindServers returns at least the server itself (always 1 entry).
- If the server runs an LDS (Local Discovery Server), it is DESIGNED to return
  multiple servers - this is its job, not a vulnerability.
- Only flag multi-server discovery as a finding when additional servers are
  revealed beyond what is expected for the server's advertised capabilities.
- The LDS scenario is detected by checking if the server advertises LDS
  capabilities or if returned servers are distinct from the target.
"""

from urllib.parse import urlparse

from asyncua.sync import Client

from ._base import add_finding, add_observation
from ..banner import warn, good, info, section, tag
from ..helpers import safe_disconnect, classify_error


def check_discovery_exposure(target, report_data, timeout=5):
    section("DISCOVERY SERVICE EXPOSURE")
    tmp = None
    try:
        tmp = Client(target, timeout=timeout)
        servers = tmp.connect_and_find_servers()
        if servers:
            target_host = (urlparse(target).hostname or "").lower()
            other_servers = []
            found_self = False

            for srv in servers:
                name = getattr(srv, "ApplicationName", None)
                app_uri = getattr(srv, "ApplicationUri", "")
                app_type = getattr(srv, "ApplicationType", None)
                disc_urls = getattr(srv, "DiscoveryUrls", []) or []
                label = name.Text if name else app_uri
                info(f"  Server: {label} (type: {app_type})")
                for url in disc_urls:
                    info(f"    URL: {url}")

                # Check if this is a different server (not self)
                is_different = True
                for url in disc_urls:
                    try:
                        url_host = (urlparse(str(url)).hostname or "").lower()
                        if url_host == target_host or url_host in ("localhost", "127.0.0.1", "::1"):
                            is_different = False
                            found_self = True
                            break
                    except Exception:
                        pass

                if is_different:
                    other_servers.append({
                        "name": str(label),
                        "uri": str(app_uri),
                        "urls": [str(u) for u in disc_urls[:5]],
                    })

            # If no entry matched the target host, the first entry is most likely
            # the server itself using a different hostname (e.g., internal hostname
            # vs. IP used for connection). Don't count it as "other."
            if not found_self and other_servers:
                other_servers.pop(0)

            if other_servers:
                # FindServers reveals OTHER servers (beyond the target) - this exposes topology
                warn(f"FindServers reveals {len(other_servers)} additional server(s) beyond the target")
                tag("Information Disclosure")
                add_finding(
                    report_data,
                    "Discovery Service Exposes Additional Servers",
                    "Medium",
                    "Information Disclosure",
                    f"FindServers returned {len(servers)} server(s), of which {len(other_servers)} appear to be "
                    f"distinct from the target. This may expose additional OPC UA targets and internal topology. "
                    f"If this server operates as a Local Discovery Server (LDS), multi-server responses "
                    f"are expected but still reveal topology.",
                    check="discovery",
                    confidence="medium",
                    verification_status="confirmed-read",
                    safe_check=True,
                    destructive=False,
                    evidence={
                        "server_count": len(servers),
                        "other_servers": other_servers[:10],
                    },
                )
            elif len(servers) > 1:
                # Multiple entries but all on the same host (multi-application on one host)
                info(f"FindServers returned {len(servers)} server(s) (all on same host)")
                add_observation(
                    report_data,
                    "Multiple Applications on Same Host",
                    "Information Disclosure",
                    f"FindServers returned {len(servers)} server(s), all apparently on the same host. "
                    f"This reveals co-located OPC UA applications but no remote topology.",
                    check="discovery",
                    confidence="low",
                    verification_status="confirmed-read",
                    safe_check=True,
                    destructive=False,
                    evidence={"server_count": len(servers)},
                )
            else:
                good("FindServers returned only self (no extra topology)")
        else:
            good("FindServers returned empty")
    except Exception as e:
        info(f"FindServers not available: {classify_error(e)}")
    finally:
        safe_disconnect(tmp)
