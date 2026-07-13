from asyncua import ua

from ._base import add_observation
from ..banner import warn, good, info, section
from ..helpers import classify_error


def check_translate_dos(client, report_data):
    section("TRANSLATE BROWSE PATHS (BULK REQUEST)")

    # TranslateBrowsePathsToNodeIds resolves symbolic paths
    # to NodeIds. If the server accepts large batches without rate limiting, an
    # attacker can exhaust CPU by sending thousands of path resolution requests.
    # This is a known amplification vector because path traversal is recursive.

    # Generate a batch of fake deep paths that force recursive traversal
    test_paths = []
    root_id = ua.NodeId(84, 0)  # Root node
    for i in range(100):
        # Create a deep path with multiple hops to force recursive resolution
        elements = []
        for depth in range(5):
            el = ua.RelativePathElement()
            el.ReferenceTypeId = ua.NodeId(33, 0)  # HierarchicalReferences
            el.IsInverse = False
            el.IncludeSubtypes = True
            el.TargetName = ua.QualifiedName(f"FakePath_{i}_Depth_{depth}", 0)
            elements.append(el)

        bp = ua.BrowsePath()
        bp.StartingNode = root_id
        bp.RelativePath = ua.RelativePath()
        bp.RelativePath.Elements = elements
        test_paths.append(bp)

    try:
        # Access via the sync-wrapped uaclient which delegates to the async session
        uac = client.uaclient
        results = uac.translate_browsepaths_to_nodeids(test_paths)

        # If the server processed all 100 paths without error, it accepts bulk requests
        if results and len(results) >= 100:
            # Check if any actually resolved (unlikely with fake paths)
            resolved = sum(1 for r in results if r.StatusCode.is_good())
            info(f"Server processed {len(results)} path translations ({resolved} resolved)")

            if len(results) >= 100:
                warn(f"Server accepted bulk TranslateBrowsePaths ({len(results)} paths, 5 levels deep each)")
                add_observation(
                    report_data,
                    "Bulk TranslateBrowsePaths Accepted",
                    "Security Misconfiguration",
                    f"Server processed {len(results)} TranslateBrowsePathsToNodeIds requests in a single call "
                    f"with 5-level deep paths. This service performs recursive path traversal and may be "
                    f"exploitable for CPU exhaustion if no server-side rate limiting is in place.",
                    check="translate-dos",
                    confidence="low",
                    verification_status="capacity-observation",
                    safe_check=False,
                    destructive=False,
                    evidence={"paths_sent": len(test_paths), "paths_processed": len(results), "depth": 5},
                )
        elif results:
            info(f"Server processed {len(results)} paths (partial acceptance)")
        else:
            good("Server returned empty result for bulk path translation")

    except ua.UaStatusCodeError as e:
        status = str(e).lower()
        if "badservicenotsupported" in status:
            info("TranslateBrowsePathsToNodeIds not supported")
        elif "badtoomanyoperations" in status:
            good(f"Server limits bulk path resolution ({e})")
        else:
            info(f"TranslateBrowsePaths test: {e}")
    except Exception as e:
        info(f"TranslateBrowsePaths test: {classify_error(e)}")
