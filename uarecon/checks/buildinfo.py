from ._base import add_observation
from ..banner import good, info, section
from ..helpers import sr


def check_buildinfo_exposure(client, report_data):
    section("BUILD INFORMATION EXPOSURE")
    build_nodes = [
        ("i=2261", "ProductName"),
        ("i=2262", "ProductUri"),
        ("i=2263", "ManufacturerName"),
        ("i=2264", "SoftwareVersion"),
        ("i=2265", "BuildNumber"),
        ("i=2266", "BuildDate"),
    ]

    exposed = {}
    for nid, label in build_nodes:
        try:
            val = sr(client.get_node(nid))
            if val is not None and str(val).strip():
                exposed[label] = str(val)
        except Exception:
            pass

    if exposed:
        details = "; ".join(f"{k}={v}" for k, v in exposed.items())
        info(f"Build info: {details}")

        has_version = "SoftwareVersion" in exposed or "BuildNumber" in exposed
        has_product = "ProductName" in exposed or "ProductUri" in exposed

        if has_version and has_product:
            add_observation(
                report_data,
                "Build Information Available",
                "Information Disclosure",
                f"Server exposes build information: {details}. "
                f"This is standard OPC UA behavior but may help identify applicable CVEs.",
                check="buildinfo",
                confidence="high",
                verification_status="confirmed-read",
                safe_check=True,
                destructive=False,
                evidence={"exposed_fields": exposed},
            )
    else:
        good("Build information not readable")
