import json
import datetime
from .banner import section, good, info


def reset_report():
    return {
        "target": "",
        "scan_time": "",
        "server_info": {},
        "namespaces": [],
        "endpoints": [],
        "sessions": [],
        "security_diag": {},
        "vendor_info": {},
        "writable_nodes": [],
        "method_nodes": [],
        "interesting_values": [],
        "all_nodes": [],
        "cve_matches": [],
        "findings": [],
        "total_nodes": 0,
        "detected_components": [],
    }


def save_report(report_data, output_file=None):
    section("REPORT")
    fname = output_file or f"opcpeas_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w") as f:
        json.dump(report_data, f, indent=2, default=str)

    good(f"Saved to {fname}")
    info(
        f"Nodes: {report_data['total_nodes']} | "
        f"Writable: {len(report_data['writable_nodes'])} | "
        f"Methods: {len(report_data['method_nodes'])} | "
        f"Interesting: {len(report_data['interesting_values'])} | "
        f"CVE matches: {len(report_data['cve_matches'])}"
    )
