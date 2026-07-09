import os
import json
from .banner import section, good, info


DEFAULT_CVE_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "data",
    "opcua_cves.json"
)


def severity_rank(sev):
    order = {
        "Critical": 4,
        "High": 3,
        "Medium": 2,
        "Low": 1,
        "Info": 0,
    }
    return order.get(sev, -1)


def format_score(value):
    return value if value is not None else "n/a"


def format_cwe_list(cwe_list):
    if not cwe_list:
        return "n/a"
    return ", ".join(cwe_list)


def reference_priority(url):
    if not url:
        return 999

    u = url.lower()

    preferred = [
        "opcfoundation.org",
        "files.opcfoundation.org",
        "github.com/opcfoundation",
        "github.com/advisories",
        "github.com",
        "nvd.nist.gov",
        "cve.org",
        "cisa.gov",
        "cert.vde.com",
        "codesys.com",
        "api-it.codesys.com",
        "inductiveautomation.com",
        "open62541.org",
        "eclipse.org",
        "mosquitto.org",
        "siemens.com",
        "cert-portal.siemens.com",
        "zerodayinitiative.com",
    ]

    for idx, dom in enumerate(preferred):
        if dom in u:
            return idx

    suspicious = [
        "php-imap",
        "keepass",
        "velociraptor",
        "frrouting",
    ]

    for bad in suspicious:
        if bad in u:
            return 1000

    return 500


def best_reference(refs):
    if not refs:
        return None

    unique_refs = []
    for r in refs:
        if r and r not in unique_refs:
            unique_refs.append(r)

    ordered = sorted(unique_refs, key=reference_priority)
    return ordered[0] if ordered else None


def load_cve_db(path=None):
    path = path or DEFAULT_CVE_DB_PATH
    if not os.path.exists(path):
        return []

    with open(path, "r") as f:
        data = json.load(f)

    if isinstance(data, list):
        return data
    return []


def infer_component_keywords_from_text(val):
    v = val.lower()
    out = set()

    if "mosquitto" in v:
        out.add("mosquitto")
    if "open62541" in v:
        out.add("open62541")
    if "unified automation" in v or "uaexpert" in v:
        out.add("unified automation")
    if "kepware" in v or "kepserver" in v:
        out.add("kepware")
    if "prosys" in v:
        out.add("prosys")
    if "ignition" in v:
        out.add("ignition")
    if "siemens" in v or "simatic" in v:
        out.add("siemens")
    if "milo" in v:
        out.add("milo")
    if "node-opcua" in v:
        out.add("node-opcua")
    if "codesys" in v:
        out.add("codesys")
    if "softing" in v:
        out.add("softing")
    if "opc foundation" in v or "opcfoundation" in v or ".net" in v:
        out.add("opc foundation")

    return out


def collect_basic_component_hints(client):
    hints = set()

    for nid in ["i=2261", "i=2262", "i=2263", "i=2264", "i=2265", "i=2266"]:
        try:
            v = client.get_node(nid).get_value()
            if v is not None:
                hints.add(str(v).lower())
        except Exception:
            pass

    try:
        ns = client.get_node("i=2255").get_value() or []
        for n in ns:
            hints.add(str(n).lower())
    except Exception:
        pass

    return hints


def build_detected_components(client, report_data):
    detected = set()

    for nid in ["i=2261", "i=2262", "i=2263", "i=2264", "i=2265", "i=2266"]:
        try:
            v = client.get_node(nid).get_value()
            if v is not None:
                sval = str(v).lower()
                detected.add(sval)
                detected.update(infer_component_keywords_from_text(sval))
        except Exception:
            pass

    for h in collect_basic_component_hints(client):
        detected.add(h)
        detected.update(infer_component_keywords_from_text(h))

    for node in report_data.get("all_nodes", []):
        val = str(node.get("value", "")).lower()
        path = str(node.get("path", "")).lower()

        if val and (
            "version" in path
            or "product" in path
            or "manufacturer" in path
            or "vendor" in path
        ):
            detected.add(val)
            detected.update(infer_component_keywords_from_text(val))

    for sess in report_data.get("sessions", []):
        sname = str(sess.get("name", "")).lower()
        if sname:
            detected.add(sname)
            detected.update(infer_component_keywords_from_text(sname))

    for ns in report_data.get("namespaces", []):
        nsl = str(ns).lower()
        detected.add(nsl)
        detected.update(infer_component_keywords_from_text(nsl))

    return detected


def check_cves(client, report_data, db_entries, include_browsed_nodes=True):
    section("CVE DATABASE CHECK")

    try:
        sw_ver = client.get_node("i=2264").get_value()
    except Exception:
        sw_ver = "unknown"

    try:
        product = client.get_node("i=2261").get_value()
    except Exception:
        product = "unknown"

    try:
        manufacturer = client.get_node("i=2263").get_value()
    except Exception:
        manufacturer = "unknown"

    try:
        product_uri = client.get_node("i=2262").get_value()
    except Exception:
        product_uri = ""

    info(f"Product: {product}")
    info(f"Manufacturer: {manufacturer}")
    info(f"Version: {sw_ver}")
    info(f"URI: {product_uri}")

    if not include_browsed_nodes:
        backup = report_data.get("all_nodes", [])
        report_data["all_nodes"] = []

    detected = build_detected_components(client, report_data)
    report_data["detected_components"] = sorted(list(detected))

    if not include_browsed_nodes:
        report_data["all_nodes"] = backup

    detected_preview = [c for c in report_data["detected_components"] if len(c) > 3][:20]
    info(f"Detected components: {', '.join(detected_preview)}")

    direct_matches = []
    generic_matches = []

    for item in db_entries:
        kws = [k.lower() for k in item.get("match_keywords", [])]
        matched_kw = None

        for kw in kws:
            for comp in detected:
                if kw in comp or comp in kw:
                    matched_kw = kw
                    break
            if matched_kw:
                break

        out = dict(item)

        if matched_kw and not item.get("protocol_generic", False):
            out["match_type"] = "direct"
            out["match_reason"] = f"keyword '{matched_kw}' matched detected component set"
            direct_matches.append(out)
        elif item.get("protocol_generic", False):
            out["match_type"] = "generic"
            out["match_reason"] = "generic OPC UA implementation risk"
            generic_matches.append(out)

    direct_matches.sort(
        key=lambda x: (severity_rank(x.get("severity")), x.get("cvss_score") or -1),
        reverse=True
    )
    generic_matches.sort(
        key=lambda x: (severity_rank(x.get("severity")), x.get("cvss_score") or -1),
        reverse=True
    )

    print("\n  ── Direct component matches ──")
    if direct_matches:
        for m in direct_matches:
            print(f"  [{m.get('severity', '?')}] {m.get('cve')}: {m.get('title')}")
            print(f"         Vendor/Product: {m.get('vendor')} / {m.get('product')}")
            print(f"         Affected: {m.get('affected')}")
            if m.get("fixed"):
                print(f"         Fixed: {m.get('fixed')}")
            print(f"         CVSS: {format_score(m.get('cvss_score'))}")
            if m.get("cvss_vector"):
                print(f"         Vector: {m.get('cvss_vector')}")
            print(f"         CWE: {format_cwe_list(m.get('cwe', []))}")
            if m.get("match_reason"):
                print(f"         Match: {m.get('match_reason')}")
            ref = best_reference(m.get("references", []))
            if ref:
                print(f"         Ref: {ref}")
    else:
        good("No direct CVE matches for detected components")

    print("\n  ── Generic OPC-UA risks ──")
    if generic_matches:
        for m in generic_matches:
            print(f"  [{m.get('severity', '?')}] {m.get('cve')}: {m.get('title')}")
            print(f"         Affected: {m.get('affected')}")
            if m.get("fixed"):
                print(f"         Fixed: {m.get('fixed')}")
            print(f"         CVSS: {format_score(m.get('cvss_score'))}")
            if m.get("cvss_vector"):
                print(f"         Vector: {m.get('cvss_vector')}")
            print(f"         CWE: {format_cwe_list(m.get('cwe', []))}")
            ref = best_reference(m.get("references", []))
            if ref:
                print(f"         Ref: {ref}")
    else:
        info("No generic protocol risks in DB")

    enriched_count = 0
    for m in direct_matches + generic_matches:
        if (
            m.get("cvss_score") is not None
            or m.get("cvss_vector")
            or m.get("cwe")
            or m.get("references")
        ):
            enriched_count += 1

    print("\n  ── CVE Summary ──")
    info(f"Direct matches: {len(direct_matches)}")
    info(f"Generic matches: {len(generic_matches)}")
    info(f"Total CVE hits: {len(direct_matches) + len(generic_matches)}")
    info(f"Enriched entries: {enriched_count}")

    report_data["cve_matches"] = direct_matches + generic_matches


def list_all_cves(db_entries):
    section(f"FULL OPC-UA CVE DATABASE ({len(db_entries)} entries)")

    enriched_count = 0

    for item in sorted(
        db_entries,
        key=lambda x: (severity_rank(x.get("severity", "Unknown")), x.get("cvss_score") or -1),
        reverse=True
    ):
        print(f"  [{item.get('severity', '?')}] {item.get('cve')}: {item.get('title')}")
        print(f"         Vendor/Product: {item.get('vendor')} / {item.get('product')}")
        print(f"         Affected: {item.get('affected')}")
        if item.get("fixed"):
            print(f"         Fixed: {item.get('fixed')}")
        print(f"         CVSS: {format_score(item.get('cvss_score'))}")
        if item.get("cvss_vector"):
            print(f"         Vector: {item.get('cvss_vector')}")
        print(f"         CWE: {format_cwe_list(item.get('cwe', []))}")
        ref = best_reference(item.get("references", []))
        if ref:
            print(f"         Ref: {ref}")

        if (
            item.get("cvss_score") is not None
            or item.get("cvss_vector")
            or item.get("cwe")
            or item.get("references")
        ):
            enriched_count += 1

    print()
    info(f"Total CVEs in DB: {len(db_entries)}")
    info(f"Entries with enrichment data: {enriched_count}")
