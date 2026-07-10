import os
import re
import json
from .banner import critical, section, good, bad, warn, info


DEFAULT_CVE_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "data",
    "opcua_cves.json"
)

VERSION_RE = re.compile(r"(\d+(?:\.\d+)+)")

PRODUCT_TAG_PATTERNS = {
    "dotnet": [".net", "ua-.netstandard", "dotnetstd", "opc foundation .net"],
    "dotnet-legacy": [".net legacy"],
    "java": ["java"],
    "lds": ["local discovery server", "lds"],
    "ansi-c": ["ansi c", "c-stack", "c stack"],
    "open62541": ["open62541"],
    "unified-automation": ["unified automation", "uaexpert"],
    "kepware": ["kepware", "kepserverex", "thingworx"],
    "prosys": ["prosys"],
    "ignition": ["ignition", "inductive automation"],
    "siemens": ["siemens", "simatic"],
    "milo": ["milo", "eclipse milo"],
    "node-opcua": ["node-opcua"],
    "codesys": ["codesys"],
    "softing": ["softing"],
    "mosquitto": ["mosquitto"],
}


def severity_rank(sev):
    return {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}.get(sev, -1)


def format_score(value):
    return value if value is not None else "n/a"


def format_cwe_list(cwe_list):
    if not cwe_list:
        return "n/a"
    return ", ".join(cwe_list)


def best_reference(refs):
    if not refs:
        return None

    priority_domains = [
        "opcfoundation.org", "files.opcfoundation.org",
        "github.com/opcfoundation", "github.com/advisories", "github.com",
        "nvd.nist.gov", "cve.org", "cisa.gov",
    ]

    def prio(url):
        u = url.lower()
        for i, dom in enumerate(priority_domains):
            if dom in u:
                return i
        return 500

    unique = list(dict.fromkeys(refs))
    return sorted(unique, key=prio)[0]


def load_cve_db(path=None):
    path = path or DEFAULT_CVE_DB_PATH
    if not os.path.exists(path):
        return []

    with open(path, "r") as f:
        data = json.load(f)

    return data if isinstance(data, list) else []


def parse_version(ver_str):
    if not ver_str:
        return None
    m = VERSION_RE.search(str(ver_str))
    if not m:
        return None
    try:
        return tuple(int(p) for p in m.group(1).split("."))
    except ValueError:
        return None


def version_lt(a, b):
    if a is None or b is None:
        return None
    for x, y in zip(a, b):
        if x < y:
            return True
        if x > y:
            return False
    return len(a) < len(b)


def identify_server(client, report_data):
    fields = {}
    node_map = {
        "product": "i=2261",
        "product_uri": "i=2262",
        "manufacturer": "i=2263",
        "version": "i=2264",
        "build": "i=2265",
    }

    for key, nid in node_map.items():
        try:
            v = client.get_node(nid).get_value()
            if v is not None:
                fields[key] = str(v)
        except Exception:
            pass

    namespaces = []
    try:
        ns = client.get_node("i=2255").get_value() or []
        namespaces = [str(n) for n in ns]
    except Exception:
        pass

    all_text = " ".join([
        fields.get("product", ""),
        fields.get("product_uri", ""),
        fields.get("manufacturer", ""),
        fields.get("build", ""),
    ] + namespaces).lower()

    detected_tags = set()
    for tag, patterns in PRODUCT_TAG_PATTERNS.items():
        for p in patterns:
            if p in all_text:
                detected_tags.add(tag)
                break

    server_version = parse_version(fields.get("version"))

    report_data["server_info"]["detected_product_tags"] = sorted(detected_tags)
    report_data["server_info"]["detected_version"] = fields.get("version")

    return fields, detected_tags, server_version, namespaces


_CVE_SEVERITY_FN = {
    "Critical": critical,
    "High": bad,
    "Medium": warn,
}


def _print_cve(m, status_label=None):
    sev = m.get("severity", "?")
    fn = _CVE_SEVERITY_FN.get(sev, info)
    label = f" ({status_label})" if status_label else ""
    fn(f"[{sev}] {m.get('cve')}: {m.get('title')}{label}")
    print(f"         Product: {m.get('product')}")
    print(f"         Affected: {m.get('affected')}")
    if m.get("fixed"):
        fixed_ver = m.get("fixed_version")
        fixed_text = m["fixed"]
        if fixed_ver:
            print(f"         Fixed in: {fixed_ver}")
        else:
            print(f"         Fix: {fixed_text}")
    print(f"         CVSS: {format_score(m.get('cvss_score'))}")
    if m.get("cvss_vector"):
        print(f"         Vector: {m.get('cvss_vector')}")
    print(f"         CWE: {format_cwe_list(m.get('cwe', []))}")
    ref = best_reference(m.get("references", []))
    if ref:
        print(f"         Ref: {ref}")


def check_cves(client, report_data, db_entries, include_browsed_nodes=True):
    section("CVE DATABASE CHECK")

    fields, detected_tags, server_version, namespaces = identify_server(client, report_data)

    info(f"Product: {fields.get('product', '?')}")
    info(f"Manufacturer: {fields.get('manufacturer', '?')}")
    info(f"Version: {fields.get('version', '?')}")
    info(f"URI: {fields.get('product_uri', '?')}")

    if detected_tags:
        info(f"Detected stack: {', '.join(sorted(detected_tags))}")
    else:
        info("Detected stack: unknown")
        info("No known product tag identified; only generic OPC UA risks will be shown")

    if server_version:
        info(f"Parsed version: {'.'.join(str(p) for p in server_version)}")

    confirmed = []
    possible = []
    generic_risks = []

    for item in db_entries:
        cve_tag = item.get("product_tag", "generic")
        fixed_version = parse_version(item.get("fixed_version"))

        # Generic / protocol-level / spec-level risks:
        if item.get("protocol_generic") or cve_tag == "generic" or cve_tag == "spec":
            out = dict(item)
            out["match_status"] = "generic"
            generic_risks.append(out)
            continue

        tag_match = False

        if cve_tag == "dotnet" and "dotnet" in detected_tags:
            tag_match = True
        elif cve_tag == "dotnet-legacy" and ("dotnet" in detected_tags or "dotnet-legacy" in detected_tags):
            tag_match = True
        elif cve_tag in detected_tags:
            tag_match = True

        if not tag_match:
            continue

        out = dict(item)

        if server_version and fixed_version:
            is_vuln = version_lt(server_version, fixed_version)
            if is_vuln is True:
                out["match_status"] = "confirmed"
                confirmed.append(out)
            elif is_vuln is False:
                pass
            else:
                out["match_status"] = "possible"
                possible.append(out)
        else:
            out["match_status"] = "possible"
            possible.append(out)

    for group in [confirmed, possible, generic_risks]:
        group.sort(
            key=lambda x: (severity_rank(x.get("severity")), x.get("cvss_score") or -1),
            reverse=True,
        )

    if confirmed:
        print(f"\n  ── CONFIRMED VULNERABLE ({len(confirmed)}) ──")
        for m in confirmed:
            _print_cve(m, status_label="version < fixed")
    else:
        print("\n  ── CONFIRMED VULNERABLE ──")
        good("No confirmed vulnerabilities based on product+version comparison")

    if possible:
        print(f"\n  ── POSSIBLY AFFECTED ({len(possible)}) ──")
        for m in possible:
            _print_cve(m, status_label="product matches, version unconfirmed")
    else:
        print("\n  ── POSSIBLY AFFECTED ──")
        good("No possible matches for detected product stack")

    if generic_risks:
        print(f"\n  ── GENERIC OPC UA / ECOSYSTEM RISKS ({len(generic_risks)}) ──")
        for m in generic_risks:
            _print_cve(m, status_label="generic/spec/protocol-level")

    all_matches = confirmed + possible + generic_risks
    print("\n  ── CVE Summary ──")
    if confirmed:
        bad(f"CONFIRMED VULNERABLE: {len(confirmed)}")
    else:
        good("No confirmed vulnerabilities")

    if possible:
        warn(f"Possibly affected: {len(possible)}")
    else:
        good("No possible product-specific matches")

    info(f"Generic risks: {len(generic_risks)}")
    info(f"Total in database: {len(db_entries)}")

    report_data["cve_matches"] = all_matches
    report_data["cve_confirmed"] = len(confirmed)
    report_data["cve_possible"] = len(possible)
    report_data["cve_generic"] = len(generic_risks)


def list_all_cves(db_entries):
    section(f"FULL OPC-UA CVE DATABASE ({len(db_entries)} entries)")

    for item in sorted(
        db_entries,
        key=lambda x: (severity_rank(x.get("severity", "Unknown")), x.get("cvss_score") or -1),
        reverse=True
    ):
        sev = item.get("severity", "?")
        fn = _CVE_SEVERITY_FN.get(sev, info)
        fn(f"[{sev}] {item.get('cve')}: {item.get('title')}")
        print(f"         Product: {item.get('product')} [tag={item.get('product_tag', '?')}]")
        print(f"         Affected: {item.get('affected')}")
        if item.get("fixed_version"):
            print(f"         Fixed in: {item['fixed_version']}")
        elif item.get("fixed"):
            print(f"         Fix: {item['fixed']}")
        print(f"         CVSS: {format_score(item.get('cvss_score'))}")
        if item.get("cvss_vector"):
            print(f"         Vector: {item.get('cvss_vector')}")
        print(f"         CWE: {format_cwe_list(item.get('cwe', []))}")
        ref = best_reference(item.get("references", []))
        if ref:
            print(f"         Ref: {ref}")

    tags = {}
    for e in db_entries:
        tags.setdefault(e.get("product_tag", "?"), []).append(e["cve"])

    print()
    info(f"Total CVEs in DB: {len(db_entries)}")
    info("By product:")
    for tag, cves in sorted(tags.items()):
        info(f"  {tag}: {len(cves)}")
