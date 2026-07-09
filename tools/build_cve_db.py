#!/usr/bin/env python3
import os
import json
import time
import argparse
import requests

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
OUT = os.path.join(BASE_DIR, "data", "opcua_cves.json")

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

DEFAULT_CVES = [
    {
        "cve": "CVE-2024-42512",
        "title": "Authentication bypass via deprecated Basic128Rsa15 handling",
        "vendor": "OPC Foundation",
        "product": "UA-.NETStandard",
        "component": "OPC UA .NET Standard Stack",
        "affected": "< 1.5.374.158",
        "fixed": "1.5.374.158",
        "cvss_score": 5.9,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "severity": "Medium",
        "cwe": ["CWE-208"],
        "match_keywords": [".net", "opc foundation", "opcfoundation", "ua-.netstandard", "dotnetstd"],
        "protocol_generic": False,
        "references": [
            "https://github.com/OPCFoundation/UA-.NETStandard/security/advisories/GHSA-h958-fxgg-g7w3",
            "https://files.opcfoundation.org/SecurityBulletins/OPC%20Foundation%20Security%20Bulletin%20CVE-2024-42512.pdf"
        ]
    },
    {
        "cve": "CVE-2024-42513",
        "title": "HTTPS endpoint application authentication bypass",
        "vendor": "OPC Foundation",
        "product": "UA-.NETStandard",
        "component": "OPC UA .NET Standard Stack",
        "affected": "< 1.5.374.158",
        "fixed": "1.5.374.158",
        "cvss_score": 6.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "severity": "Medium",
        "cwe": ["CWE-305"],
        "match_keywords": [".net", "opc foundation", "opcfoundation", "ua-.netstandard", "dotnetstd", "https"],
        "protocol_generic": False,
        "references": [
            "https://files.opcfoundation.org/SecurityBulletins/OPC%20Foundation%20Security%20Bulletin%20CVE-2024-42513.pdf"
        ]
    },
    {
        "cve": "CVE-2024-45526",
        "title": "Performance degradation by saving rejected certificates after auth failure",
        "vendor": "OPC Foundation",
        "product": "UA-.NETStandard",
        "component": "OPC UA .NET Standard Stack",
        "affected": "< 1.5.374.118",
        "fixed": "1.5.374.118",
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
        "severity": "Medium",
        "cwe": ["CWE-770"],
        "match_keywords": [".net", "opc foundation", "opcfoundation", "ua-.netstandard", "dotnetstd"],
        "protocol_generic": False,
        "references": [
            "https://files.opcfoundation.org/SecurityBulletins/OPC%20Foundation%20Security%20Bulletin%20CVE-2024-45526.pdf"
        ]
    },
    {
        "cve": "CVE-2025-1468",
        "title": "Basic128Rsa15 private-key compromise / auth bypass on enabled deprecated policy",
        "vendor": "Multiple / CODESYS confirmed",
        "product": "Multiple implementations / CODESYS Runtime Toolkit",
        "component": "OPC UA server implementations with Basic128Rsa15 enabled",
        "affected": "Multiple implementations; CODESYS Runtime Toolkit < 3.5.21.0",
        "fixed": "3.5.21.0",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "severity": "High",
        "cwe": ["CWE-208"],
        "match_keywords": ["codesys", "opc ua", "basic128rsa15", "runtime toolkit", "opcfoundation", ".net"],
        "protocol_generic": True,
        "references": [
            "https://api-it.codesys.com/fileadmin/user_upload/CODESYS_Group/Ecosystem/Up-to-Date/Security/Security-Advisories/Advisory2025-04_CDS-91316.pdf"
        ]
    },
    {
        "cve": "CVE-2024-10525",
        "title": "Heap-based overflow in SUBACK handler",
        "vendor": "Eclipse Mosquitto",
        "product": "Mosquitto",
        "component": "MQTT broker",
        "affected": "1.3.2 - 2.0.18",
        "fixed": "after 2.0.18",
        "cvss_score": None,
        "cvss_vector": None,
        "severity": "High",
        "cwe": [],
        "match_keywords": ["mosquitto"],
        "protocol_generic": False,
        "references": []
    },
    {
        "cve": "CVE-2024-10526",
        "title": "Memory leak / UAF / segfault via CONNECT-DISCONNECT sequences",
        "vendor": "Eclipse Mosquitto",
        "product": "Mosquitto",
        "component": "MQTT broker",
        "affected": "<= 2.0.18a",
        "fixed": "after 2.0.18a",
        "cvss_score": None,
        "cvss_vector": None,
        "severity": "High",
        "cwe": [],
        "match_keywords": ["mosquitto"],
        "protocol_generic": False,
        "references": []
    },
    {
        "cve": "CVE-2024-3935",
        "title": "Double free in bridge connection with topic remapping",
        "vendor": "Eclipse Mosquitto",
        "product": "Mosquitto",
        "component": "MQTT broker",
        "affected": "2.0.0 - 2.0.18",
        "fixed": "after 2.0.18",
        "cvss_score": None,
        "cvss_vector": None,
        "severity": "Medium",
        "cwe": [],
        "match_keywords": ["mosquitto"],
        "protocol_generic": False,
        "references": []
    },
    {
        "cve": "CVE-2023-31048",
        "title": "Insufficient access control in Prosys OPC UA Simulation Server",
        "vendor": "Prosys",
        "product": "Prosys OPC UA Simulation Server",
        "component": "Simulation Server",
        "affected": "< 5.0.2",
        "fixed": "5.0.2",
        "cvss_score": None,
        "cvss_vector": None,
        "severity": "Medium",
        "cwe": [],
        "match_keywords": ["prosys", "simulation server"],
        "protocol_generic": False,
        "references": []
    },
    {
        "cve": "CVE-2024-53429",
        "title": "Pre-auth DoS via malformed SecureChannel chunks",
        "vendor": "open62541",
        "product": "open62541",
        "component": "SecureChannel handling",
        "affected": "<= 1.4.6",
        "fixed": "patched release required",
        "cvss_score": None,
        "cvss_vector": None,
        "severity": "High",
        "cwe": [],
        "match_keywords": ["open62541"],
        "protocol_generic": False,
        "references": []
    },
    {
        "cve": "CVE-2024-25380",
        "title": "DoS via malformed OPC-UA packet causing NULL dereference",
        "vendor": "open62541",
        "product": "open62541",
        "component": "Packet handling",
        "affected": "< 1.3.9",
        "fixed": "1.3.9",
        "cvss_score": None,
        "cvss_vector": None,
        "severity": "High",
        "cwe": [],
        "match_keywords": ["open62541"],
        "protocol_generic": False,
        "references": []
    },
    {
        "cve": "CVE-2023-32784",
        "title": "Memory leak via repeated CreateSession requests",
        "vendor": "open62541",
        "product": "open62541",
        "component": "CreateSession handling",
        "affected": "< 1.3.6",
        "fixed": "1.3.6",
        "cvss_score": None,
        "cvss_vector": None,
        "severity": "Medium",
        "cwe": [],
        "match_keywords": ["open62541"],
        "protocol_generic": False,
        "references": []
    },
    {
        "cve": "CVE-2023-27334",
        "title": "Use-after-free in Unified Automation UA .NET SDK",
        "vendor": "Unified Automation",
        "product": "UA .NET SDK",
        "component": "SDK internals",
        "affected": "versions before patch",
        "fixed": "vendor patch required",
        "cvss_score": None,
        "cvss_vector": None,
        "severity": "High",
        "cwe": [],
        "match_keywords": ["unified automation", "uaexpert"],
        "protocol_generic": False,
        "references": []
    },
    {
        "cve": "CVE-2023-27335",
        "title": "Stack buffer overflow in Unified Automation C++ SDK",
        "vendor": "Unified Automation",
        "product": "UA C++ SDK",
        "component": "C++ SDK",
        "affected": "versions before patch",
        "fixed": "vendor patch required",
        "cvss_score": None,
        "cvss_vector": None,
        "severity": "High",
        "cwe": [],
        "match_keywords": ["unified automation"],
        "protocol_generic": False,
        "references": []
    },
    {
        "cve": "CVE-2023-29444",
        "title": "Heap-based buffer overflow in KEPServerEX OPC-UA component",
        "vendor": "Kepware",
        "product": "KEPServerEX",
        "component": "OPC-UA component",
        "affected": "< 6.14",
        "fixed": "6.14",
        "cvss_score": None,
        "cvss_vector": None,
        "severity": "High",
        "cwe": [],
        "match_keywords": ["kepware", "kepserverex", "thingworx"],
        "protocol_generic": False,
        "references": []
    },
    {
        "cve": "CVE-2023-29445",
        "title": "Stack-based buffer overflow in KEPServerEX OPC-UA component",
        "vendor": "Kepware",
        "product": "KEPServerEX",
        "component": "OPC-UA component",
        "affected": "< 6.14",
        "fixed": "6.14",
        "cvss_score": None,
        "cvss_vector": None,
        "severity": "High",
        "cwe": [],
        "match_keywords": ["kepware", "kepserverex", "thingworx"],
        "protocol_generic": False,
        "references": []
    },
    {
        "cve": "CVE-2023-35169",
        "title": "Denial of service via malformed ExtensionObject",
        "vendor": "Eclipse",
        "product": "Milo",
        "component": "ExtensionObject handling",
        "affected": "< 0.6.11",
        "fixed": "0.6.11",
        "cvss_score": None,
        "cvss_vector": None,
        "severity": "High",
        "cwe": [],
        "match_keywords": ["milo", "eclipse milo"],
        "protocol_generic": False,
        "references": []
    },
    {
        "cve": "CVE-2023-39476",
        "title": "OPC-UA auth bypass leading to RCE",
        "vendor": "Inductive Automation",
        "product": "Ignition",
        "component": "OPC-UA subsystem",
        "affected": "< 8.1.31",
        "fixed": "8.1.31",
        "cvss_score": None,
        "cvss_vector": None,
        "severity": "Critical",
        "cwe": [],
        "match_keywords": ["ignition", "inductive automation"],
        "protocol_generic": False,
        "references": []
    },
    {
        "cve": "CVE-2023-39475",
        "title": "OPC-UA deserialization leading to RCE",
        "vendor": "Inductive Automation",
        "product": "Ignition",
        "component": "OPC-UA deserialization",
        "affected": "< 8.1.31",
        "fixed": "8.1.31",
        "cvss_score": None,
        "cvss_vector": None,
        "severity": "Critical",
        "cwe": [],
        "match_keywords": ["ignition", "inductive automation"],
        "protocol_generic": False,
        "references": []
    },
    {
        "cve": "CVE-2024-44070",
        "title": "OPC-UA server DoS via specially crafted packets",
        "vendor": "Siemens",
        "product": "Multiple SIMATIC products",
        "component": "OPC-UA server",
        "affected": "multiple SIMATIC products",
        "fixed": "vendor patch required",
        "cvss_score": None,
        "cvss_vector": None,
        "severity": "High",
        "cwe": [],
        "match_keywords": ["siemens", "simatic"],
        "protocol_generic": False,
        "references": []
    },
    {
        "cve": "CVE-2023-47457",
        "title": "Uncontrolled resource consumption causing DoS",
        "vendor": "node-opcua",
        "product": "node-opcua",
        "component": "Server resource handling",
        "affected": "< 2.108.0",
        "fixed": "2.108.0",
        "cvss_score": None,
        "cvss_vector": None,
        "severity": "High",
        "cwe": [],
        "match_keywords": ["node-opcua", "nodejs"],
        "protocol_generic": False,
        "references": []
    },
    {
        "cve": "CVE-2023-37550",
        "title": "OPC-UA server DoS via crafted request",
        "vendor": "CODESYS",
        "product": "CODESYS",
        "component": "OPC UA server",
        "affected": "< 3.5.19.20",
        "fixed": "3.5.19.20",
        "cvss_score": None,
        "cvss_vector": None,
        "severity": "High",
        "cwe": [],
        "match_keywords": ["codesys"],
        "protocol_generic": False,
        "references": []
    },
    {
        "cve": "CVE-2023-37551",
        "title": "OPC-UA server DoS via crafted certificate",
        "vendor": "CODESYS",
        "product": "CODESYS",
        "component": "Certificate handling",
        "affected": "< 3.5.19.20",
        "fixed": "3.5.19.20",
        "cvss_score": None,
        "cvss_vector": None,
        "severity": "High",
        "cwe": [],
        "match_keywords": ["codesys"],
        "protocol_generic": False,
        "references": []
    },
    {
        "cve": "CVE-2017-12069",
        "title": "Improper validation of trust chain in OpenSecureChannel handshake",
        "vendor": "Multiple",
        "product": "OPC UA implementations",
        "component": "OpenSecureChannel / trust-chain validation",
        "affected": "various implementations",
        "fixed": "implementation-specific",
        "cvss_score": None,
        "cvss_vector": None,
        "severity": "High",
        "cwe": [],
        "match_keywords": ["opc ua", "generic", "all"],
        "protocol_generic": True,
        "references": []
    },
    {
        "cve": "CVE-2019-8287",
        "title": "Stack buffer overflow in UA Binary decoder",
        "vendor": "Multiple",
        "product": "OPC UA implementations",
        "component": "UA Binary decoder",
        "affected": "various implementations",
        "fixed": "implementation-specific",
        "cvss_score": None,
        "cvss_vector": None,
        "severity": "Critical",
        "cwe": [],
        "match_keywords": ["opc ua", "generic", "all"],
        "protocol_generic": True,
        "references": []
    }
]


def atomic_write_json(path, data):
    tmp_path = path + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp_path, path)


def merge_by_cve(entries):
    merged = {}
    for item in entries:
        cve = item.get("cve")
        if not cve:
            continue
        merged[cve] = item
    return list(merged.values())


def load_extra(path):
    if not path:
        return []
    with open(path, "r") as f:
        data = json.load(f)
    return data if isinstance(data, list) else []


def load_existing_output(path):
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


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


def clean_references(refs):
    if not refs:
        return []

    unique_refs = []
    for r in refs:
        if r and r not in unique_refs:
            unique_refs.append(r)

    ordered = sorted(unique_refs, key=reference_priority)
    return ordered


def fetch_nvd_details(cve_id, api_key=None, timeout=20):
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    response = requests.get(
        NVD_API,
        params={"cveId": cve_id},
        headers=headers,
        timeout=timeout
    )
    response.raise_for_status()
    data = response.json()

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None

    cve = vulns[0].get("cve", {})
    metrics = cve.get("metrics", {})
    weaknesses = cve.get("weaknesses", [])
    references = cve.get("references", [])

    score = None
    vector = None
    severity = None

    for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if metric_key in metrics and metrics[metric_key]:
            metric = metrics[metric_key][0]
            cvss_data = metric.get("cvssData", {})
            score = cvss_data.get("baseScore")
            vector = cvss_data.get("vectorString")
            severity = metric.get("baseSeverity") or cvss_data.get("baseSeverity")
            break

    cwes = []
    for w in weaknesses:
        for d in w.get("description", []):
            val = d.get("value")
            if val and val not in cwes:
                cwes.append(val)

    refs = []
    for ref in references:
        url = ref.get("url")
        if url and url not in refs:
            refs.append(url)

    descriptions = cve.get("descriptions", [])
    desc = None
    for d in descriptions:
        if d.get("lang") == "en":
            desc = d.get("value")
            break

    return {
        "title_from_nvd": desc,
        "cvss_score": score,
        "cvss_vector": vector,
        "severity": severity,
        "cwe": cwes,
        "references": refs,
    }


def fetch_nvd_with_retry(cve_id, api_key=None, timeout=20, retries=5, base_delay=6):
    attempt = 0
    while attempt < retries:
        try:
            return fetch_nvd_details(cve_id, api_key=api_key, timeout=timeout)
        except requests.HTTPError as e:
            status = None
            try:
                status = e.response.status_code
            except Exception:
                pass

            if status == 429:
                sleep_time = base_delay * (2 ** attempt)
                print(f"[!] Rate limited on {cve_id}, retrying in {sleep_time:.1f}s")
                time.sleep(sleep_time)
                attempt += 1
                continue
            raise
        except requests.RequestException:
            sleep_time = base_delay * (2 ** attempt)
            print(f"[!] Network/API issue on {cve_id}, retrying in {sleep_time:.1f}s")
            time.sleep(sleep_time)
            attempt += 1

    raise RuntimeError(f"Exceeded retries for {cve_id}")


def enrich_entry(entry, nvd_data):
    if not nvd_data:
        entry["references"] = clean_references(entry.get("references", []))
        return entry

    if not entry.get("title") and nvd_data.get("title_from_nvd"):
        entry["title"] = nvd_data["title_from_nvd"]

    if nvd_data.get("cvss_score") is not None:
        entry["cvss_score"] = nvd_data["cvss_score"]

    if nvd_data.get("cvss_vector"):
        entry["cvss_vector"] = nvd_data["cvss_vector"]

    if nvd_data.get("severity"):
        entry["severity"] = str(nvd_data["severity"]).title()

    existing_cwe = entry.get("cwe", [])
    for c in nvd_data.get("cwe", []):
        if c not in existing_cwe:
            existing_cwe.append(c)
    entry["cwe"] = existing_cwe

    existing_refs = entry.get("references", [])
    for ref in nvd_data.get("references", []):
        if ref not in existing_refs:
            existing_refs.append(ref)
    entry["references"] = clean_references(existing_refs)

    return entry


def main():
    ap = argparse.ArgumentParser(description="Build or update local OPC UA CVE database JSON")
    ap.add_argument("--merge", help="Merge additional JSON CVE file into default DB")
    ap.add_argument("--enrich-nvd", action="store_true", help="Enrich entries from NVD API")
    ap.add_argument("--api-key", help="Optional NVD API key")
    ap.add_argument("--delay", type=float, default=6.0, help="Delay between NVD requests")
    ap.add_argument("--resume", action="store_true", help="Resume from existing data/opcua_cves.json")
    args = ap.parse_args()

    entries = list(DEFAULT_CVES)

    if args.merge:
        entries.extend(load_extra(args.merge))

    if args.resume:
        existing = load_existing_output(OUT)
        if existing:
            print(f"[*] Resuming from existing DB with {len(existing)} entries")
            entries.extend(existing)

    entries = merge_by_cve(entries)

    try:
        if args.enrich_nvd:
            print("[*] Enriching from NVD...")
            enriched = []

            for idx, item in enumerate(entries, start=1):
                cve_id = item.get("cve")
                print(f"[*] ({idx}/{len(entries)}) Querying NVD for {cve_id}")

                try:
                    nvd_data = fetch_nvd_with_retry(
                        cve_id,
                        api_key=args.api_key,
                        timeout=20,
                        retries=5,
                        base_delay=max(args.delay, 2.0)
                    )
                    item = enrich_entry(item, nvd_data)
                except Exception as e:
                    print(f"[!] Failed NVD lookup for {cve_id}: {e}")
                    item["references"] = clean_references(item.get("references", []))

                enriched.append(item)

                partial = merge_by_cve(enriched + entries[idx:])
                partial.sort(key=lambda x: x.get("cve", ""))
                for p in partial:
                    p["references"] = clean_references(p.get("references", []))
                atomic_write_json(OUT, partial)

                time.sleep(args.delay)

            entries = enriched

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user, saving current progress...")
        entries = merge_by_cve(entries)
        for item in entries:
            item["references"] = clean_references(item.get("references", []))
        atomic_write_json(OUT, entries)
        print(f"[+] Partial DB saved to {OUT}")
        return

    entries = merge_by_cve(entries)
    entries.sort(key=lambda x: x.get("cve", ""))

    for item in entries:
        item["references"] = clean_references(item.get("references", []))

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    atomic_write_json(OUT, entries)

    print(f"[+] Wrote {len(entries)} entries to {OUT}")


if __name__ == "__main__":
    main()
