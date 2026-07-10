#!/usr/bin/env python3
"""
Fetch OPC UA security advisories from the OPC Foundation CSAF repository
and build the local CVE database for UARecon.

Source: https://github.com/OPCFoundation/OPC-SecurityAdvisories/tree/latest/csaf

Parses CSAF JSON where available; for PDF-only advisories, extracts CVE ID
from the filename and enriches via NVD API.
"""
import os
import re
import json
import time
import argparse
import requests

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
OUT = os.path.join(BASE_DIR, "data", "opcua_cves.json")

GITHUB_API_TREE = "https://api.github.com/repos/OPCFoundation/OPC-SecurityAdvisories/git/trees/latest"
RAW_BASE = "https://raw.githubusercontent.com/OPCFoundation/OPC-SecurityAdvisories/latest"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

CVE_RE = re.compile(r"CVE-\d{4}-\d+")
VERSION_RE = re.compile(r"(\d+(?:\.\d+)+)")


PRODUCT_TAGS = {
    ".net standard": "dotnet",
    "ua-.net": "dotnet",
    ".net legacy": "dotnet-legacy",
    "local discovery server": "lds",
    " lds ": "lds",
    "lds-": "lds",
    "lds.": "lds",
    "java stack": "java",
    "java legacy": "java",
    "ansi c": "ansi-c",
    "c-stack": "ansi-c",
    "specification": "spec",
}


def classify_product(text):
    low = text.lower()
    for pattern, tag in PRODUCT_TAGS.items():
        if pattern in low:
            return tag
    return "generic"


def parse_fixed_version(remediation_text):
    if not remediation_text:
        return None
    m = VERSION_RE.search(remediation_text)
    return m.group(1) if m else None


def parse_affected_version(product_name):
    if not product_name:
        return None
    m = re.search(r"<\s*(\d+(?:\.\d+)+)", product_name)
    if m:
        return m.group(1)
    return None


def list_repo_tree(timeout=15):
    resp = requests.get(GITHUB_API_TREE, params={"recursive": "1"}, timeout=timeout)
    resp.raise_for_status()
    return resp.json().get("tree", [])


def scan_advisories(tree):
    csaf_json = []
    pdf_only_cves = {}

    dirs = {}
    for item in tree:
        path = item["path"]
        if not path.startswith("csaf/"):
            continue
        parts = path.split("/")
        if len(parts) >= 3:
            dir_key = "/".join(parts[:3])
            dirs.setdefault(dir_key, []).append(path)

    for dir_key, files in dirs.items():
        jsons = [f for f in files if f.endswith(".json") and not f.endswith((".asc", ".sha512"))]
        csaf_jsons = [f for f in jsons if "CSAF" in f.split("/")[-1]]

        if csaf_jsons:
            csaf_json.extend(csaf_jsons)
        else:
            pdfs = [f for f in files if f.endswith(".pdf")]
            for pdf in pdfs:
                m = CVE_RE.search(pdf)
                if m:
                    cve_id = m.group(0)
                    encoded_name = requests.utils.quote(pdf.split("/")[-1])
                    pdf_url = f"https://files.opcfoundation.org/SecurityBulletins/{encoded_name}"
                    pdf_only_cves[cve_id] = pdf_url

    return csaf_json, pdf_only_cves


def fetch_csaf(path, timeout=15):
    url = f"{RAW_BASE}/{path}"
    resp = requests.get(url, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def extract_products(product_tree):
    products = []

    def walk_branches(branches):
        for branch in branches:
            prod = branch.get("product")
            if prod:
                products.append(prod.get("name", ""))
            walk_branches(branch.get("branches", []))

    walk_branches(product_tree.get("branches", []))
    return products


def parse_csaf(data):
    entries = []
    doc = data.get("document", {})
    product_tree = data.get("product_tree", {})
    product_names = extract_products(product_tree)

    for vuln in data.get("vulnerabilities", []):
        cve_id = vuln.get("cve")
        gcve_id = None
        for alt_id in vuln.get("ids", []):
            if alt_id.get("system_name") == "GCVE":
                gcve_id = alt_id.get("text")

        identifier = cve_id or gcve_id
        if not identifier:
            continue

        title = vuln.get("title") or doc.get("title", "")
        if title == "TBA":
            title = doc.get("title", identifier)

        cvss_score = None
        cvss_vector = None
        severity = None
        for score_block in vuln.get("scores", []):
            cvss = score_block.get("cvss_v3", {})
            cvss_score = cvss.get("baseScore")
            cvss_vector = cvss.get("vectorString")
            raw_sev = cvss.get("baseSeverity", "")
            severity = raw_sev.capitalize() if raw_sev else None
            break

        cwe_list = []
        cwe_data = vuln.get("cwe")
        if isinstance(cwe_data, dict) and cwe_data.get("id"):
            cwe_list.append(cwe_data["id"])

        refs = []
        for ref in vuln.get("references", []):
            url = ref.get("url")
            if url:
                refs.append(url)
        for ref in doc.get("references", []):
            url = ref.get("url")
            if url and url not in refs:
                refs.append(url)

        description_parts = []
        for threat in vuln.get("threats", []):
            details = threat.get("details", "")
            if details:
                description_parts.append(details)
        for note in vuln.get("notes", []):
            text = note.get("text", "")
            if text:
                description_parts.append(text)
        description = " ".join(description_parts) if description_parts else title

        affected = ", ".join(product_names) if product_names else "OPC UA implementation"

        fixed_text = None
        for rem in vuln.get("remediations", []):
            if rem.get("category") == "vendor_fix":
                fixed_text = rem.get("details", "")
                break

        fixed_version = parse_fixed_version(fixed_text)
        if not fixed_version and product_names:
            fixed_version = parse_affected_version(product_names[0])

        product_tag = classify_product(affected) or classify_product(title)

        entry = {
            "cve": identifier,
            "title": title,
            "vendor": "OPC Foundation",
            "product": product_names[0] if product_names else "OPC UA",
            "product_tag": product_tag,
            "affected": affected,
            "fixed": fixed_text,
            "fixed_version": fixed_version,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "severity": severity or "Unknown",
            "cwe": cwe_list,
            "protocol_generic": product_tag == "spec",
            "references": refs,
            "description": description,
            "source": "OPCFoundation/OPC-SecurityAdvisories (CSAF)",
        }

        entries.append(entry)

    return entries


def fetch_nvd(cve_id, api_key=None, timeout=20):
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    resp = requests.get(NVD_API, params={"cveId": cve_id}, headers=headers, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None

    cve = vulns[0].get("cve", {})
    metrics = cve.get("metrics", {})

    score = None
    vector = None
    severity = None
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and metrics[key]:
            cvss_data = metrics[key][0].get("cvssData", {})
            score = cvss_data.get("baseScore")
            vector = cvss_data.get("vectorString")
            severity = metrics[key][0].get("baseSeverity") or cvss_data.get("baseSeverity")
            break

    cwes = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            val = d.get("value")
            if val and val not in cwes and val != "NVD-CWE-noinfo":
                cwes.append(val)

    refs = []
    for ref in cve.get("references", []):
        url = ref.get("url")
        if url and url not in refs:
            refs.append(url)

    title = None
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            title = d.get("value")
            break

    return {
        "title": title,
        "cvss_score": score,
        "cvss_vector": vector,
        "severity": str(severity).capitalize() if severity else None,
        "cwe": cwes,
        "references": refs,
    }


def build_entry_from_nvd(cve_id, pdf_url, nvd_data):
    title = cve_id
    severity = "Unknown"
    cvss_score = None
    cvss_vector = None
    cwe_list = []
    refs = [pdf_url]
    description = ""
    product_tag = "generic"

    if nvd_data:
        title = nvd_data.get("title") or cve_id
        severity = nvd_data.get("severity") or "Unknown"
        cvss_score = nvd_data.get("cvss_score")
        cvss_vector = nvd_data.get("cvss_vector")
        cwe_list = nvd_data.get("cwe", [])
        description = nvd_data.get("title") or ""
        for r in nvd_data.get("references", []):
            if r not in refs:
                refs.append(r)
        product_tag = classify_product(title)

    fixed_version = None
    if title:
        m = re.search(r"(?:before|prior to|fixed in)\s+(?:version\s+)?(\d+(?:\.\d+)+)", title, re.IGNORECASE)
        if m:
            fixed_version = m.group(1)

    return {
        "cve": cve_id,
        "title": title[:200] if title else cve_id,
        "vendor": "OPC Foundation",
        "product": "OPC UA",
        "product_tag": product_tag,
        "affected": description[:200] if description else "See advisory PDF",
        "fixed": None,
        "fixed_version": fixed_version,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "severity": severity,
        "cwe": cwe_list,
        "protocol_generic": product_tag in ("spec", "generic"),
        "references": refs,
        "description": description[:500] if description else "",
        "source": "OPCFoundation/OPC-SecurityAdvisories (PDF + NVD)",
    }


def main():
    ap = argparse.ArgumentParser(
        description="Fetch OPC Foundation CSAF advisories and build UARecon CVE database"
    )
    ap.add_argument("--timeout", type=int, default=15, help="HTTP request timeout")
    ap.add_argument("--api-key", help="NVD API key (optional, avoids rate limits)")
    ap.add_argument("--delay", type=float, default=6.0, help="Delay between NVD requests")
    ap.add_argument("--out", default=OUT, help="Output path")
    args = ap.parse_args()

    print("[*] Scanning OPC-SecurityAdvisories repo...")
    tree = list_repo_tree(timeout=args.timeout)
    csaf_paths, pdf_only = scan_advisories(tree)
    print(f"[*] Found {len(csaf_paths)} CSAF JSON file(s) + {len(pdf_only)} PDF-only advisory(ies)")

    all_entries = []

    print("\n── CSAF JSON advisories ──")
    for path in csaf_paths:
        print(f"[*] Fetching {path}")
        try:
            data = fetch_csaf(path, timeout=args.timeout)
            entries = parse_csaf(data)
            all_entries.extend(entries)
            for e in entries:
                print(f"  [+] {e['cve']}: {e['title']} [tag={e['product_tag']}, fixed={e['fixed_version']}]")
        except Exception as e:
            print(f"  [!] Failed: {e}")

    csaf_cves = {e["cve"] for e in all_entries}
    pdf_only = {k: v for k, v in pdf_only.items() if k not in csaf_cves}

    if pdf_only:
        print(f"\n── PDF-only advisories (enriching via NVD) ──")
        delay = max(args.delay, 1.0)
        for i, (cve_id, pdf_url) in enumerate(sorted(pdf_only.items())):
            print(f"[*] ({i+1}/{len(pdf_only)}) {cve_id}")
            nvd_data = None
            try:
                nvd_data = fetch_nvd(cve_id, api_key=args.api_key, timeout=args.timeout)
            except requests.HTTPError as e:
                status = getattr(e.response, "status_code", None)
                if status in (403, 429):
                    print(f"  [!] Rate limited, waiting {delay*2:.0f}s...")
                    time.sleep(delay * 2)
                    try:
                        nvd_data = fetch_nvd(cve_id, api_key=args.api_key, timeout=args.timeout)
                    except Exception:
                        print(f"  [!] Retry failed for {cve_id}")
                else:
                    print(f"  [!] NVD error: {e}")
            except Exception as e:
                print(f"  [!] NVD lookup failed: {e}")

            entry = build_entry_from_nvd(cve_id, pdf_url, nvd_data)
            all_entries.append(entry)
            print(f"  [+] [{entry['severity']}] tag={entry['product_tag']}, fixed={entry['fixed_version']}")

            if i < len(pdf_only) - 1:
                time.sleep(delay)

    seen = {}
    for entry in all_entries:
        seen[entry["cve"]] = entry
    all_entries = sorted(seen.values(), key=lambda x: x["cve"])

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(all_entries, f, indent=2)

    tags = {}
    for e in all_entries:
        tags.setdefault(e["product_tag"], []).append(e["cve"])

    print(f"\n[+] Wrote {len(all_entries)} entries to {args.out}")
    print("[*] Product tags:")
    for tag, cves in sorted(tags.items()):
        print(f"    {tag}: {len(cves)} CVE(s)")


if __name__ == "__main__":
    main()
