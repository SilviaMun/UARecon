import os
import json
import datetime
from html import escape
from .banner import section, good, info

REPORT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")

SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4, "Unknown": 5}
SEV_COLORS = {
    "Critical": "#dc2626",
    "High": "#ea580c",
    "Medium": "#ca8a04",
    "Low": "#2563eb",
    "Info": "#6b7280",
    "Unknown": "#6b7280",
}


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


CAT_ICONS = {
    "Broken Authentication": "&#x1f513;",
    "Broken Access Control": "&#x1f6e1;",
    "Cryptographic Failures": "&#x1f510;",
    "Information Disclosure": "&#x1f441;",
    "Security Misconfiguration": "&#x2699;",
}


def _sev_badge(sev):
    color = SEV_COLORS.get(sev, "#6b7280")
    return f'<span class="badge" style="background:{color}">{escape(sev)}</span>'


def _risk_label(counts):
    if counts.get("Critical", 0):
        return "CRITICAL", "#dc2626"
    if counts.get("High", 0):
        return "HIGH", "#ea580c"
    if counts.get("Medium", 0):
        return "MEDIUM", "#ca8a04"
    if counts.get("Low", 0):
        return "LOW", "#2563eb"
    return "NONE", "#22c55e"


def _donut_css(counts, total):
    if total == 0:
        return "conic-gradient(#334155 0deg 360deg)"
    segments = []
    pos = 0
    for sev in ("Critical", "High", "Medium", "Low", "Info"):
        c = counts.get(sev, 0)
        if c:
            deg = round(c / total * 360)
            color = SEV_COLORS[sev]
            segments.append(f"{color} {pos}deg {pos + deg}deg")
            pos += deg
    if pos < 360:
        segments.append(f"#334155 {pos}deg 360deg")
    return "conic-gradient(" + ", ".join(segments) + ")"


def _build_html(rd):
    target = escape(rd.get("target", ""))
    scan_time = escape(rd.get("scan_time", ""))
    si = rd.get("server_info", {})
    vi = rd.get("vendor_info", {})

    findings = [f for f in rd.get("findings", []) if f.get("category")]
    findings.sort(key=lambda f: SEV_ORDER.get(f.get("severity", "Unknown"), 5))

    by_cat = {}
    for f in findings:
        by_cat.setdefault(f.get("category", "Other"), []).append(f)

    cves = rd.get("cve_matches", [])
    endpoints = rd.get("endpoints", [])

    counts = {}
    for f in findings:
        s = f.get("severity", "Unknown")
        counts[s] = counts.get(s, 0) + 1
    total_findings = len(findings)

    risk_label, risk_color = _risk_label(counts)
    donut = _donut_css(counts, total_findings)

    total_nodes = rd.get("total_nodes", 0)
    n_writable = len(rd.get("writable_nodes", []))
    n_methods = len(rd.get("method_nodes", []))

    product = escape(si.get("ProductName", vi.get("ProductName", "Unknown")))
    version = escape(si.get("SoftwareVersion", vi.get("SoftwareVersion", "")))
    manufacturer = escape(si.get("ManufacturerName", vi.get("ManufacturerName", "")))

    # --- stat cards ---
    stats_cards = ""
    for sev in ("Critical", "High", "Medium", "Low", "Info"):
        c = counts.get(sev, 0)
        color = SEV_COLORS[sev]
        opacity = "" if c else ' style="opacity:.3"'
        stats_cards += f'<div class="stat-card"{opacity}><div class="stat-num" style="color:{color}">{c}</div><div class="stat-label">{sev}</div></div>'

    # --- findings by category ---
    findings_html = ""
    cat_idx = 0
    for cat in sorted(by_cat.keys()):
        items = by_cat[cat]
        icon = CAT_ICONS.get(cat, "&#x26a0;")
        max_sev = items[0].get("severity", "Unknown") if items else "Unknown"
        findings_html += f'''<div class="cat-block">
<div class="cat-header" onclick="toggleCat({cat_idx})">
<span class="cat-icon">{icon}</span>
<span class="cat-title">{escape(cat)}</span>
<span class="cat-count">{len(items)} finding{"s" if len(items) != 1 else ""}</span>
{_sev_badge(max_sev)}
<span class="cat-arrow" id="arrow-{cat_idx}">&#x25BC;</span>
</div>
<div class="cat-body" id="cat-{cat_idx}">'''
        for f in items:
            sev = f.get("severity", "Unknown")
            title = escape(f.get("title", ""))
            desc = escape(f.get("description", ""))
            color = SEV_COLORS.get(sev, "#6b7280")
            slug = escape(f.get("check", ""))
            verify = f'<code class="verify">python3 uarecon.py -t {escape(rd.get("target","TARGET"))} --check {slug}</code>' if slug else ""
            findings_html += f'''<div class="finding" style="border-left:3px solid {color}">
<div class="finding-header">{_sev_badge(sev)} <strong>{title}</strong></div>
<p>{desc}</p>
{verify}
</div>'''
        findings_html += '</div></div>'
        cat_idx += 1

    # --- endpoints ---
    ep_html = ""
    if endpoints:
        ep_html = '<div class="section-block"><h2>&#x1f310; Endpoints</h2><div class="table-wrap"><table><thead><tr><th>URL</th><th>Security Policy</th><th>Mode</th><th>Tokens</th></tr></thead><tbody>'
        for ep in endpoints:
            pol = escape(ep.get("policy", ""))
            mode = escape(ep.get("mode", ""))
            url = escape(ep.get("url", ""))
            tokens = escape(", ".join(ep.get("tokens", [])))
            rc = ""
            if pol == "None" or mode == "None":
                rc = ' class="row-crit"'
            elif pol in ("Basic128Rsa15", "Basic256"):
                rc = ' class="row-warn"'
            ep_html += f'<tr{rc}><td><code>{url}</code></td><td>{pol}</td><td>{mode}</td><td>{tokens}</td></tr>'
        ep_html += '</tbody></table></div></div>'

    # --- CVEs ---
    cve_html = ""
    if cves:
        cve_html = '<div class="section-block"><h2>&#x1f6a8; CVE Matches</h2><div class="table-wrap"><table><thead><tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Description</th></tr></thead><tbody>'
        for c in cves:
            cve_id = escape(c.get("cve", ""))
            sev = c.get("severity", "Unknown")
            score = c.get("cvss_score")
            score_str = f"{score}" if score else "-"
            title = escape(c.get("title", "")[:120])
            cve_html += f'<tr><td><strong>{cve_id}</strong></td><td>{_sev_badge(sev)}</td><td>{score_str}</td><td>{title}</td></tr>'
        cve_html += '</tbody></table></div></div>'

    # --- server info ---
    server_html = ""
    all_info = {**si, **vi}
    if all_info:
        server_html = '<div class="section-block"><h2>&#x1f5a5; Server Details</h2><div class="info-grid">'
        for k, v in all_info.items():
            server_html += f'<div class="info-item"><div class="info-key">{escape(str(k))}</div><div class="info-val">{escape(str(v))}</div></div>'
        server_html += '</div></div>'

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>UARecon &mdash; {target}</title>
<style>
:root{{--bg:#0a0e1a;--card:#111827;--card2:#1e293b;--border:#1e293b;--text:#e2e8f0;--muted:#64748b;--accent:#a78bfa}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;min-height:100vh}}
.wrap{{max-width:1040px;margin:0 auto;padding:32px 24px}}

/* header */
.header{{background:linear-gradient(135deg,#1e1b4b 0%,#0f172a 100%);border:1px solid #312e81;border-radius:16px;padding:32px;margin-bottom:28px;position:relative;overflow:hidden}}
.header::before{{content:"";position:absolute;top:-50%;right:-20%;width:300px;height:300px;background:radial-gradient(circle,rgba(139,92,246,.08) 0%,transparent 70%);pointer-events:none}}
.header-top{{display:flex;align-items:center;gap:16px;margin-bottom:16px}}
.logo{{width:44px;height:44px;background:linear-gradient(135deg,#7c3aed,#a78bfa);border-radius:12px;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:18px;color:#fff;flex-shrink:0}}
.header h1{{font-size:1.6rem;color:#f8fafc;font-weight:700;letter-spacing:-.02em}}
.header h1 span{{color:var(--accent);font-weight:400}}
.meta{{display:flex;gap:24px;flex-wrap:wrap}}
.meta-item{{font-size:.85rem;color:var(--muted)}}
.meta-item strong{{color:var(--text)}}

/* overview row */
.overview{{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:28px}}
@media(max-width:700px){{.overview{{grid-template-columns:1fr}}}}

.risk-card{{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:24px;display:flex;align-items:center;gap:24px}}
.donut-wrap{{position:relative;width:110px;height:110px;flex-shrink:0}}
.donut{{width:110px;height:110px;border-radius:50%;background:{donut}}}
.donut-hole{{position:absolute;top:18px;left:18px;width:74px;height:74px;border-radius:50%;background:var(--card);display:flex;flex-direction:column;align-items:center;justify-content:center}}
.donut-num{{font-size:1.6rem;font-weight:800;color:{risk_color}}}
.donut-label{{font-size:.6rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}}
.risk-text h3{{font-size:.75rem;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin-bottom:4px}}
.risk-level{{font-size:1.4rem;font-weight:800;color:{risk_color}}}
.risk-sub{{font-size:.8rem;color:var(--muted);margin-top:4px}}

.stats-card{{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:24px}}
.stats-card h3{{font-size:.75rem;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin-bottom:14px}}
.stat-row{{display:flex;gap:8px;flex-wrap:wrap}}
.stat-card{{flex:1;min-width:72px;background:var(--bg);border-radius:10px;padding:12px;text-align:center}}
.stat-num{{font-size:1.5rem;font-weight:800}}
.stat-label{{font-size:.65rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}}

/* kpi row */
.kpi-row{{display:flex;gap:12px;margin-bottom:28px;flex-wrap:wrap}}
.kpi{{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px 20px;flex:1;min-width:120px}}
.kpi-num{{font-size:1.2rem;font-weight:700;color:var(--accent)}}
.kpi-label{{font-size:.7rem;color:var(--muted);text-transform:uppercase}}

/* section blocks */
.section-block{{margin-bottom:24px}}
h2{{color:#f8fafc;font-size:1.1rem;margin-bottom:14px;padding-bottom:10px;border-bottom:1px solid var(--border)}}

/* category accordion */
.cat-block{{margin-bottom:10px}}
.cat-header{{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:14px 20px;display:flex;align-items:center;gap:12px;cursor:pointer;transition:background .15s}}
.cat-header:hover{{background:var(--card2)}}
.cat-icon{{font-size:1.2rem}}
.cat-title{{font-weight:600;flex:1}}
.cat-count{{font-size:.8rem;color:var(--muted)}}
.cat-arrow{{font-size:.7rem;color:var(--muted);transition:transform .2s}}
.cat-arrow.collapsed{{transform:rotate(-90deg)}}
.cat-body{{padding:8px 0 0 20px}}
.cat-body.hidden{{display:none}}

/* finding */
.finding{{background:var(--card);border-radius:10px;padding:14px 18px;margin-bottom:8px;transition:transform .1s}}
.finding:hover{{transform:translateX(4px)}}
.finding-header{{margin-bottom:6px;display:flex;align-items:center;gap:8px}}
.finding p{{color:var(--muted);font-size:.82rem;line-height:1.5}}

.badge{{display:inline-block;padding:2px 10px;border-radius:6px;color:#fff;font-size:.7rem;font-weight:700;letter-spacing:.03em;vertical-align:middle;white-space:nowrap}}

/* tables */
.table-wrap{{overflow-x:auto;border-radius:10px;border:1px solid var(--border)}}
table{{width:100%;border-collapse:collapse;font-size:.82rem}}
thead th{{background:var(--card2);color:#f8fafc;text-align:left;padding:10px 14px;font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.05em}}
td{{padding:10px 14px;border-top:1px solid var(--border)}}
tbody tr{{transition:background .1s}}
tbody tr:hover{{background:rgba(255,255,255,.02)}}
.row-crit{{background:rgba(220,38,38,.08)}}
.row-crit:hover{{background:rgba(220,38,38,.14)!important}}
.row-warn{{background:rgba(234,88,12,.06)}}
.row-warn:hover{{background:rgba(234,88,12,.12)!important}}
code{{font-size:.82rem;color:var(--accent)}}
.verify{{display:block;margin-top:8px;padding:6px 10px;background:var(--bg);border:1px solid var(--border);border-radius:6px;font-size:.75rem;color:var(--muted);word-break:break-all}}

/* info grid */
.info-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:10px}}
.info-item{{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:12px 16px}}
.info-key{{font-size:.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-bottom:2px}}
.info-val{{font-size:.9rem;font-weight:600;word-break:break-all}}

footer{{text-align:center;color:var(--muted);font-size:.75rem;margin-top:40px;padding:20px 0;border-top:1px solid var(--border)}}
footer a{{color:var(--accent);text-decoration:none}}
</style>
</head>
<body>
<div class="wrap">

<div class="header">
<div class="header-top">
<div class="logo">UA</div>
<h1>UARecon <span>Report</span></h1>
</div>
<div class="meta">
<div class="meta-item">Target: <strong>{target}</strong></div>
<div class="meta-item">Scan: <strong>{scan_time}</strong></div>
<div class="meta-item">Product: <strong>{product} {version}</strong></div>
{f'<div class="meta-item">Vendor: <strong>{manufacturer}</strong></div>' if manufacturer else ''}
</div>
</div>

<div class="overview">
<div class="risk-card">
<div class="donut-wrap"><div class="donut"></div><div class="donut-hole"><div class="donut-num">{total_findings}</div><div class="donut-label">findings</div></div></div>
<div class="risk-text">
<h3>Overall Risk</h3>
<div class="risk-level">{risk_label}</div>
<div class="risk-sub">{counts.get("Critical",0)} critical &middot; {counts.get("High",0)} high &middot; {counts.get("Medium",0)} medium</div>
</div>
</div>
<div class="stats-card">
<h3>Severity Breakdown</h3>
<div class="stat-row">{stats_cards}</div>
</div>
</div>

<div class="kpi-row">
<div class="kpi"><div class="kpi-num">{len(endpoints)}</div><div class="kpi-label">Endpoints</div></div>
<div class="kpi"><div class="kpi-num">{total_nodes}</div><div class="kpi-label">Nodes</div></div>
<div class="kpi"><div class="kpi-num">{n_writable}</div><div class="kpi-label">Writable</div></div>
<div class="kpi"><div class="kpi-num">{n_methods}</div><div class="kpi-label">Methods</div></div>
<div class="kpi"><div class="kpi-num">{len(cves)}</div><div class="kpi-label">CVEs</div></div>
</div>

<div class="section-block">
<h2>&#x1f50d; Findings by Category</h2>
{findings_html}
</div>

{ep_html}
{cve_html}
{server_html}

<footer>Generated by <strong>UARecon</strong> &mdash; OPC UA Security Assessment Toolkit</footer>
</div>

<script>
function toggleCat(i){{
  var b=document.getElementById("cat-"+i);
  var a=document.getElementById("arrow-"+i);
  b.classList.toggle("hidden");
  a.classList.toggle("collapsed");
}}
</script>
</body>
</html>'''


def save_report(report_data, output_file=None):
    section("REPORT")
    os.makedirs(REPORT_DIR, exist_ok=True)
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')

    if output_file:
        json_path = output_file
    else:
        json_path = os.path.join(REPORT_DIR, f"uarecon_report_{ts}.json")

    html_path = json_path.rsplit(".", 1)[0] + ".html"

    with open(json_path, "w") as f:
        json.dump(report_data, f, indent=2, default=str)

    with open(html_path, "w") as f:
        f.write(_build_html(report_data))

    good(f"JSON: {json_path}")
    good(f"HTML: {html_path}")
    info(
        f"Nodes: {report_data['total_nodes']} | "
        f"Writable: {len(report_data['writable_nodes'])} | "
        f"Methods: {len(report_data['method_nodes'])} | "
        f"Interesting: {len(report_data['interesting_values'])} | "
        f"CVE matches: {len(report_data['cve_matches'])}"
    )
