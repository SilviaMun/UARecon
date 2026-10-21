RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def set_no_color():
    global RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, BOLD, RESET
    RED = ""
    GREEN = ""
    YELLOW = ""
    BLUE = ""
    MAGENTA = ""
    CYAN = ""
    BOLD = ""
    RESET = ""


def _gradient(text_lines, offset=0):
    colors = [
        (66, 133, 244), (56, 152, 236), (46, 171, 220),
        (38, 190, 200), (32, 206, 176), (30, 220, 150),
        (34, 232, 120), (44, 240, 96), (58, 246, 78),
    ]
    out = []
    for row, line in enumerate(text_lines):
        colored = []
        for col, ch in enumerate(line):
            if ch == " " or ch == "\n":
                colored.append(ch)
            else:
                idx = ((col + row * 3 + offset) / 3) % len(colors)
                i = int(idx)
                t = idx - i
                r1, g1, b1 = colors[i]
                r2, g2, b2 = colors[(i + 1) % len(colors)]
                r = int(r1 + (r2 - r1) * t)
                g = int(g1 + (g2 - g1) * t)
                b = int(b1 + (b2 - b1) * t)
                colored.append(f"\033[1;38;2;{r};{g};{b}m{ch}")
        out.append("".join(colored))
    return "\n".join(out) + RESET


def banner():
    from uarecon import __version__
    art = [
        r" _   _   _    ____                       ",
        r"| | | | / \  |  _ \ ___  ___ ___  _ __   ",
        r"| | | |/ _ \ | |_) / _ \/ __/ _ \| '_ \  ",
        r"| |_| / ___ \|  _ <  __/ (_| (_) | | | | ",
        r" \___/_/   \_\_| \_\___|\___\___/|_| |_| ",
    ]
    print()
    print(_gradient(art))
    print(f"  {BLUE}v{__version__} — OPC UA Security Assessment Toolkit{RESET}")
    print(f"              {MAGENTA}@Chef.S{RESET}")
    print()


def phase(t):
    print(f"\n{GREEN}{BOLD}{'━' * 60}")
    print(f"  {t}")
    print(f"{'━' * 60}{RESET}")


def section(t):
    print(f"\n  {BLUE}{BOLD}── {t} ──{RESET}")


def good(m):
    print(f"  {GREEN}[+]{RESET} {m}")


def critical(m):
    print(f"  {RED}{BOLD}[!!!] {m}{RESET}")


def bad(m):
    print(f"  {RED}{BOLD}[!] {m}{RESET}")


def info(m):
    print(f"  {BLUE}[*]{RESET} {m}")


def warn(m):
    print(f"  {YELLOW}[~] {m}{RESET}")


def tag(category):
    print(f"      {MAGENTA}↳ {category}{RESET}")



def vuln_recap(findings, target=None, report_data=None):
    vulns = [f for f in findings if f.get("category")]
    if not vulns:
        return

    actionable = [f for f in vulns if not f.get("observation")]
    observations = [f for f in vulns if f.get("observation")]

    phase_fn = globals().get("phase")

    # --- Connection context ---
    if report_data and report_data.get("connection_context"):
        ctx = report_data["connection_context"]
        if phase_fn:
            phase_fn("SCAN CONTEXT")
        print(f"  {BLUE}Connection strategy:{RESET} {ctx.get('strategy', '?')}")
        print(f"  {BLUE}Security:{RESET} {ctx.get('policy', '?')}/{ctx.get('mode', '?')}")
        print(f"  {BLUE}Client certificate:{RESET} {ctx.get('cert_type', '?')}")
        print(f"  {BLUE}User authentication:{RESET} {ctx.get('user_auth', '?')}")

    # --- Actionable findings by IEC 62443 FR ---
    if phase_fn:
        phase_fn("FINDINGS — IEC 62443 POSTURE")

    if not actionable:
        print(f"\n  {GREEN}No actionable findings.{RESET}")
    else:
        by_fr = {}
        for f in actionable:
            frs = f.get("iec62443", [])
            if not frs:
                frs = ["Uncategorized"]
            for fr in frs:
                by_fr.setdefault(fr, []).append(f)

        seen_titles = set()
        for fr in sorted(by_fr.keys()):
            items = by_fr[fr]
            print(f"\n  {MAGENTA}{BOLD}{fr}{RESET}")
            for f in items:
                title = f.get("title", "")
                if title in seen_titles:
                    continue
                seen_titles.add(title)
                sev = f.get("severity", "")
                if sev == "Critical":
                    print(f"    {RED}{BOLD}[{sev}]{RESET} {title}")
                elif sev == "High":
                    print(f"    {RED}[{sev}]{RESET} {title}")
                elif sev == "Medium":
                    print(f"    {YELLOW}[{sev}]{RESET} {title}")
                else:
                    print(f"    {BLUE}[{sev}]{RESET} {title}")
                desc = f.get("description", "")
                if desc:
                    short = desc if len(desc) <= 120 else desc[:117] + "..."
                    print(f"      {short}")
                opcua = f.get("opcua_security", [])
                if opcua:
                    print(f"      {CYAN}OPC UA: {', '.join(opcua)}{RESET}")
                slug = f.get("check", "")
                if slug and target:
                    print(f"      {CYAN}⟶ python3 uarecon.py -t {target} --check {slug}{RESET}")

    # --- Observations (muted) ---
    if observations:
        confirmed = [f for f in observations if "No Issues Found" in f.get("title", "")]
        other_obs = [f for f in observations if "No Issues Found" not in f.get("title", "")]

        if other_obs:
            print(f"\n  {BLUE}{BOLD}── OBSERVATIONS ({len(other_obs)}) ──{RESET}")
            for f in other_obs:
                title = f.get("title", "")
                print(f"    {BLUE}[Info]{RESET} {title}")

        if confirmed:
            print(f"\n  {GREEN}{BOLD}── CONTROLS VERIFIED ({len(confirmed)}) ──{RESET}")
            for f in confirmed:
                title = f.get("title", "").replace(": No Issues Found", "")
                print(f"    {GREEN}[OK]{RESET} {title}")

    # --- FR posture summary ---
    fr_labels = [
        "FR1 – Identification & Authentication",
        "FR2 – Use Control",
        "FR3 – System Integrity",
        "FR4 – Data Confidentiality",
        "FR5 – Restricted Data Flow",
        "FR6 – Timely Response to Events",
        "FR7 – Resource Availability",
    ]

    all_with_fr = actionable + observations
    if phase_fn:
        phase_fn("IEC 62443 POSTURE SUMMARY")
    for fr in fr_labels:
        fr_findings = [f for f in all_with_fr if fr in f.get("iec62443", [])]
        fr_actionable = [f for f in fr_findings if not f.get("observation")]
        fr_confirmed = [f for f in fr_findings
                        if f.get("observation") and "No Issues Found" in f.get("title", "")]
        fr_obs = [f for f in fr_findings
                  if f.get("observation") and "No Issues Found" not in f.get("title", "")]

        if not fr_findings:
            print(f"  {BLUE}[—]{RESET} {fr}: not assessed")
            continue

        worst = "OK"
        color = GREEN
        for f in fr_actionable:
            s = f.get("severity", "")
            if s == "Critical":
                worst, color = "CRITICAL", RED
                break
            elif s == "High" and worst not in ("CRITICAL",):
                worst, color = "HIGH", RED
            elif s == "Medium" and worst in ("OK", "LOW"):
                worst, color = "MEDIUM", YELLOW
            elif s == "Low" and worst == "OK":
                worst, color = "LOW", BLUE

        parts = []
        if fr_actionable:
            parts.append(f"{len(fr_actionable)} finding(s)")
        if fr_obs:
            parts.append(f"{len(fr_obs)} obs")
        if fr_confirmed:
            parts.append(f"{len(fr_confirmed)} verified")
        detail = " | ".join(parts) if parts else "no data"

        print(f"  {color}[{worst}]{RESET} {fr}: {detail}")

    # --- Totals ---
    crits = sum(1 for f in actionable if f.get("severity") == "Critical")
    highs = sum(1 for f in actionable if f.get("severity") == "High")
    meds = sum(1 for f in actionable if f.get("severity") == "Medium")
    lows = sum(1 for f in actionable if f.get("severity") in ("Low", "Info"))
    print(f"\n  {BOLD}Findings: {len(actionable)} — "
          f"{RED}{crits} Critical{RESET}{BOLD}, "
          f"{RED}{highs} High{RESET}{BOLD}, "
          f"{YELLOW}{meds} Medium{RESET}{BOLD}, "
          f"{BLUE}{lows} Low/Info{RESET}{BOLD} "
          f"| Observations: {len(observations)}{RESET}")
