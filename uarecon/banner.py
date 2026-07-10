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
    print(f"              {MAGENTA}@SilviaMun (Chef.S){RESET}")
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



def vuln_recap(findings, target=None):
    vulns = [f for f in findings if f.get("category")]
    if not vulns:
        return

    phase_fn = globals().get("phase")
    if phase_fn:
        phase_fn("VULNERABILITY SUMMARY")

    by_cat = {}
    for f in vulns:
        cat = f["category"]
        by_cat.setdefault(cat, []).append(f)

    for cat, items in sorted(by_cat.items()):
        print(f"\n  {MAGENTA}{BOLD}{cat}{RESET}")
        for f in items:
            sev = f.get("severity", "")
            title = f.get("title", "")
            if sev in ("Critical",):
                print(f"    {RED}{BOLD}[{sev}]{RESET} {title}")
            elif sev in ("High",):
                print(f"    {RED}[{sev}]{RESET} {title}")
            elif sev in ("Medium",):
                print(f"    {YELLOW}[{sev}]{RESET} {title}")
            else:
                print(f"    {BLUE}[{sev}]{RESET} {title}")
            desc = f.get("description", "")
            if desc:
                short = desc if len(desc) <= 120 else desc[:117] + "..."
                print(f"      {short}")

            slug = f.get("check", "")
            if slug and target:
                print(f"      {CYAN}⟶ python3 uarecon.py -t {target} --check {slug}{RESET}")

    total = len(vulns)
    crits = sum(1 for f in vulns if f.get("severity") == "Critical")
    highs = sum(1 for f in vulns if f.get("severity") == "High")
    meds = sum(1 for f in vulns if f.get("severity") == "Medium")
    lows = sum(1 for f in vulns if f.get("severity") in ("Low", "Info"))
    print(f"\n  {BOLD}Total: {total} finding(s) — "
          f"{RED}{crits} Critical{RESET}{BOLD}, "
          f"{RED}{highs} High{RESET}{BOLD}, "
          f"{YELLOW}{meds} Medium{RESET}{BOLD}, "
          f"{BLUE}{lows} Low/Info{RESET}")
