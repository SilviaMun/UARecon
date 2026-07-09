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


def banner():
    print(f"""{RED}{BOLD}
╔══════════════════════════════════════════════════════════════╗
║             OpcPEAS v4.3 - OPC-UA Security Scanner          ║
║      Post-Auth Enumeration Tool + Modular CVE Engine        ║
╚══════════════════════════════════════════════════════════════╝{RESET}
""")


def section(t):
    print(f"\n{YELLOW}{BOLD}{'═' * 60}\n  {t}\n{'═' * 60}{RESET}")


def good(m):
    print(f"  {GREEN}[+]{RESET} {m}")


def bad(m):
    print(f"  {RED}[!]{RESET} {BOLD}{m}{RESET}")


def info(m):
    print(f"  {BLUE}[*]{RESET} {m}")


def warn(m):
    print(f"  {MAGENTA}[~]{RESET} {m}")
