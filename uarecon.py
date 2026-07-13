#!/usr/bin/env python3
import os
import sys
import time
import logging
import datetime
import argparse

logging.getLogger("asyncua").setLevel(logging.CRITICAL + 1)
logging.getLogger("asyncio").setLevel(logging.CRITICAL + 1)

from uarecon import __version__
from uarecon.banner import banner, set_no_color, phase, section, bad, good, info, vuln_recap
from uarecon.report import reset_report, save_report
from uarecon.connection import try_connect
from uarecon.enumeration import (
    enum_endpoints,
    enum_server_info,
    enum_namespaces,
    enum_sessions,
    enum_security_diag,
    enum_capabilities,
    enum_vendor_info,
    enum_objects_deep,
)
from uarecon.cve import load_cve_db, list_all_cves, check_cves
from uarecon.security_checks import (
    check_anonymous_access, check_default_credentials, check_bruteforce,
    check_provided_credentials,
    run_security_checks, CHECK_CATALOG, run_check_by_slug,
    FAMILY_ALIASES, FAMILY_ALIAS_REVERSE, PRE_AUTH_SLUGS, FAMILY_AUTHENTICATION,
)


def parse_args():
    p = argparse.ArgumentParser(
        prog="uarecon",
        description=f"UARecon v{__version__} — OPC UA Enumeration Toolkit"
    )
    p.add_argument("-t", "--target", help="OPC-UA target")
    p.add_argument("-u", "--user", help="Username")
    p.add_argument("-p", "--password", help="Password")
    p.add_argument("-c", "--cert", help="Client certificate PEM")
    p.add_argument("-k", "--key", help="Client private key PEM")
    p.add_argument("--uri", default="urn:UARecon", help="Application URI")
    p.add_argument(
        "--policy",
        default="Basic256Sha256",
        choices=["Basic256Sha256", "Aes128Sha256RsaOaep", "Aes256Sha256RsaPss"],
    )
    p.add_argument("--mode", default="Sign", choices=["Sign", "SignAndEncrypt"])
    p.add_argument("--timeout", type=int, default=5, help="Connection timeout")
    p.add_argument("--endpoints-only", action="store_true")
    p.add_argument("--cve-only", action="store_true")
    p.add_argument("--deep-only", action="store_true")
    p.add_argument("--sessions-only", action="store_true")
    p.add_argument("--list-cves", action="store_true")
    p.add_argument("--skip-endpoints", action="store_true")
    p.add_argument("--skip-server", action="store_true")
    p.add_argument("--skip-namespaces", action="store_true")
    p.add_argument("--skip-sessions", action="store_true")
    p.add_argument("--skip-security", action="store_true")
    p.add_argument("--skip-capabilities", action="store_true")
    p.add_argument("--skip-vendor", action="store_true")
    p.add_argument("--skip-deep", action="store_true")
    p.add_argument("--skip-cve", action="store_true")
    p.add_argument("--skip-security-checks", action="store_true")
    p.add_argument("--prod", action="store_true",
                   help="Production-safe mode: skip destructive checks (write, method calls, resource abuse)")
    p.add_argument("--check", nargs="+", metavar="SLUG",
                   help="Run only specific check(s) by slug (see --list-checks)")
    p.add_argument("--family", nargs="+", metavar="FAMILY",
                   choices=list(FAMILY_ALIASES.keys()),
                   help="Run only checks from specified families: "
                        + ", ".join(sorted(FAMILY_ALIASES.keys())))
    p.add_argument("--list-checks", action="store_true",
                   help="Show all available security checks and exit")
    p.add_argument("--wordlist", metavar="FILE",
                   help="Username wordlist for brute-force (one per line)")
    p.add_argument("--passlist", metavar="FILE",
                   help="Password wordlist for brute-force (one per line)")
    p.add_argument("--delay", type=float, default=None, metavar="SEC",
                   help="Delay between checks in seconds (default: 0, --prod default: 1.0)")
    p.add_argument("--depth", type=int, default=8)
    p.add_argument("-o", "--output", help="Output JSON filename")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("--no-color", action="store_true")
    return p.parse_args()


def main():
    args = parse_args()

    if args.no_color:
        set_no_color()

    cve_db = load_cve_db()

    if args.list_checks:
        if not args.quiet:
            banner()
        selected_families = None
        if args.family:
            selected_families = {FAMILY_ALIASES[a] for a in args.family}
        current_family = None
        shown = 0
        for slug, label, cat, testing_only, _req, family in CHECK_CATALOG:
            if selected_families and family not in selected_families:
                continue
            if family != current_family:
                current_family = family
                alias = FAMILY_ALIAS_REVERSE.get(family, "")
                header = f"{family}  (--family {alias})" if alias else family
                print(f"\n  [{header}]")
            mode = "testing" if testing_only else "prod"
            print(f"    {slug:<20} {label:<35} {mode}")
            shown += 1
        total = shown
        prod_count = sum(1 for s, _, _, t, _, f in CHECK_CATALOG
                         if not t and (not selected_families or f in selected_families))
        test_count = sum(1 for s, _, _, t, _, f in CHECK_CATALOG
                         if t and (not selected_families or f in selected_families))
        filter_note = ""
        if selected_families:
            aliases = [FAMILY_ALIAS_REVERSE.get(f, f) for f in sorted(selected_families)]
            filter_note = f" (filtered: {', '.join(aliases)})"
        print(f"\n  {total} checks shown{filter_note} "
              f"({prod_count} prod-safe, {test_count} testing-only)")
        return

    if args.list_cves:
        if not args.quiet:
            banner()
        list_all_cves(cve_db)
        return

    if args.check and args.family:
        print("Error: --check and --family are mutually exclusive")
        sys.exit(1)

    if not args.target:
        print("Error: -t/--target is required")
        sys.exit(1)

    if not args.quiet:
        banner()

    delay = args.delay if args.delay is not None else (1.0 if args.prod else 0)

    # Resolve --family aliases to full family names
    selected_families = None
    if args.family:
        selected_families = {FAMILY_ALIASES[a] for a in args.family}

    report_data = reset_report()
    report_data["target"] = args.target
    report_data["scan_time"] = str(datetime.datetime.now())

    info(f"Target: {args.target}")
    if delay > 0:
        info(f"Delay between checks: {delay}s")

    if args.endpoints_only:
        enum_endpoints(args.target, report_data, args.timeout)
        save_report(report_data, args.output)
        return

    # --check mode: run specific checks only
    if args.check:
        catalog_map = {c[0]: c for c in CHECK_CATALOG}
        for slug in args.check:
            if slug not in catalog_map:
                print(f"Error: unknown check '{slug}' (use --list-checks)")
                sys.exit(1)

        needs_endpoints = any(catalog_map[s][4] == "endpoints" for s in args.check)
        needs_client = any(catalog_map[s][4] == "client" for s in args.check)
        needs_creds = "provided-creds" in args.check

        if needs_creds:
            if not args.user or not args.password:
                print("Error: -u/--user and -p/--password required for provided-creds check")
                sys.exit(1)
            report_data["_user"] = args.user
            report_data["_password"] = args.password

        if needs_endpoints or needs_creds:
            enum_endpoints(args.target, report_data, args.timeout)

        client = None
        try:
            if needs_client:
                if not args.user or not args.password:
                    print("Error: -u/--user and -p/--password required for this check")
                    sys.exit(1)
                phase("CONNECTING")
                client, conn_findings, conn_ctx = try_connect(
                    args.target, args.user, args.password,
                    args.cert, args.key, args.uri,
                    args.policy, args.mode, args.timeout,
                )
                report_data["findings"].extend(conn_findings)
                if conn_ctx:
                    report_data["connection_context"] = conn_ctx
                if client is None:
                    bad("Cannot connect to server")
                    sys.exit(1)

            phase("SECURITY ASSESSMENT")
            for i, slug in enumerate(args.check):
                _, _, _, testing_only, _, _ = catalog_map[slug]
                if testing_only and args.prod:
                    info(f"Skipping {slug} (testing-only, --prod mode)")
                    continue
                if i > 0 and delay > 0:
                    time.sleep(delay)
                run_check_by_slug(slug, args.target, client, report_data, args.timeout)

            vuln_recap(report_data["findings"], target=args.target, report_data=report_data)
            save_report(report_data, args.output)
        finally:
            if client:
                try:
                    client.disconnect()
                except Exception:
                    pass
            good("Done")
        return

    # Brute-force only mode (no -u/-p needed)
    if args.wordlist and args.passlist and not args.user:
        phase("BRUTE-FORCE ATTACK")
        check_bruteforce(args.target, report_data, args.wordlist, args.passlist,
                         args.timeout, delay=delay)
        vuln_recap(report_data["findings"], target=args.target, report_data=report_data)
        save_report(report_data, args.output)
        good("Done")
        return

    if args.wordlist and not args.passlist:
        print("Error: --passlist is required when using --wordlist")
        sys.exit(1)
    if args.passlist and not args.wordlist:
        print("Error: --wordlist is required when using --passlist")
        sys.exit(1)

    if not args.user or not args.password:
        print("Error: -u/--user and -p/--password required for authenticated scans")
        sys.exit(1)

    info(f"User: {args.user}")

    # Store credentials in report_data for pre-auth check dispatch
    report_data["_user"] = args.user
    report_data["_password"] = args.password

    if not args.cve_only and not args.deep_only and not args.sessions_only:
        phase("PRE-AUTH RECONNAISSANCE")
        if not args.skip_endpoints:
            enum_endpoints(args.target, report_data, args.timeout)
        # Pre-auth checks belong to authentication_posture family
        run_preauth = (not args.skip_security_checks
                       and (not selected_families
                            or FAMILY_AUTHENTICATION in selected_families))
        if run_preauth:
            check_anonymous_access(args.target, report_data, args.timeout)
            # Skip default-creds when the user already provided valid credentials
            if not args.user:
                check_default_credentials(args.target, report_data, args.timeout)
            else:
                info("  [SKIP] default-creds (credentials provided via -u/-p)")
            if args.user and args.password:
                check_provided_credentials(args.target, args.user, args.password,
                                           report_data, args.timeout)
        if args.wordlist and args.passlist:
            check_bruteforce(args.target, report_data, args.wordlist, args.passlist,
                             args.timeout, delay=delay)

    phase("CONNECTING")
    client = None
    report_saved = False

    try:
        client, conn_findings, conn_ctx = try_connect(
            args.target,
            args.user,
            args.password,
            args.cert,
            args.key,
            args.uri,
            args.policy,
            args.mode,
            args.timeout,
        )

        report_data["findings"].extend(conn_findings)
        if conn_ctx:
            report_data["connection_context"] = conn_ctx
            info(f"Enumeration context: {conn_ctx['strategy']} "
                 f"({conn_ctx['policy']}/{conn_ctx['mode']})")

        if client is None:
            bad("Cannot connect to server")
            save_report(report_data, args.output)
            report_saved = True
            sys.exit(1)

        if args.cve_only:
            enum_server_info(client, report_data)
            enum_namespaces(client, report_data)
            enum_vendor_info(client, report_data)
            check_cves(client, report_data, cve_db, include_browsed_nodes=False)
            save_report(report_data, args.output)
            report_saved = True
            return

        if args.deep_only:
            enum_objects_deep(client, report_data, args.depth)
            save_report(report_data, args.output)
            report_saved = True
            return

        if args.sessions_only:
            enum_sessions(client, report_data)
            save_report(report_data, args.output)
            report_saved = True
            return

        phase("ENUMERATION")
        if not args.skip_server:
            enum_server_info(client, report_data)
        if not args.skip_namespaces:
            enum_namespaces(client, report_data)
        if not args.skip_sessions:
            enum_sessions(client, report_data)
        if not args.skip_security:
            enum_security_diag(client, report_data)
        if not args.skip_capabilities:
            enum_capabilities(client)
        if not args.skip_vendor:
            enum_vendor_info(client, report_data)
        if not args.skip_deep:
            enum_objects_deep(client, report_data, args.depth)

        if not args.skip_security_checks:
            phase("SECURITY ASSESSMENT")
            run_security_checks(args.target, client, report_data, args.timeout,
                                safe=args.prod, delay=delay, families=selected_families)

        if not args.skip_cve:
            check_cves(client, report_data, cve_db, include_browsed_nodes=not args.skip_deep)

        vuln_recap(report_data["findings"], target=args.target, report_data=report_data)

        save_report(report_data, args.output)
        report_saved = True

    except KeyboardInterrupt:
        bad("Interrupted by user")
    finally:
        if client:
            try:
                client.disconnect()
            except Exception:
                pass

        if not report_saved:
            save_report(report_data, args.output)

        good("Done")


if __name__ == "__main__":
    main()
    # Flush stdout/stderr before forced exit (os._exit skips buffer flush)
    sys.stdout.flush()
    sys.stderr.flush()
    # asyncua sync ThreadLoop can hang on exit; force clean shutdown
    os._exit(0)
