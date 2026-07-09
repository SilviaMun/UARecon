#!/usr/bin/env python3
import sys
import datetime
import argparse

from opcpeas import __version__
from opcpeas.banner import banner, set_no_color, section, bad, good, info
from opcpeas.report import reset_report, save_report
from opcpeas.connection import try_connect
from opcpeas.enumeration import (
    enum_endpoints,
    enum_server_info,
    enum_namespaces,
    enum_sessions,
    enum_security_diag,
    enum_capabilities,
    enum_vendor_info,
    enum_objects_deep,
)
from opcpeas.cve import load_cve_db, list_all_cves, check_cves


def parse_args():
    p = argparse.ArgumentParser(
        prog="opcpeas",
        description=f"OpcPEAS v{__version__} - OPC-UA Security Scanner"
    )
    p.add_argument("-t", "--target", help="OPC-UA target")
    p.add_argument("-u", "--user", help="Username")
    p.add_argument("-p", "--password", help="Password")
    p.add_argument("-c", "--cert", help="Client certificate PEM")
    p.add_argument("-k", "--key", help="Client private key PEM")
    p.add_argument("--uri", default="urn:OpcPEAS", help="Application URI")
    p.add_argument(
        "--policy",
        default="Basic256Sha256",
        choices=["Basic256Sha256", "Aes128_Sha256_RsaOaep", "Aes256_Sha256_RsaPss"],
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

    if args.list_cves:
        if not args.quiet:
            banner()
        list_all_cves(cve_db)
        return

    if not args.target:
        print("Error: -t/--target is required")
        sys.exit(1)

    if not args.quiet:
        banner()

    report_data = reset_report()
    report_data["target"] = args.target
    report_data["scan_time"] = str(datetime.datetime.now())

    info(f"Target: {args.target}")

    if args.endpoints_only:
        enum_endpoints(args.target, report_data, args.timeout)
        save_report(report_data, args.output)
        return

    if not args.user or not args.password:
        print("Error: -u/--user and -p/--password required for authenticated scans")
        sys.exit(1)

    info(f"User: {args.user}")

    if not args.skip_endpoints and not args.cve_only and not args.deep_only and not args.sessions_only:
        section("PHASE 1: PRE-AUTH")
        enum_endpoints(args.target, report_data, args.timeout)

    section("PHASE 2: CONNECTING")
    client = None
    report_saved = False

    try:
        client, conn_findings = try_connect(
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
        if not args.skip_cve:
            check_cves(client, report_data, cve_db, include_browsed_nodes=not args.skip_deep)

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
