import datetime
from opcua import Client, ua
from .banner import section, good, bad, info, warn
from .helpers import sr, sn, sc, safe_disconnect, format_exc


INTERESTING_KW = [
    "password", "secret", "key", "token", "credential", "auth", "user", "admin",
    "config", "setting", "address", "host", "port", "url", "uri", "serial", "license",
    "firmware", "version", "model", "device", "door", "lock", "unlock", "open", "close",
    "grant", "deny", "alarm", "status", "state", "mode", "command", "control",
    "mqtt", "broker", "connection", "certificate", "protocol", "driver", "connected",
    "error", "log", "event"
]


def normalize_policy(policy_uri):
    try:
        if "#" in policy_uri:
            return policy_uri.split("#")[-1]
        return str(policy_uri)
    except Exception:
        return str(policy_uri)


def normalize_mode(mode):
    s = str(mode)
    if "SignAndEncrypt" in s:
        return "SignAndEncrypt"
    if "Sign" in s and "SignAndEncrypt" not in s:
        return "Sign"
    if "None" in s:
        return "None"
    return s


def token_type_to_str(token_type):
    s = str(token_type)
    if "Anonymous" in s or s.endswith(".0") or s == "0":
        return "Anonymous"
    if "UserName" in s or s.endswith(".1") or s == "1":
        return "UserName"
    if "Certificate" in s or "X509" in s or s.endswith(".2") or s == "2":
        return "Certificate"
    if "IssuedToken" in s or s.endswith(".3") or s == "3":
        return "IssuedToken"
    return s


def enum_endpoints(target, report_data, timeout=5):
    section("ENDPOINT ENUMERATION")
    tmp = None
    try:
        tmp = Client(target, timeout=timeout)
        endpoints = tmp.connect_and_get_server_endpoints()
        for ep in endpoints:
            mode_str = normalize_mode(ep.SecurityMode)
            policy = normalize_policy(ep.SecurityPolicyUri)

            ep_info = {
                "url": str(ep.EndpointUrl),
                "mode": mode_str,
                "policy": policy,
                "tokens": []
            }

            if policy == "None" or mode_str == "None":
                bad(f"INSECURE: {ep.EndpointUrl} | {mode_str} | {policy}")
            elif "Basic128" in policy or policy == "Basic256":
                warn(f"WEAK/LEGACY: {ep.EndpointUrl} | {mode_str} | {policy}")
            else:
                good(f"{ep.EndpointUrl} | {mode_str} | {policy}")

            for token in ep.UserIdentityTokens:
                tt = token_type_to_str(token.TokenType)
                ep_info["tokens"].append(tt)
                if tt == "Anonymous":
                    bad("  Token: Anonymous access enabled")
                elif tt == "UserName":
                    info("  Token: Username/Password")
                elif tt == "Certificate":
                    info("  Token: X509 Certificate")
                else:
                    info(f"  Token: {tt}")

            report_data["endpoints"].append(ep_info)
    except Exception as e:
        warn(f"Endpoint enum failed: {format_exc(e)}")
    finally:
        safe_disconnect(tmp)


def enum_server_info(client, report_data):
    section("SERVER IDENTIFICATION")
    pairs = [
        ("i=2262", "ProductUri"),
        ("i=2263", "ManufacturerName"),
        ("i=2261", "ProductName"),
        ("i=2264", "SoftwareVersion"),
        ("i=2265", "BuildNumber"),
        ("i=2266", "BuildDate"),
    ]

    for nid, label in pairs:
        try:
            val = client.get_node(nid).get_value()
            report_data["server_info"][label] = str(val)
            if label in ["SoftwareVersion", "BuildNumber", "ProductName", "ManufacturerName"]:
                bad(f"{label}: {val}")
            else:
                info(f"{label}: {val}")
        except Exception:
            pass

    try:
        start = client.get_node("i=2257").get_value()
        report_data["server_info"]["StartTime"] = str(start)
        info(f"Start: {start}")
        if start:
            now = datetime.datetime.now(datetime.timezone.utc)
            st = start.replace(tzinfo=datetime.timezone.utc) if start.tzinfo is None else start
            d = now - st
            info(f"Uptime: {d.days}d {d.seconds // 3600}h")
    except Exception:
        pass

    try:
        state = client.get_node("i=2259").get_value()
        states = {
            0: "Running",
            1: "Failed",
            2: "NoConfiguration",
            3: "Suspended",
            4: "Shutdown",
            5: "Test",
            6: "CommunicationFault"
        }
        info(f"State: {states.get(state, state)}")
    except Exception:
        pass

    try:
        uris = client.get_node("i=2254").get_value() or []
        for uri in uris:
            bad(f"Server URI: {uri}")
            report_data["server_info"]["ServerURI"] = str(uri)
    except Exception:
        pass


def enum_namespaces(client, report_data):
    section("NAMESPACES & DEVICE TYPES")
    try:
        ns = client.get_node("i=2255").get_value() or []
        for i, n in enumerate(ns):
            report_data["namespaces"].append(n)
            nl = str(n).lower()
            if "devices:" in nl:
                bad(f"NS[{i}]: {n}")
            elif "opcfoundation" in nl:
                info(f"NS[{i}]: {n}")
            else:
                warn(f"NS[{i}]: {n}")
    except Exception as e:
        warn(f"Failed: {format_exc(e)}")


def enum_sessions(client, report_data):
    section("ACTIVE SESSIONS")
    try:
        diag = client.get_node("i=3706")
        for child in sc(diag):
            name = sn(child)
            if name == "SessionDiagnosticsArray":
                continue

            sess = {"name": name}
            bad(f"Client: {name}")

            for prop in sc(child):
                pn, pv = sn(prop), sr(prop)
                if pv is not None and pn in [
                    "SessionName",
                    "EndpointUrl",
                    "ClientConnectionTime",
                    "ClientLastContactTime",
                    "ActualSessionTimeout",
                    "SessionId",
                ]:
                    sess[pn] = str(pv)
                    (warn if pn == "SessionId" else info)(f"  {pn}: {pv}")

            report_data["sessions"].append(sess)
    except Exception as e:
        warn(f"Session diagnostics unavailable: {format_exc(e)}")


def enum_security_diag(client, report_data):
    section("SECURITY DIAGNOSTICS")
    fields = [
        ("i=2276", "ServerViewCount"),
        ("i=2277", "CurrentSessionCount"),
        ("i=2278", "CumulatedSessionCount"),
        ("i=2279", "SecurityRejectedSessionCount"),
        ("i=2280", "RejectedSessionCount"),
        ("i=2281", "SessionTimeoutCount"),
        ("i=2282", "SessionAbortCount"),
        ("i=2284", "CurrentSubscriptionCount"),
        ("i=2285", "CumulatedSubscriptionCount"),
        ("i=2287", "SecurityRejectedRequestsCount"),
        ("i=2288", "RejectedRequestsCount"),
    ]

    for nid, label in fields:
        try:
            val = client.get_node(nid).get_value()
            report_data["security_diag"][label] = val
            if ("Rejected" in label or "Abort" in label or "Timeout" in label) and val > 0:
                bad(f"{label}: {val}")
            elif "Rejected" in label:
                good(f"{label}: {val}")
            else:
                info(f"{label}: {val}")
        except Exception:
            pass


def enum_capabilities(client):
    section("SERVER CAPABILITIES")
    try:
        profiles = client.get_node("i=2269").get_value() or []
        for p in profiles:
            if "Method" in p or "NodeManagement" in p:
                warn(f"Profile: {p}")
            else:
                info(f"Profile: {p}")
    except Exception:
        pass

    for nid, label in [
        ("i=11705", "MaxNodesPerRead"),
        ("i=11707", "MaxNodesPerWrite"),
        ("i=11709", "MaxNodesPerMethodCall"),
        ("i=11710", "MaxNodesPerBrowse"),
        ("i=11713", "MaxNodesPerNodeManagement"),
        ("i=11714", "MaxMonitoredItemsPerCall"),
    ]:
        try:
            val = client.get_node(nid).get_value()
            if val is not None:
                if "Write" in label or "Method" in label or "Management" in label:
                    warn(f"{label}: {val}")
                else:
                    info(f"{label}: {val}")
        except Exception:
            pass


def enum_vendor_info(client, report_data):
    section("VENDOR INFO")
    try:
        def browse_vendor(node, depth=0):
            if depth > 3:
                return
            for c in sc(node):
                n, v = sn(c), sr(c)
                if v is not None:
                    report_data["vendor_info"][n] = str(v)
                    info(f"{'  ' * depth}{n}: {v}")
                else:
                    info(f"{'  ' * depth}{n}")
                browse_vendor(c, depth + 1)

        browse_vendor(client.get_node("i=2295"))
    except Exception as e:
        warn(f"Failed: {format_exc(e)}")


def enum_objects_deep(client, report_data, max_depth=8):
    section(f"DEEP NODE ENUMERATION (depth={max_depth})")
    writable = []
    methods = []
    interesting = []
    count = [0]
    visited = set()

    def browse(node, depth=0, path=""):
        if depth > max_depth:
            return

        for child in sc(node):
            try:
                nid = child.nodeid.to_string()
            except Exception:
                nid = f"{path}/{sn(child)}"

            if nid in visited:
                continue
            visited.add(nid)

            count[0] += 1
            name = sn(child)
            current_path = f"{path}/{name}"

            try:
                node_class = child.get_node_class()
            except Exception:
                node_class = None

            if node_class == ua.NodeClass.Method:
                n_in = 0
                n_out = 0
                for a in sc(child):
                    an = sn(a)
                    if "Input" in an:
                        av = sr(a)
                        n_in = len(av) if isinstance(av, list) else 1
                    elif "Output" in an:
                        av = sr(a)
                        n_out = len(av) if isinstance(av, list) else 1

                bad(f"METHOD: {current_path} (in:{n_in} out:{n_out})")
                methods.append({"path": current_path, "inputs": n_in, "outputs": n_out})
                continue

            if node_class == ua.NodeClass.Variable:
                val = sr(child)
                writable_flag = False
                access = "?"
                try:
                    al = child.get_access_level()
                    access = str(al)
                    writable_flag = "Write" in access or (isinstance(al, int) and (al & 0x02))
                except Exception:
                    pass

                entry = {
                    "path": current_path,
                    "value": str(val)[:200] if val is not None else None,
                    "access": access,
                    "writable": writable_flag,
                }
                report_data["all_nodes"].append(entry)

                if writable_flag:
                    writable.append(entry)
                    bad(f"WRITABLE: {current_path} = {str(val)[:100]} [{access}]")

                haystack = f"{current_path} {name} {val}".lower()
                if any(kw in haystack for kw in INTERESTING_KW):
                    interesting.append(entry)
                    warn(f"{current_path} = {str(val)[:100]}")

            browse(child, depth + 1, current_path)

    try:
        browse(client.get_node("i=85"), 0, "Objects")
    except Exception as e:
        warn(f"Browse failed: {format_exc(e)}")

    report_data["writable_nodes"] = writable
    report_data["method_nodes"] = methods
    report_data["interesting_values"] = interesting
    report_data["total_nodes"] = count[0]

    section("ENUMERATION SUMMARY")
    info(f"Total nodes: {count[0]}")
    if writable:
        bad(f"WRITABLE NODES: {len(writable)}")
    else:
        good("No writable nodes")

    if methods:
        bad(f"METHODS: {len(methods)}")
        for m in methods:
            warn(f"  {m['path']}")
    else:
        good("No methods")

    if interesting:
        bad(f"INTERESTING VALUES: {len(interesting)}")
