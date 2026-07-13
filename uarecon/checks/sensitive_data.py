from asyncua import ua

from ._base import (
    add_finding, score_sensitive_content, mask_value, _decode_bytestring,
)
from ..banner import warn, good, info, section, tag
from ..helpers import classify_error


def check_sensitive_data_exposure(client, report_data, max_nodes=2000, threshold=6, max_depth=7):
    section("SENSITIVE DATA EXPOSURE")

    skip_names = {
        "ServerDiagnostics", "SessionsDiagnosticsSummary",
        "SubscriptionDiagnosticsArray", "SamplingIntervalDiagnosticsArray",
        "ServerRedundancy", "ServerCapabilities", "ModellingRules",
        "AggregateFunctions", "HistoryServerCapabilities",
    }

    priority_names = {
        "Configuration", "Config", "Settings", "Credentials",
        "Connection", "Authentication", "MQTT", "Database",
        "Communication", "Network", "Security", "UserManagement",
        "Broker", "Driver", "PLCConfig", "License",
    }

    matches = []
    tested = [0]
    visited = set()

    def browse_recursive(node, depth, path, in_priority):
        if tested[0] >= max_nodes:
            return
        effective_depth = max_depth + 2 if in_priority else max_depth
        if depth > effective_depth:
            return

        try:
            children = node.get_children()
        except Exception:
            return

        priority_children = []
        normal_children = []

        for child in children:
            try:
                name = child.read_browse_name().Name
            except Exception:
                name = "?"
            if name in priority_names:
                priority_children.append((child, name))
            else:
                normal_children.append((child, name))

        for child, name in priority_children + normal_children:
            if tested[0] >= max_nodes:
                return

            try:
                nid = child.nodeid.to_string()
            except Exception:
                continue

            if nid in visited:
                continue
            visited.add(nid)

            current_path = f"{path}/{name}"

            if name in skip_names:
                continue

            try:
                node_class = child.read_node_class()
            except Exception:
                continue

            child_is_priority = in_priority or name in priority_names

            if node_class == ua.NodeClass.Variable:
                try:
                    value = child.read_value()
                except Exception:
                    value = None

                if value is not None:
                    tested[0] += 1

                    # Skip empty/trivial values - a node named "Password" with
                    # empty value is just a field definition, not a credential leak
                    str_val = str(value).strip() if not isinstance(value, (bytes, bytearray)) else None
                    if str_val is not None and (str_val == "" or str_val == "None"):
                        continue
                    if isinstance(value, (bytes, bytearray)) and len(value) == 0:
                        continue

                    effective_threshold = threshold - 2 if child_is_priority else threshold
                    score, reasons = score_sensitive_content(current_path, name, value)

                    if score >= effective_threshold:
                        if isinstance(value, (bytes, bytearray)):
                            sample = mask_value(_decode_bytestring(value))
                        else:
                            sample = mask_value(value)
                        warn(f"SENSITIVE: {current_path} | score={score} | {sample}")
                        tag("Information Disclosure")
                        matches.append({
                            "path": current_path,
                            "node_id": nid,
                            "browse_name": name,
                            "score": score,
                            "reasons": reasons,
                            "sample": sample,
                        })

            if node_class in (ua.NodeClass.Object, ua.NodeClass.Variable):
                browse_recursive(child, depth + 1, current_path, child_is_priority)

    info("Recursively browsing node tree for sensitive data patterns...")
    try:
        browse_recursive(client.get_node("i=85"), 0, "Objects", False)
    except Exception as e:
        warn(f"Browse failed: {classify_error(e)}")

    info(f"Scanned {tested[0]} variable nodes (max_depth={max_depth}, limit={max_nodes})")

    high_score = [m for m in matches if m["score"] >= 10]
    medium_score = [m for m in matches if 4 <= m["score"] < 10]

    if high_score:
        add_finding(
            report_data,
            "Sensitive Data Exposed (High Confidence)",
            "High",
            "Information Disclosure",
            f"{len(high_score)} node(s) contain values strongly matching sensitive data patterns "
            f"(credentials, private keys, connection strings). Immediate review required.",
            check="sensitive-data",
            confidence="high",
            verification_status="pattern-match",
            safe_check=True,
            destructive=False,
            evidence=high_score[:20],
        )

    if medium_score:
        add_finding(
            report_data,
            "Potentially Sensitive Data Exposed",
            "Medium",
            "Information Disclosure",
            f"{len(medium_score)} node(s) match sensitive content patterns (tokens, internal addresses, "
            f"high-entropy secrets, configuration values). Manual validation recommended.",
            check="sensitive-data",
            confidence="medium",
            verification_status="pattern-match",
            safe_check=True,
            destructive=False,
            evidence=medium_score[:20],
        )

    if not matches:
        good(f"No sensitive data patterns found in {tested[0]} nodes")
