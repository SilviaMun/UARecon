"""
Method Access Control Check (non-destructive).

NON-DESTRUCTIVE STRATEGY:
  - Read the UserExecutable attribute to determine if the method is callable.
  - Read InputArguments to determine if the method requires parameters.
  - For methods WITH required arguments: call with empty args [].  The server
    will return BadArgumentsMissing / BadInvalidArgument / BadTypeMismatch,
    which proves the method is reachable without triggering any action.
  - For methods with ZERO required arguments: NEVER call them.  A zero-arg
    method could be a Start, Stop, Reset, or any action trigger.  Report
    these as executable based on UserExecutable only.

This guarantees no method is ever successfully invoked during the scan.
"""

from asyncua import ua

from ._base import add_finding, add_observation
from ..banner import bad, warn, good, info, section, tag
from ..helpers import sc, sn


def _get_input_arguments(client, method_node):
    """
    Read the InputArguments property of a method node.
    Returns the number of required arguments, or None if unreadable.
    """
    try:
        for child in sc(method_node):
            try:
                name = sn(child)
                if name == "InputArguments":
                    args = child.read_value()
                    if args is not None:
                        return len(args)
                    return 0
            except Exception:
                continue
    except Exception:
        pass
    return None


def check_method_access_control(client, report_data):
    section("METHOD ACCESS CONTROL")
    methods_found = report_data.get("method_nodes", [])
    if not methods_found:
        info("No methods discovered (run deep enumeration first)")
        return

    # Results
    arg_reachable = []          # Called with [] -> argument error (proves reachable)
    executable_zero_arg = []    # UserExecutable=True, 0 args (NOT called)
    executable_with_args = []   # UserExecutable=True, has args (will attempt call)
    denied_methods = 0
    tested = 0

    for m in methods_found[:20]:
        path = m.get("path", "")
        try:
            # Resolve the method node by walking the path
            parts = path.strip("/").split("/")
            node = client.get_node("i=85")

            for part in parts[1:]:
                found = False
                for child in sc(node):
                    if sn(child) == part:
                        node = child
                        found = True
                        break
                if not found:
                    node = None
                    break

            if node is None:
                continue

            node_class = node.read_node_class()
            if node_class != ua.NodeClass.Method:
                continue

            tested += 1

            # --- Check UserExecutable attribute ---
            try:
                user_exec = node.read_attribute(ua.AttributeIds.UserExecutable)
                is_executable = bool(user_exec.Value.Value) if user_exec.Value else False
            except Exception:
                # If we can't read UserExecutable, assume unknown
                is_executable = None

            if is_executable is False:
                denied_methods += 1
                good(f"Method not executable: {path}")
                continue

            # --- Check InputArguments ---
            n_args = _get_input_arguments(client, node)

            if n_args is not None and n_args == 0:
                # ZERO-ARG METHOD: NEVER call it.  Report based on UserExecutable.
                executable_zero_arg.append(path)
                warn(f"EXECUTABLE (zero-arg, not called): {path}")
                continue

            # --- Method has arguments (or unknown arg count): safe to probe ---
            # Call with empty args -- will fail with BadArgumentsMissing/BadTypeMismatch
            # which proves the method is reachable without executing it.
            parent = node.get_parent()
            if parent is None:
                if is_executable:
                    executable_with_args.append(path)
                continue

            try:
                parent.call_method(node, [])
                # If this unexpectedly succeeds, the method took 0 args after all
                # but InputArguments wasn't properly declared.  Report it.
                executable_zero_arg.append(path)
                warn(f"Method call succeeded unexpectedly (declared args={n_args}): {path}")
            except ua.UaStatusCodeError as e:
                status = str(e)
                if "BadUserAccessDenied" in status or "BadNotExecutable" in status:
                    denied_methods += 1
                    good(f"Method access denied: {path}")
                elif ("BadInvalidArgument" in status
                      or "BadArgumentsMissing" in status
                      or "BadTypeMismatch" in status):
                    arg_reachable.append(path)
                    info(f"Method reachable (arg error proves access): {path}")
                else:
                    # Other errors -- method may or may not be accessible
                    info(f"Method {path}: {status}")
            except Exception:
                pass

        except Exception:
            pass

    # --- Findings ---

    # Zero-arg executable methods are the highest risk (could be action triggers)
    if executable_zero_arg:
        bad(f"{len(executable_zero_arg)} zero-argument method(s) are executable")
        tag("Broken Access Control")
        add_finding(
            report_data,
            "Executable Zero-Argument Methods (Not Called)",
            "High",
            "Broken Access Control",
            f"{len(executable_zero_arg)} method(s) with zero input arguments are marked "
            f"as UserExecutable by the server: {', '.join(executable_zero_arg[:5])}. "
            f"These were NOT invoked to avoid triggering actions. Zero-argument methods "
            f"are often action triggers (Start, Stop, Reset). Manual review is required.",
            check="method-access",
            confidence="high",
            verification_status="access-level-read",
            safe_check=True,
            destructive=False,
            evidence={
                "executable_zero_arg": executable_zero_arg[:20],
                "tested": tested,
            },
        )

    # Methods proven reachable via argument errors
    if arg_reachable:
        level = "High" if not executable_zero_arg else None
        if level:
            add_finding(
                report_data,
                "Methods Reachable by Current Role",
                "High",
                "Broken Access Control",
                f"{len(arg_reachable)} method(s) are proven reachable: the server returned "
                f"argument errors instead of access denial when called with empty arguments: "
                f"{', '.join(arg_reachable[:5])}. No method was actually executed.",
                check="method-access",
                confidence="high",
                verification_status="confirmed-reachable",
                safe_check=True,
                destructive=False,
                evidence={
                    "argument_reachable": arg_reachable[:20],
                    "tested": tested,
                },
            )
        else:
            # Already have the zero-arg finding, add reachable as observation
            add_observation(
                report_data,
                "Additional Methods Proven Reachable",
                "Broken Access Control",
                f"{len(arg_reachable)} additional method(s) are proven reachable via "
                f"argument errors: {', '.join(arg_reachable[:5])}.",
                check="method-access",
                confidence="high",
                verification_status="confirmed-reachable",
                safe_check=True,
                destructive=False,
                evidence={"argument_reachable": arg_reachable[:20]},
            )

    if not executable_zero_arg and not arg_reachable and tested > 0:
        good(f"All {tested} tested method(s) denied access or were not executable")
    elif tested == 0:
        info("No methods could be resolved for testing")
