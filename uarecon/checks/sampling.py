from ..banner import info, section


def check_min_sampling_interval(client, report_data):
    section("SAMPLING INTERVAL LIMITS")
    try:
        val = client.get_node("i=2272").read_value()
        if val is not None:
            if val == 0:
                info("MinSupportedSampleRate: 0 (fastest possible, server default)")
            else:
                info(f"MinSupportedSampleRate: {val}ms")
    except Exception:
        pass
