
import statistics


def _packet_times(packets):
    return [float(p["timestamp"]) for p in packets]


def _packet_sizes(packets):
    return [int(p["packet_length"]) for p in packets]


def _mean_interval(packets):
    times = sorted(_packet_times(packets))

    if len(times) < 2:
        return 0.0

    intervals = [
        times[i] - times[i - 1]
        for i in range(1, len(times))
        if times[i] >= times[i - 1]
    ]

    return statistics.mean(intervals) if intervals else 0.0


def _jitter(packets):
    times = sorted(_packet_times(packets))

    if len(times) < 3:
        return 0.0

    intervals = [
        times[i] - times[i - 1]
        for i in range(1, len(times))
        if times[i] >= times[i - 1]
    ]

    if len(intervals) < 2:
        return 0.0

    differences = [
        abs(intervals[i] - intervals[i - 1])
        for i in range(1, len(intervals))
    ]

    return statistics.mean(differences) if differences else 0.0


def _mean_size(packets):
    sizes = _packet_sizes(packets)
    return statistics.mean(sizes) if sizes else 0.0


def extract_flow_features(flow):

    packets = flow["packets"]

    if not packets:
        return None

    forward = flow["forward_packets"]
    reverse = flow["reverse_packets"]

    all_times = _packet_times(packets)

    duration = max(all_times) - min(all_times) if len(all_times) >= 2 else 0.0

    total_packets = len(packets)
    total_bytes = sum(p["packet_length"] for p in packets)

    spkts = len(forward)
    dpkts = len(reverse)

    sbytes = sum(p["packet_length"] for p in forward)
    dbytes = sum(p["packet_length"] for p in reverse)

    rate = total_packets / duration if duration > 0 else 0.0

    sload = (sbytes * 8) / duration if duration > 0 else 0.0
    dload = (dbytes * 8) / duration if duration > 0 else 0.0

    sloss = 0
    dloss = 0

    if spkts > 0:
        sloss = max(0, spkts - len(set(
            p["sequence_number"]
            for p in forward
            if p["sequence_number"] is not None
        )))

    if dpkts > 0:
        dloss = max(0, dpkts - len(set(
            p["sequence_number"]
            for p in reverse
            if p["sequence_number"] is not None
        )))

    first_packet = packets[0]

    proto = first_packet["protocol"]

    source_port = first_packet["source_port"]
    destination_port = first_packet["destination_port"]

    service = "unknown"

    known_services = {
        20: "ftp-data",
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        123: "ntp",
        143: "imap",
        443: "https",
        445: "smb",
        587: "submission",
        993: "imaps",
        995: "pop3s",
        3306: "mysql",
        3389: "rdp",
        5432: "postgresql",
        8080: "http-alt"
    }

    if destination_port in known_services:
        service = known_services[destination_port]
    elif source_port in known_services:
        service = known_services[source_port]

    sttl = forward[0]["ttl"] if forward else first_packet["ttl"]
    dttl = reverse[0]["ttl"] if reverse else sttl

    sinpkt = _mean_interval(forward)
    dinpkt = _mean_interval(reverse)

    sjit = _jitter(forward)
    djit = _jitter(reverse)

    smean = _mean_size(forward)
    dmean = _mean_size(reverse)

    swin = 0
    dwin = 0

    for packet in forward:
        if packet["window_size"] is not None:
            swin = packet["window_size"]
            break

    for packet in reverse:
        if packet["window_size"] is not None:
            dwin = packet["window_size"]
            break

    stcpb = 0
    dtcpb = 0

    for packet in forward:
        if packet["sequence_number"] is not None:
            stcpb = packet["sequence_number"]
            break

    for packet in reverse:
        if packet["sequence_number"] is not None:
            dtcpb = packet["sequence_number"]
            break

    tcprtt = 0.0
    synack = 0.0
    ackdat = 0.0

    if proto == "tcp":

        syn_time = None
        synack_time = None
        ack_time = None

        for packet in packets:

            flags = packet["tcp_flags"] or ""

            if "S" in flags and "A" not in flags and syn_time is None:
                syn_time = packet["timestamp"]

            elif "S" in flags and "A" in flags and synack_time is None:
                synack_time = packet["timestamp"]

            elif "A" in flags and synack_time is not None and ack_time is None:
                ack_time = packet["timestamp"]

        if syn_time is not None and synack_time is not None:
            synack = max(0.0, synack_time - syn_time)
            tcprtt = synack

        if synack_time is not None and ack_time is not None:
            ackdat = max(0.0, ack_time - synack_time)

    is_sm_ips_ports = int(
        flow["endpoint_a"][0] == flow["endpoint_b"][0]
        and flow["endpoint_a"][1] == flow["endpoint_b"][1]
    )

    return {
        "dur": duration,
        "proto": proto,
        "service": service,
        "state": "INT" if proto == "tcp" else "CON",
        "spkts": spkts,
        "dpkts": dpkts,
        "sbytes": sbytes,
        "dbytes": dbytes,
        "rate": rate,
        "sttl": sttl,
        "dttl": dttl,
        "sload": sload,
        "dload": dload,
        "sloss": sloss,
        "dloss": dloss,
        "sinpkt": sinpkt,
        "dinpkt": dinpkt,
        "sjit": sjit,
        "djit": djit,
        "swin": swin,
        "stcpb": stcpb,
        "dtcpb": dtcpb,
        "dwin": dwin,
        "tcprtt": tcprtt,
        "synack": synack,
        "ackdat": ackdat,
        "smean": smean,
        "dmean": dmean,

        # Features that require application-level/context information.
        # They are explicitly marked as unavailable rather than pretending
        # they were measured from packet contents.
        "trans_depth": 0,
        "response_body_len": 0,
        "ct_srv_src": 0,
        "ct_state_ttl": 0,
        "ct_dst_ltm": 0,
        "ct_src_dport_ltm": 0,
        "ct_dst_sport_ltm": 0,
        "ct_dst_src_ltm": 0,
        "is_ftp_login": 0,
        "ct_ftp_cmd": 0,
        "ct_flw_http_mthd": 0,
        "ct_src_ltm": 0,
        "ct_srv_dst": 0,
        "is_sm_ips_ports": is_sm_ips_ports
    }
