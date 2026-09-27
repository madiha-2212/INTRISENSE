
from collections import defaultdict


def build_flows(captured_packets):

    flows = {}

    for packet in captured_packets:

        source = packet["source_ip"]
        destination = packet["destination_ip"]
        protocol = packet["protocol"]

        source_port = packet["source_port"]
        destination_port = packet["destination_port"]

        endpoint_a = (source, source_port)
        endpoint_b = (destination, destination_port)

        base_key = (
            tuple(sorted([endpoint_a, endpoint_b])),
            protocol
        )

        if base_key not in flows:

            flows[base_key] = {
                "protocol": protocol,
                "endpoint_a": endpoint_a,
                "endpoint_b": endpoint_b,
                "packets": [],
                "forward_packets": [],
                "reverse_packets": [],
                "bytes": 0
            }

        flow = flows[base_key]

        flow["packets"].append(packet)
        flow["bytes"] += packet["packet_length"]

        if (
            packet["source_ip"] == endpoint_a[0]
            and packet["source_port"] == endpoint_a[1]
        ):
            flow["forward_packets"].append(packet)
        else:
            flow["reverse_packets"].append(packet)

    return flows
