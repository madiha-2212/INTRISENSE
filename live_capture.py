from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime


def process_packet(packet):
    if IP not in packet:
        return None

    timestamp = float(packet.time)

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst

    protocol = "tcp" if TCP in packet else "udp" if UDP in packet else "icmp" if ICMP in packet else "other"

    source_port = None
    destination_port = None
    tcp_flags = None
    window_size = None
    sequence_number = None
    acknowledgement_number = None

    if TCP in packet:
        source_port = int(packet[TCP].sport)
        destination_port = int(packet[TCP].dport)
        tcp_flags = str(packet[TCP].flags)
        window_size = int(packet[TCP].window)
        sequence_number = int(packet[TCP].seq)
        acknowledgement_number = int(packet[TCP].ack)

    elif UDP in packet:
        source_port = int(packet[UDP].sport)
        destination_port = int(packet[UDP].dport)

    return {
        "timestamp": timestamp,
        "timestamp_readable": datetime.fromtimestamp(timestamp).strftime(
            "%Y-%m-%d %H:%M:%S.%f"
        ),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol,
        "source_port": source_port,
        "destination_port": destination_port,
        "packet_length": len(packet),
        "ttl": int(packet[IP].ttl),
        "tcp_flags": tcp_flags,
        "window_size": window_size,
        "sequence_number": sequence_number,
        "acknowledgement_number": acknowledgement_number
    }


def capture_packets(packet_count=200, timeout=30, on_packet=None):
    """
    Capture live packets using scapy.

    on_packet : callable, optional
        If provided, called synchronously with each packet's parsed
        dict the moment it is captured. scapy's sniff() runs this
        handler in the same thread as the capture call, so a caller
        (e.g. a Streamlit UI) can use this to update a live chart or
        counter in real time -- no threading or queues required.
    """
    captured_packets = []

    def packet_handler(packet):
        result = process_packet(packet)

        if result is not None:
            captured_packets.append(result)

            if on_packet is not None:
                on_packet(result)

    sniff(
        prn=packet_handler,
        count=packet_count,
        timeout=timeout,
        store=False
    )

    return captured_packets