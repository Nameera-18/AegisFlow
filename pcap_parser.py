"""
pcap_parser.py
----------------
Reads a .pcap / .pcapng file with Scapy and turns it into two things:

1. `packets`  -> a flat list of per-packet dicts (used for the timeline chart)
2. `flows`    -> packets grouped by 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol)
                 with aggregated stats (this is what the analyzer scores)

This mirrors the "Flow & Packet Feature Extraction" stage from the AegisFlow
pipeline diagram, just implemented with simple, explainable rules instead of
a trained model (see analyzer.py for why).
"""

from collections import defaultdict
from scapy.all import rdpcap, IP, TCP, UDP


def _proto_name(pkt):
    if TCP in pkt:
        return "TCP"
    if UDP in pkt:
        return "UDP"
    return "OTHER"


def parse_pcap(file_path: str):
    """Read a pcap file and return a list of packet-level dicts."""
    packets = rdpcap(file_path)
    records = []

    for pkt in packets:
        if IP not in pkt:
            continue  # skip non-IP traffic (ARP, etc.) for this prototype

        ip_layer = pkt[IP]
        proto = _proto_name(pkt)

        record = {
            "time": float(pkt.time),
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            "protocol": proto,
            "length": len(pkt),
            "src_port": None,
            "dst_port": None,
            "flags": None,
        }

        if TCP in pkt:
            record["src_port"] = int(pkt[TCP].sport)
            record["dst_port"] = int(pkt[TCP].dport)
            record["flags"] = str(pkt[TCP].flags)
        elif UDP in pkt:
            record["src_port"] = int(pkt[UDP].sport)
            record["dst_port"] = int(pkt[UDP].dport)

        records.append(record)

    records.sort(key=lambda r: r["time"])
    return records


def build_flows(records):
    """Group packet records into bidirectional-agnostic 5-tuple flows."""
    grouped = defaultdict(list)

    for r in records:
        key = (r["src_ip"], r["dst_ip"], r["src_port"], r["dst_port"], r["protocol"])
        grouped[key].append(r)

    flows = []
    for i, (key, pkts) in enumerate(grouped.items()):
        src_ip, dst_ip, src_port, dst_port, protocol = key
        times = [p["time"] for p in pkts]
        lengths = [p["length"] for p in pkts]
        start, end = min(times), max(times)
        duration = max(end - start, 1e-6)

        flows.append({
            "flow_id": f"flow_{i}",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "packet_count": len(pkts),
            "byte_count": sum(lengths),
            "avg_packet_size": round(sum(lengths) / len(lengths), 2),
            "start_time": start,
            "end_time": end,
            "duration": round(duration, 4),
            "packets_per_second": round(len(pkts) / duration, 2),
        })

    return flows
