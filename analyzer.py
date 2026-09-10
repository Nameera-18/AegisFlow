"""
analyzer.py
------------
This is the "investigation & analysis" brain of the prototype.

The real AegisFlow pitch uses LSTM / Temporal Transformer / Temporal GNN
models trained on labelled datasets (CSE-CIC-IDS2018, CTU-13, UNSW-NB15) to
FORECAST future attack stages. Training a real model needs those datasets,
GPU time, and days of work -- out of scope for a quick prototype.

Instead, this module reproduces the *shape* of that pipeline using
transparent, rule-based heuristics that flag the same attack stages the
slides mention (Recon -> Initial Access -> Lateral Movement -> C2 ->
Exfiltration), each rule tagged with a MITRE ATT&CK technique ID. This is
the same "explainability" idea as their SHAP/Attention layer, just with
if/else instead of a model -- every alert says exactly *why* it fired.

Swapping this module for a trained model later is a drop-in replacement:
keep the same `analyze_flows(flows) -> alerts` contract.
"""

from collections import defaultdict

PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.2", "172.3", "192.168.")


def _is_private(ip: str) -> bool:
    return ip.startswith(PRIVATE_PREFIXES) or ip.startswith("127.")


LATERAL_MOVEMENT_PORTS = {22, 23, 445, 3389, 5985, 5986}  # SSH, Telnet, SMB, RDP, WinRM


def analyze_flows(flows):
    """
    Runs every heuristic rule over the flow list and returns:
      - scored_flows: flows with a risk_score (0-100) and list of triggered rules
      - alerts: the subset of flows that crossed the alert threshold, each
                tagged with a MITRE tactic + technique
    """
    scored_flows = [dict(f, risk_score=0, tags=[]) for f in flows]
    by_id = {f["flow_id"]: f for f in scored_flows}

    _rule_port_scan(scored_flows, by_id)
    _rule_brute_force(scored_flows, by_id)
    _rule_lateral_movement(scored_flows, by_id)
    _rule_beaconing(scored_flows, by_id)
    _rule_exfiltration(scored_flows, by_id)

    for f in scored_flows:
        f["risk_score"] = min(f["risk_score"], 100)

    alerts = [f for f in scored_flows if f["risk_score"] >= 30]
    alerts.sort(key=lambda f: f["risk_score"], reverse=True)

    return scored_flows, alerts


def _tag(flow, points, tactic, technique, technique_id, reason):
    flow["risk_score"] += points
    flow["tags"].append({
        "tactic": tactic,
        "technique": technique,
        "technique_id": technique_id,
        "reason": reason,
    })


def _rule_port_scan(flows, by_id):
    """Recon: one source IP hitting many distinct destination ports on the
    same destination IP within the capture -> classic port scan (T1046)."""
    src_dst_ports = defaultdict(set)
    src_dst_flowids = defaultdict(list)

    for f in flows:
        if f["dst_port"] is None:
            continue
        key = (f["src_ip"], f["dst_ip"])
        src_dst_ports[key].add(f["dst_port"])
        src_dst_flowids[key].append(f["flow_id"])

    for key, ports in src_dst_ports.items():
        if len(ports) >= 6:
            for fid in src_dst_flowids[key]:
                _tag(by_id[fid], 40, "Reconnaissance",
                     "Network Service Scanning", "T1046",
                     f"{key[0]} probed {len(ports)} distinct ports on {key[1]}")


def _rule_brute_force(flows, by_id):
    """Initial Access: many short connection attempts to the same
    service port -> credential brute forcing (T1110)."""
    src_dst_port_counts = defaultdict(list)

    for f in flows:
        if f["dst_port"] is None:
            continue
        key = (f["src_ip"], f["dst_ip"], f["dst_port"])
        src_dst_port_counts[key].append(f)

    for key, group in src_dst_port_counts.items():
        total_packets = sum(f["packet_count"] for f in group)
        if len(group) >= 5 and total_packets / len(group) <= 4:
            for f in group:
                _tag(f, 35, "Initial Access", "Brute Force", "T1110",
                     f"{len(group)} repeated low-packet connections from "
                     f"{key[0]} to {key[1]}:{key[2]}")


def _rule_lateral_movement(flows, by_id):
    """Lateral Movement: internal host talking to another internal host
    over an admin/remote-access port (T1021)."""
    for f in flows:
        if (f["dst_port"] in LATERAL_MOVEMENT_PORTS
                and _is_private(f["src_ip"]) and _is_private(f["dst_ip"])):
            _tag(f, 30, "Lateral Movement", "Remote Services", "T1021",
                 f"internal host {f['src_ip']} reached {f['dst_ip']} on "
                 f"admin port {f['dst_port']}")


def _rule_beaconing(flows, by_id):
    """Command & Control: small, low-volume flow to an external IP that
    repeats -- a very rough stand-in for C2 beaconing (T1071)."""
    dst_flow_count = defaultdict(list)
    for f in flows:
        if not _is_private(f["dst_ip"]):
            dst_flow_count[(f["src_ip"], f["dst_ip"])].append(f)

    for key, group in dst_flow_count.items():
        avg_size = sum(f["avg_packet_size"] for f in group) / len(group)
        if len(group) >= 4 and avg_size < 200:
            for f in group:
                _tag(f, 25, "Command and Control",
                     "Application Layer Protocol", "T1071",
                     f"{len(group)} small repeated flows from {key[0]} to "
                     f"external {key[1]} (avg {avg_size:.0f} bytes/flow)")


def _rule_exfiltration(flows, by_id):
    """Exfiltration: large outbound byte volume, in a short window, to an
    external IP (T1041)."""
    for f in flows:
        if (not _is_private(f["dst_ip"]) and f["byte_count"] > 200_000
                and f["duration"] < 30):
            _tag(f, 45, "Exfiltration", "Exfiltration Over C2 Channel",
                 "T1041",
                 f"{f['byte_count']} bytes sent from {f['src_ip']} to "
                 f"external {f['dst_ip']} in {f['duration']}s")


def summarize(records, scored_flows, alerts):
    """High-level numbers for the dashboard's overview cards."""
    protocol_counts = defaultdict(int)
    for r in records:
        protocol_counts[r["protocol"]] += 1

    tactic_counts = defaultdict(int)
    for a in alerts:
        for tag in a["tags"]:
            tactic_counts[tag["tactic"]] += 1

    return {
        "total_packets": len(records),
        "total_flows": len(scored_flows),
        "total_alerts": len(alerts),
        "protocol_breakdown": dict(protocol_counts),
        "tactic_breakdown": dict(tactic_counts),
        "capture_start": min((r["time"] for r in records), default=None),
        "capture_end": max((r["time"] for r in records), default=None),
    }
