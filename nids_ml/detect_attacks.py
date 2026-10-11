#!/usr/bin/env python3
"""
Nimda Worm & Rate-Based Intrusion Detector
Portfolio project - NIDS ML Pipeline
Analyzes .pcap files and outputs JSON for Splunk ingestion.
"""

import os
import json
from collections import defaultdict
from datetime import datetime
from scapy.all import rdpcap, IP, TCP

THRESHOLD = 40
PCAP_FILE = "nids_ml/data/simulated_traffic.pcap"
LOG_FILE = "nids_ml/logs/detections.log"
JSON_FILE = "nids_ml/logs/detections.json"


def is_nimda_worm(packet):
    """Check for Nimda worm signature in HTTP traffic."""
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        payload = bytes(packet[TCP].payload)
        return b"GET /scripts/root.exe" in payload
    return False


def log_event(message):
    """Append a message to the detection log file."""
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {message}\n")


def analyze_pcap(pcap_file):
    """Analyze a .pcap file and flag malicious traffic."""
    if not os.path.exists(pcap_file):
        print(f"[-] Error: {pcap_file} not found.")
        print(f"    Run simulate_traffic.py first.")
        return None

    print(f"[*] Loading packets from {pcap_file}")
    packets = rdpcap(pcap_file)
    print(f"[*] Analyzing {len(packets)} packets...")
    print(f"[*] Threshold: {THRESHOLD} packets\n")

    packet_count = defaultdict(int)
    blocked_ips = set()
    nimda_detections = 0
    rate_violations = 0

    for packet in packets:
        if not packet.haslayer(IP):
            continue

        src_ip = packet[IP].src

        # Nimda worm signature detection
        if is_nimda_worm(packet):
            if src_ip not in blocked_ips:
                print(f"[BLOCK] Nimda worm from: {src_ip}")
                log_event(f"Nimda worm detected: {src_ip}")
                blocked_ips.add(src_ip)
            nimda_detections += 1
            continue

        # Rate-based detection
        packet_count[src_ip] += 1
        if packet_count[src_ip] > THRESHOLD and src_ip not in blocked_ips:
            print(f"[BLOCK] Rate violation: {src_ip} ({packet_count[src_ip]} packets)")
            log_event(f"Rate violation: {src_ip} ({packet_count[src_ip]} packets)")
            rate_violations += 1
            blocked_ips.add(src_ip)

    # Build result summary
    results = {
        "scan_time": datetime.now().isoformat(),
        "total_packets": len(packets),
        "nimda_detections": nimda_detections,
        "rate_violations": rate_violations,
        "total_blocked_ips": len(blocked_ips),
        "blocked_ips": sorted(list(blocked_ips))
    }

    # Save JSON for Splunk
    os.makedirs(os.path.dirname(JSON_FILE), exist_ok=True)
    with open(JSON_FILE, "w") as f:
        json.dump(results, f, indent=4)

    # Print summary
    print("\n" + "=" * 50)
    print("DETECTION SUMMARY")
    print("=" * 50)
    print(f"Total packets analyzed:  {results['total_packets']}")
    print(f"Nimda detections:        {results['nimda_detections']}")
    print(f"Rate violations:         {results['rate_violations']}")
    print(f"Total IPs blocked:       {results['total_blocked_ips']}")
    print(f"Blocked IPs:             {', '.join(results['blocked_ips']) if results['blocked_ips'] else 'None'}")
    print("=" * 50)
    print(f"\n[+] Log saved to:  {LOG_FILE}")
    print(f"[+] JSON saved to: {JSON_FILE}")

    return results


if __name__ == "__main__":
    analyze_pcap(PCAP_FILE)
