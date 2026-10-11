#!/usr/bin/env python3
"""
Network Traffic Simulator - NIDS ML Pipeline
Portfolio project - SOC Automation Lab
Generates synthetic normal and malicious packets for ML training.
"""

from scapy.all import IP, TCP, Raw, wrpcap
from datetime import datetime
import os
import random


def build_nimda_packet(target_ip, source_ip):
    """Build a Nimda worm packet (malicious HTTP request)."""
    return (
        IP(src=source_ip, dst=target_ip)
        / TCP(sport=random.randint(1024, 65535), dport=80, flags="S")
        / Raw(load="GET /scripts/root.exe HTTP/1.0\r\nHost: example.com\r\n\r\n")
    )


def build_normal_packet(target_ip, source_ip):
    """Build a normal HTTP GET packet."""
    return (
        IP(src=source_ip, dst=target_ip)
        / TCP(sport=random.randint(1024, 65535), dport=80, flags="A")
        / Raw(load="GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
    )


def build_ssh_packet(target_ip, source_ip):
    """Build a normal SSH packet."""
    return (
        IP(src=source_ip, dst=target_ip)
        / TCP(sport=random.randint(1024, 65535), dport=22, flags="A")
        / Raw(load=b"\x00" * 40)
    )


def generate_traffic(count=100, output_file="nids_ml/data/simulated_traffic.pcap"):
    """Generate a mixed dataset of normal and malicious packets."""
    packets = []
    target_ips = ["192.168.1.10", "192.168.1.20", "192.168.1.30"]
    attacker_ips = ["10.0.0.66", "10.0.0.99"]

    print(f"[*] Generating {count} packets at {datetime.now().strftime('%H:%M:%S')}")
    print(f"[*] Output: {output_file}\n")

    for i in range(count):
        target = random.choice(target_ips)

        # 30% malicious (Nimda), 70% normal
        if random.random() < 0.30:
            source = random.choice(attacker_ips)
            packets.append(build_nimda_packet(target, source))
            label = "MALICIOUS (Nimda)"
        else:
            source = f"192.168.1.{random.randint(100, 200)}"
            if random.random() < 0.5:
                packets.append(build_normal_packet(target, source))
                label = "normal (HTTP)"
            else:
                packets.append(build_ssh_packet(target, source))
                label = "normal (SSH)"

        if (i + 1) % 10 == 0:
            print(f"  [{i+1}/{count}] last: {label}")

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    wrpcap(output_file, packets)

    print(f"\n[+] Saved {len(packets)} packets to {output_file}")
    print(f"[+] File size: {os.path.getsize(output_file)} bytes")


if __name__ == "__main__":
    generate_traffic(count=100)
