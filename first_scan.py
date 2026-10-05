#!/usr/bin/env python3
"""
First Nmap Automation Script
Portfolio project - SOC Automation Lab
Author: Elphas Baloyi
"""

import nmap
import json
import os
from datetime import datetime


def run_scan(target):
    """Run a basic Nmap scan and return the scanner object."""
    print(f"[*] Starting scan on {target} at {datetime.now().strftime('%H:%M:%S')}")
    
    scanner = nmap.PortScanner()
    
    # -sT = TCP connect scan (no root needed)
    # -Pn = skip ping check
    # -T4 = faster timing
    scanner.scan(hosts=target, arguments='-sT -Pn -T4 --top-ports 100')
    
    return scanner


def display_results(scanner, target):
    """Print the scan results in a readable format."""
    print(f"\n[+] Scan complete\n")
    
    # Check if any hosts were found at all
    all_hosts = scanner.all_hosts()
    if not all_hosts:
        print(f"[-] No hosts found in scan results.")
        return None
    
    # Use the actual host key that Nmap returned
    host = all_hosts[0]
    print(f"Requested target: {target}")
    print(f"Resolved host:    {host}")
    print(f"Host State:       {scanner[host].state()}")
    print("-" * 40)
    
    # Loop through protocols and ports
    found_any = False
    for proto in scanner[host].all_protocols():
        print(f"Protocol: {proto.upper()}")
        ports = sorted(scanner[host][proto].keys())
        
        for port in ports:
            service = scanner[host][proto][port]
            version = service.get('version', '')
            product = service.get('product', '')
            print(f"  Port {port}: {service['state']} | {service['name']} | {product} {version}".strip())
            found_any = True
    
    if not found_any:
        print("  No open ports detected.")
    
    print("-" * 40)
    return host


def save_results(scanner, host, target):
    """Save the scan results to a JSON file for later use in Splunk."""
    if host is None:
        print(f"[-] No data to save.")
        return
    
    # Create a results folder if it doesn't exist
    os.makedirs("results", exist_ok=True)
    
    safe_name = target.replace('.', '_').replace(':', '_')
    filename = f"results/scan_{safe_name}.json"
    
    with open(filename, 'w') as f:
        json.dump(scanner[host], f, indent=4)
    
    print(f"[+] Results saved to {filename}")


if __name__ == "__main__":
    target = "127.0.0.1"
    
    scanner = run_scan(target)
    host = display_results(scanner, target)
    save_results(scanner, host, target)