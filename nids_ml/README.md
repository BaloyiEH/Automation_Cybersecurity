# Network Intrusion Detection System (NIDS) with ML

A Python-based network intrusion detection pipeline that simulates, detects, and analyzes malicious traffic patterns.

## What This Project Does

1. **Simulates network traffic** — generates normal and malicious (Nimda worm) packets using Scapy
2. **Detects attacks** — identifies Nimda worm signatures and rate-based anomalies from .pcap files
3. **Outputs structured data** — produces JSON reports ready for Splunk SIEM ingestion
4. **Trains an ML model** (in progress) — uses labeled traffic to classify future attacks

## Architecture
