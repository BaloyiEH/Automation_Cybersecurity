# Network Intrusion Detection System (NIDS) with ML

A Python-based network intrusion detection pipeline that simulates, detects, and classifies malicious traffic using machine learning.

## What This Project Does

1. **Simulates network traffic** — generates normal and malicious (Nimda worm) packets using Scapy
2. **Detects attacks** — identifies Nimda worm signatures and rate-based anomalies from .pcap files
3. **Extracts features** — converts each packet into 8 numeric features for ML analysis
4. **Trains a classifier** — Random Forest model that distinguishes normal from malicious traffic
5. **Outputs structured data** — produces JSON reports ready for Splunk SIEM ingestion

## Architecture
