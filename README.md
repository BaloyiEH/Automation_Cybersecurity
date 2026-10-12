# Automation & Cybersecurity Portfolio

Welcome to my cybersecurity automation portfolio. This repository contains Python tools, detection scripts, and ML pipelines I am building as I transition into a SOC Analyst role.

---

##  About Me

- **Name:** Elphas Baloyi
- **Location:** Gauteng, Roodepoorte | Western Cape, Cape Town| Limpopo (Polokwane) | available remotely (also willing to relocate)
- **Career Goal:** SOC Analyst / Blue Team / Security Automation
- **Background:** BSc Computer Science (completing November 2026)
- **Certifications:**
  - Cisco Cybersecurity Defense Analyst (Intermediate) — Completed 2026
  - Cisco Introduction to Cybersecurity — Completed 2026
- **Currently Building:**
  - SOC skills through Let's Defend simulations
  - Python automation for security operations
  - Splunk SIEM dashboards and log analysis
  - Machine learning for network intrusion detection

---

## Technical Skills

| Category | Skills |
|---|---|
| **Scripting & Automation** | Python, file handling, APIs, JSON |
| **Security Tools** | Nmap (CLI + Zenmap), Splunk, Scapy, Wireshark (basic) |
| **Machine Learning** | scikit-learn, Random Forest, anomaly detection, feature extraction |
| **Operating Systems** | Windows, Linux (WSL/Ubuntu) |
| **Networking** | TCP/IP, OSI model, subnetting, ports & protocols |
| **Version Control** | Git, GitHub, GitHub Codespaces |
| **Security Concepts** | Threat detection, incident response, log analysis, MITRE ATT&CK (foundational) |

---

## Projects

### 1. Nmap Automation Scanner
**Folder:** `nmap_scanner/` *(or root-level `first_scan.py`)*

A Python script that automates Nmap network scans and outputs structured JSON results ready for SIEM ingestion.

- **Tech:** Python, python-nmap, GitHub Codespaces
- **Output:** JSON reports of open ports, services, and host states
- **Skills demonstrated:** Network discovery, automation, structured output for SIEM

---

### 2. Network Intrusion Detection System (NIDS) with ML
**Folder:** `nids_ml/`

An end-to-end pipeline that simulates network traffic, detects malicious activity (Nimda worm + rate-based anomalies), and prepares data for machine learning classification.

- **Tech:** Python, Scapy, scikit-learn, JSON
- **Components:**
  - `simulate_traffic.py` — Generates labeled normal and malicious packets
  - `detect_attacks.py` — Detects Nimda worm signatures and rate violations, outputs JSON
  - `train_model.py` — Random Forest classifier (in progress)
- **Output:** `.pcap` files, detection logs, JSON reports for Splunk
- **Skills demonstrated:** Packet analysis, signature-based detection, anomaly detection, ML pipeline design
