# Automation & Cybersecurity Portfolio

Welcome to my cybersecurity automation portfolio. This repository contains Python tools, detection scripts, and ML pipelines I am building as I transition into a SOC Analyst role.

---

##  About Me

- **Name:** Elphas Baloyi
- **Location:** South Africa | Willing to relocate
- **Career Goal:** SOC Analyst / Blue Team / Security Automation
- **Background:** BSc Computer Science (completing November 2026)
- **Certifications:**
  - Cisco Cybersecurity Defense Analyst (Intermediate) — 2026
  - Cisco Introduction to Cybersecurity — 2026
  - GenAI Course for Software Engineers — WeThinkCode_ — 2026
- **Currently Building:**
  - SOC skills through Let's Defend simulations
  - Python automation for security operations
  - Splunk SIEM dashboards and log analysis
  - Machine learning for network intrusion detection

---

## 🛠️ Technical Skills

| Category | Skills |
|---|---|
| **Scripting & Automation** | Python, Bash, file handling, APIs, JSON |
| **Security Tools** | Nmap (CLI + Zenmap), Splunk, Scapy, Wireshark (basic) |
| **Machine Learning** | scikit-learn, Random Forest, anomaly detection, feature extraction |
| **Operating Systems** | Windows, Linux (WSL/Ubuntu) |
| **Networking** | TCP/IP, OSI model, subnetting, ports & protocols |
| **Version Control** | Git, GitHub, GitHub Codespaces |
| **Security Concepts** | Threat detection, incident response, log analysis, MITRE ATT&CK (foundational) |

---

## 📁 Projects

### 1. Network Intrusion Detection System (NIDS) with ML
**Folder:** [`nids_ml/`](nids_ml/)

An end-to-end pipeline that simulates network traffic, detects malicious activity (Nimda worm + rate-based anomalies), and prepares data for machine learning classification.

- **Tech:** Python, Scapy, scikit-learn, JSON, Splunk
- **Components:**
  - `simulate_traffic.py` — Generates labeled normal and malicious packets
  - `detect_attacks.py` — Detects Nimda worm signatures and rate violations, outputs JSON
  - `train_model.py` — Random Forest classifier (100% accuracy on synthetic data)
- **Output:** Splunk SOC dashboard with 4 panels
- **Skills demonstrated:** Packet analysis, signature detection, anomaly detection, ML pipeline design, SIEM integration

### 2. Nmap Automation Scanner
**File:** [`first_scan.py`](first_scan.py)

A Python script that automates Nmap network scans and outputs structured JSON results ready for SIEM ingestion.

- **Tech:** Python, python-nmap, GitHub Codespaces
- **Output:** JSON reports of open ports, services, and host states
- **Skills demonstrated:** Network discovery, automation, structured output for SIEM

---

## 🚀 How to Use This Repo

### Option 1: GitHub Codespaces (Recommended)

1. Click the green **Code** button → **Codespaces** → **Create codespace on main**
2. Wait for the environment to build (about 1–2 minutes)
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run any project:
   ```bash
   python nids_ml/simulate_traffic.py
   python nids_ml/detect_attacks.py
   python nids_ml/train_model.py
   ```

### Option 2: Clone Locally

```bash
git clone https://github.com/BaloyiEH/Automation_Cybersecurity.git
cd Automation_Cybersecurity
pip install -r requirements.txt
```

---

## 📦 Requirements

All Python dependencies are listed in `requirements.txt`. Key libraries:

- `scapy` — Packet crafting and analysis
- `python-nmap` — Nmap automation
- `requests` — HTTP requests for API integration
- `pandas` — Data analysis
- `scikit-learn` — Machine learning

Install all at once:
```bash
pip install -r requirements.txt
```

---

## 📊 Skills Demonstrated Across Projects

| Skill | Where It's Shown |
|---|---|
| Python scripting & automation | All projects |
| Network scanning | `first_scan.py` |
| Packet crafting & analysis | `nids_ml/simulate_traffic.py` |
| Attack signature detection | `nids_ml/detect_attacks.py` |
| Anomaly detection (rate-based) | `nids_ml/detect_attacks.py` |
| SIEM integration (JSON output) | All projects |
| Machine learning pipeline | `nids_ml/train_model.py` |
| Splunk dashboard creation | `nids_ml/Screenshots/` |
| Cloud dev environments | GitHub Codespaces |
| Linux command line | WSL, Codespaces |
| Git version control | Every commit |

---

## 🎯 Current Focus

- Completing the Let's Defend SOC Analyst path
- Building a phishing email analyzer and brute force detector
- Preparing for CompTIA Security+ and CySA+
- Applying for entry-level SOC Analyst roles in South Africa

---

## 📬 Contact

- **GitHub:** [@BaloyiEH](https://github.com/BaloyiEH)


---

## 📜 Credits & Acknowledgements

This portfolio is built on continuous learning from multiple sources, including:

- Cisco Networking Academy (Skills for All)
- TryHackMe and Let's Defend (hands-on SOC training)
- Public NIDS tutorials and open-source security tools
- WeThinkCode_ (GenAI engineering course)
- The broader cybersecurity community

Where code is adapted from public sources, this is noted in the project-specific README files. All modifications, extensions, and documentation are my own.

---

*Built with a focus on practical security automation and continuous improvement.*