# Network Intrusion Detection System (NIDS) with ML

A Python-based network intrusion detection pipeline that simulates, detects, and classifies malicious traffic using machine learning.

![NIDS SOC Dashboard](screenshots/screenshot(15).png)

## What This Project Does

1. **Simulates network traffic** — generates normal and malicious (Nimda worm) packets using Scapy
2. **Detects attacks** — identifies Nimda worm signatures and rate-based anomalies from .pcap files
3. **Extracts features** — converts each packet into 8 numeric features for ML analysis
4. **Trains a classifier** — Random Forest model that distinguishes normal from malicious traffic
5. **Outputs structured data** — produces JSON reports ready for Splunk SIEM ingestion

## Architecture

```
[simulate_traffic.py]  →  simulated_traffic.pcap
                              ↓
[detect_attacks.py]    →  detections.json  →  Splunk Dashboard
                              ↓
[train_model.py]       →  nids_model.pkl  +  model_metrics.json
```

## Files

| File | Purpose |
|---|---|
| `simulate_traffic.py` | Generates labeled dataset of normal and malicious packets |
| `detect_attacks.py` | Analyzes .pcap, detects attacks, outputs JSON for Splunk |
| `train_model.py` | Trains Random Forest classifier, evaluates performance |

## Model Performance

Based on 100 simulated packets (27 malicious, 73 normal):

| Metric | Score |
|---|---|
| Accuracy | 100% |
| Precision | 100% |
| Recall | 100% |
| F1 Score | 100% |

**Top Features (by importance):**
1. IP Length — 34.22%
2. Packet Size — 25.74%
3. TCP Flags — 20.70%
4. Payload Size — 14.92%
5. Source Port — 2.24%

*Note: The 100% score reflects the synthetic dataset's clean labeling. Real-world traffic is noisier and will reduce accuracy — future work includes testing on public datasets like CICIDS2017.*

## How to Run

```bash
# Install dependencies
pip install -r requirements.txt

# Step 1: Generate traffic data
python nids_ml/simulate_traffic.py

# Step 2: Detect attacks and produce JSON
python nids_ml/detect_attacks.py

# Step 3: Train and evaluate the ML model
python nids_ml/train_model.py
```

## Outputs

| File | Purpose |
|---|---|
| `nids_ml/data/simulated_traffic.pcap` | Raw packet capture (not committed) |
| `nids_ml/logs/detections.log` | Timestamped detection events (not committed) |
| `nids_ml/logs/detections.json` | Structured JSON for Splunk (not committed) |
| `nids_ml/models/nids_model.pkl` | Trained classifier (not committed) |
| `nids_ml/logs/model_metrics.json` | Performance metrics (not committed) |

## Skills Demonstrated

- Packet crafting and analysis with Scapy
- Signature-based detection (Nimda worm)
- Rate-based anomaly detection
- Feature engineering for ML (8 numeric features)
- Random Forest classification with scikit-learn
- Model evaluation (accuracy, precision, recall, F1, confusion matrix)
- Model persistence and JSON reporting for SIEM integration
- Python automation and file handling

## Credits

The detection logic is adapted from public NIDS tutorials. Substantial modifications include:
- Modular function structure with docstrings
- JSON output for SIEM integration
- Rate-based detection added alongside signature detection
- ML feature extraction and Random Forest training
- Error handling and timestamped logging
- Designed to feed into a Splunk dashboard

## Next Steps

- [ ] Test on public datasets (CICIDS2017, NSL-KDD)
- [ ] Build Splunk dashboard from detection JSON
- [ ] Add more attack signatures (SQL injection, port scans, XSS)
- [ ] Automate the pipeline with Splunk HEC
- [ ] Containerize with Docker for portability
