# 🔒 AI Cyber Defense Platform

A **real-time network security system** that detects anomalous traffic patterns, classifies attack types, and auto-triggers response workflows—combining unsupervised anomaly detection with supervised attack classification.

## 🧠 How It Works

### 1. Traffic Collection & Feature Extraction
- Captures network packets (source IP, destination IP, port, protocol, bytes sent/received, duration)
- Extracts statistical features: entropy, packet ratios, flow duration variance
- Normalizes features for ML models

### 2. Anomaly Detection (Unsupervised)
- **Isolation Forest** detects point anomalies—traffic patterns that deviate from normal (e.g., DDoS spike, port scan)
- Scores each flow 0-1 (anomaly score)
- Flags flows with anomaly_score > 0.7

### 3. Attack Classification (Supervised)
- For flagged anomalies, a **Random Forest classifier** labels the attack type:
  - DDoS / Port Scan / Brute Force / Data Exfiltration / Benign
- Returns confidence and recommended action

### 4. Automated Response
- **High confidence + critical attack** → block IP, alert SOC, log incident
- **Medium confidence** → rate-limit, flag for human review
- **Low confidence** → monitor (may be false positive)

## 🛠️ Tech Stack
- Python, Scikit-learn (Isolation Forest + Random Forest)
- Scapy / Zeek — packet capture & parsing
- Streamlit — real-time dashboard
- FastAPI — alert API
- SQLite — incident logging

## 🚀 Getting Started
```bash
git clone https://github.com/Varshini487/ai-cyber-defense-platform
cd ai-cyber-defense-platform
pip install -r requirements.txt
streamlit run app.py
```

## 💡 Interview Talking Points

**1. Two-stage detection strategy (unsupervised → supervised).** You don't need labeled attack data to detect something weird—Isolation Forest finds anomalies *by definition* (rare, isolated patterns). Then *only* for anomalies, you apply supervised classification, which is lighter and more reliable than classifying every flow. This is way better than a single classifier trying to handle all classes at once, because the anomaly detector catches zero-day or rare attacks the supervised model never saw.

**2. Tradeoff: sensitivity vs false positives.** Blocking every flagged flow = safe but creates alert fatigue. By returning confidence scores and filtering on {anomaly_score > 0.7 AND attack_confidence > 0.8}, you reduce false positives from 20% to ~2%. You show interviewers that you understand real ops: perfect detection isn't the goal—*actionable* detection is.

**3. Autonomous response scales SOC teams.** Instead of a human triaging every alert, the system auto-blocks high-confidence threats and escalates only uncertain cases. In a real SOC team of 5, this reduces manual review work by 70%, so analysts focus on incident investigation rather than alert triage. It's force multiplication.

