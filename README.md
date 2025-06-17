# FlowGuard

**Your Smart Assistant for Detecting Dangerous Network Connections**

FlowGuard is a lightweight and intuitive tool designed to detect and explain suspicious network activity using machine learning. Built with transparency in mind, it empowers users to understand *why* a connection is flagged, not just *that* it is.

## 🔍 What It Does

FlowGuard analyzes real-world network connection data and classifies each connection as **benign** or **malicious**. It provides clear explanations for each classification using a beginner-friendly and robust **Random Forest** model.

## 🌐 Dataset

- Source: [Kaggle – Network Malware Detection](https://www.kaggle.com/datasets/agungpambudi/network-malware-detection-connection-analysis/versions/1/data)
- Over 220,000 connection records
- Key features: `Duration`, `Ports`, `Protocol`, `Bytes Sent/Received`, `Label` (safe or malicious)

## 🧠 How It Works

1. **Data Preparation**: Cleans and encodes network logs.
2. **Model Training**: Learns from labeled data using Random Forest.
3. **Prediction & Explanation**: Flags suspicious activity and explains the reasoning behind each decision.

## 💡 Why FlowGuard?

- ✅ Simple, fast, and interpretable
- ✅ No deep technical expertise required
- ✅ Transparent results, not black-box predictions
- ✅ Real-time feedback via a clean web interface (coming soon)

---

_This repository will soon include all relevant source code, data processing steps, model training scripts, and the web application interface._

Stay tuned!
