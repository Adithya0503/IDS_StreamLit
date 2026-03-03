# 🛡 Windows AI Security Anomaly Detection System

## 📌 Project Overview

The **Windows AI Security Anomaly Detection System** is a client-assisted web-based security auditing solution that detects abnormal system behavior using Artificial Intelligence.

This project allows users to:

1. Download a lightweight Windows audit script
2. Run the script locally to collect system telemetry
3. Upload the generated CSV file to a web application
4. Analyze the system using an AI anomaly detection model
5. View risk score, severity level, visual analytics, and installed applications

---

# 🎯 Main Objective

The main objective of this project is:

- To automate Windows system security auditing
- To detect abnormal system behavior using AI
- To provide a centralized web-based anomaly detection interface
- To separate data collection (client-side) from AI analysis (server-side)
- To create a scalable and privacy-preserving security solution

---

# 🧠 Technologies Used

- **Python**
- **Streamlit** (Web Application Framework)
- **Scikit-learn (Isolation Forest)** (AI Model)
- **Pandas** (Data Processing)
- **Matplotlib** (Visualization)
- **Windows Batch Script (.cmd)**
- **Windows Registry (winreg)**

---

# 🔎 How Scanning Works

The system follows a two-stage architecture:

## Stage 1 – Client-Side Data Collection

A Windows CMD script:

- Checks if Python is installed
- Installs required dependency (`psutil`)
- Collects:
  - CPU usage
  - Memory usage
  - Running processes
  - Open ports
  - Installed applications (via Windows Registry)
- Saves data into a structured CSV file

This ensures:
- No remote execution
- User privacy maintained
- Secure local data collection

---

## Stage 2 – AI-Based Anomaly Detection

After CSV upload:

- Data is validated
- Numeric features are extracted
- Isolation Forest model is applied
- Anomalies are detected
- Risk score is calculated
- Severity classification is determined
- Visual dashboards are generated

---

# 🤖 AI Model Used

## Isolation Forest (Unsupervised Learning)

Isolation Forest is used because:

- It does not require labeled attack data
- It detects statistical outliers
- It is lightweight and efficient
- It is suitable for tabular system telemetry

Anomaly prediction mapping:
- `1 → Normal`
- `-1 → Anomaly`

---

# 📊 Features

- Downloadable Windows audit script
- AI-based anomaly detection
- Risk score calculation
- Severity classification (Low / Medium / High)
- Pie chart visualization
- Bar graph visualization
- Installed applications inventory display
- Clean and user-friendly interface

---

# ⚠ Limitations

- Works only on Windows client systems
- Requires Python installed on client machine
- Isolation Forest is statistical (not signature-based detection)
- Does not perform deep malware analysis
- Depends on uploaded CSV integrity

---

# 🚀 Future Scope

- Add authentication and login system
- Store historical scan reports in database
- Add downloadable PDF security report
- Add suspicious application blacklist detection
- Add interactive Plotly dashboards
- Integrate Zero-Trust architecture
- Deploy as enterprise endpoint security system
- Convert into agent-based automatic reporting system
- Add deep learning anomaly detection (Autoencoder)

---

# 👥 Team

- **Adithya Vallabhaneni**

---

# 🛠 LOCAL DEPLOYMENT GUIDE

Follow these steps to run this project locally.

---

## Step 1: Install Python

Download Python from:

👉 https://www.python.org/downloads/

During installation:
- ✅ Check "Add Python to PATH"
- Click Install

Verify installation:

```bash
python --version
