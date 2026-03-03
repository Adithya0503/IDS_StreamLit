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
```
## Step 2: Clone or Download Project

If using Git:

```bash
git clone https://github.com/Adithya0503/IDS_StreamLit
cd IDS_StreamLit
```
Or download ZIP and extract.

## Step 3: Create Virtual Environment (Recommended)

```bash
python -m venv venv
```
Activate it:
```bash
venv\Scripts\activate
```
If You Get PowerShell Execution Error
Run once:
```bash
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```
Then activate venv again.

## Step 4: Install Dependencies
```bash
pip install -r requirements.txt
```

## Step 5: Run the Streamlit Application
```bash
streamlit run app.py
```
The browser will automatically open at:
```bash
http://localhost:8501
```

# 🌐 How to Use the Application

Download the Audit Script (.cmd)

Run it on your Windows machine

CSV file will be generated

Upload the CSV file to the Streamlit app

View anomaly results and risk analysis

# 🏗 How We Performed the Project
### Phase 1 – Research

Studied AI-based anomaly detection models

Compared rule-based vs ML-based approaches

Selected Isolation Forest for unsupervised anomaly detection

### Phase 2 – Client Script Development

Developed dynamic Windows batch script

Embedded Python code inside CMD

Extracted telemetry and registry data

Generated structured CSV

### Phase 3 – AI Web Application

Built Streamlit interface

Integrated Isolation Forest

Implemented risk scoring logic

Added visualization dashboard

Added installed applications display

### Phase 4 – Deployment

Configured requirements.txt

Deployed using Streamlit Cloud

Tested end-to-end workflow

# 🧾 Conclusion

This project demonstrates how AI can be used to enhance Windows system security auditing by combining:

Local telemetry collection

AI-based anomaly detection

Web-based visualization

Risk assessment framework

It provides a scalable and privacy-aware security monitoring solution suitable for academic and enterprise applications.
