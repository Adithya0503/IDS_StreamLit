import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# --- PAGE CONFIG ---
st.set_page_config(page_title="Windows AI Security Analyzer Pro", layout="wide")

st.title("🛡️ Windows AI Security Anomaly Detection System")

st.markdown("""
### 📋 Instructions
1. **Download** the `audit_collector.cmd` file below.
2. **Run** it on your Windows machine. It will automatically install requirements and perform the scan.
3. **Upload** all CSV files from the generated `audit_output` folder to this dashboard.
4. **Enter an email** to receive the summarized PDF security report.
""")

# -------------------------------------------------------
# STEP 1: DYNAMIC CMD GENERATOR
# -------------------------------------------------------
st.header("📥 Step 1: Download Audit Collector")

# This is the "One-Click" script that installs libraries and runs the audit
cmd_code = r"""@echo off
color 0A
title Windows AI Security Audit Collector

echo =====================================================
echo       WINDOWS AI SECURITY DATA COLLECTOR
echo =====================================================
echo.

python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python is NOT installed.
    echo Please install Python from https://www.python.org/
    pause
    exit /b
)

echo [STATUS] Verifying required libraries (psutil)...
pip install psutil --quiet

set SCRIPT_NAME=windows_system_audit.py
echo [STATUS] Preparing audit engine...

(
echo import csv, json, os, platform, re, socket, subprocess, sys, winreg
echo from datetime import datetime
echo import psutil
echo def get_system_info_dict^(^):
echo     hostname = socket.gethostname^(^)
echo     mem = psutil.virtual_memory^(^)
echo     disk = psutil.disk_usage^(os.environ.get^("SystemDrive", "C:"^)^)
echo     return {"Asset_Hostname": hostname, "Memory_Total_GB": round^(mem.total / ^(1024**3^), 2^), "Disk_Total_GB": round^(disk.total / ^(1024**3^), 2^)}
echo def run_audit^(^):
echo     ts = datetime.now^(^).strftime^("%%Y-%%m-%%d %%H:%%M:%%S"^).replace^(":","-"^)
echo     host = socket.gethostname^(^)
echo     folder = f"audit_output/Report_{ts}_{host}"
echo     os.makedirs^(folder, exist_ok=True^)
echo     path = os.path.join^(folder, "03_SYSTEM_INFO.csv"^)
echo     with open^(path, "w", newline="", encoding="utf-8-sig"^) as f:
echo         w = csv.DictWriter^(f, fieldnames=["Audit_Reference_Timestamp", "Asset_Hostname", "Section_Title", "Memory_Total_GB", "Disk_Total_GB"]^)
echo         w.writeheader^(^)
echo         data = get_system_info_dict^(^)
echo         data.update^({"Audit_Reference_Timestamp": ts, "Section_Title": "SYSTEM_INFO"^}^)
echo         w.writerow^(data^)
echo     print^(f"Audit completed. Folder: {folder}"^)
echo if __name__ == "__main__": run_audit^(^)
) > %SCRIPT_NAME%

echo [STATUS] Running System Audit...
python %SCRIPT_NAME%

echo.
echo =====================================================
echo AUDIT COMPLETED SUCCESSFULLY
echo Please upload the CSV files from the 'audit_output' folder.
echo =====================================================
explorer audit_output
pause
"""

st.download_button(
    label="Download Audit Collector (.cmd)",
    data=cmd_code,
    file_name="audit_collector.cmd",
    mime="application/octet-stream"
)

# -------------------------------------------------------
# STEP 2: UPLOAD & ANALYSIS
# -------------------------------------------------------
st.header("📤 Step 2: Upload Generated CSV Files")

uploaded_files = st.file_uploader(
    "Select all CSV files from your report folder", 
    type=["csv"], 
    accept_multiple_files=True
)

if uploaded_files:
    file_map = {file.name.upper(): pd.read_csv(file) for file in uploaded_files}
    
    # --- AI RISK ANALYSIS ---
    # Isolation Forest looks for statistical outliers in numeric telemetry
    all_numeric = pd.concat([df.select_dtypes(include=['number']) for df in file_map.values()], axis=1).fillna(0)

    risk_score = 0
    if not all_numeric.empty:
        model = IsolationForest(n_estimators=150, contamination=0.05, random_state=42)
        preds = model.fit_predict(all_numeric) # 1 = Normal, -1 = Anomaly
        
        total_points = len(preds)
        anomalies = (preds == -1).sum()
        risk_score = round((anomalies / total_points) * 100, 2)

        c1, c2, c3 = st.columns(3)
        c1.metric("Telemetry Records", total_points)
        c2.metric("Anomalies Detected", anomalies)
        c3.metric("Risk Score", f"{risk_score}%")

    # --- CATEGORIZED TABS ---
    tab1, tab2, tab3 = st.tabs(["🌐 Network", "⚙️ Processes", "🛡️ Security & Users"])

    def clean_df(df):
        return df.drop(columns=["Audit_Reference_Timestamp", "Asset_Hostname", "Section_Title"], errors='ignore')

    with tab1:
        for name, df in file_map.items():
            if any(k in name for k in ["PORT", "CONNECTION", "IP"]):
                st.dataframe(clean_df(df), use_container_width=True)

    with tab2:
        for name, df in file_map.items():
            if any(k in name for k in ["PROCESS", "STARTUP", "PROGRAM"]):
                st.dataframe(clean_df(df), use_container_width=True)

    with tab3:
        for name, df in file_map.items():
            if any(k in name for k in ["USER", "ADMIN", "POLICY", "STATUS", "FIREWALL"]):
                st.dataframe(clean_df(df), use_container_width=True)

    # -------------------------------------------------------
    # STEP 3: EMAIL PDF REPORT (FIXED CONNECTIVITY)
    # -------------------------------------------------------
    st.divider()
    st.header("📧 Step 3: Send PDF Report")
    
    first_df = list(file_map.values())[0]
    device_name = first_df["Asset_Hostname"].iloc[0] if "Asset_Hostname" in first_df.columns else "Unknown_Device"

    recipient_email = st.text_input("Enter the recipient's email address")
    
    if st.button("Send Report to Entered Email"):
        if recipient_email:
            try:
                # 1. Generate PDF
                pdf_path = f"Security_Report_{device_name}.pdf"
                canvas_obj = canvas.Canvas(pdf_path, pagesize=letter)
                canvas_obj.setFont("Helvetica-Bold", 16)
                canvas_obj.drawString(50, 750, f"AI Security Audit: {device_name}")
                canvas_obj.setFont("Helvetica", 12)
                canvas_obj.drawString(50, 730, f"Risk Score: {risk_score}%")
                canvas_obj.save()

                # 2. Setup Credentials (Sourced from Secrets)
                SENDER_EMAIL = st.secrets["SENDER_EMAIL"]
                SENDER_PASSWORD = st.secrets["SENDER_PASSWORD"]

                msg = MIMEMultipart()
                msg['From'] = SENDER_EMAIL
                msg['To'] = recipient_email 
                msg['Subject'] = f"🛡️ Windows Security Report - {device_name}"
                msg.attach(MIMEText(f"Attached is the security report for {device_name}.\nRisk Score: {risk_score}%", 'plain'))

                with open(pdf_path, "rb") as f:
                    part = MIMEApplication(f.read(), Name=pdf_path)
                    part['Content-Disposition'] = f'attachment; filename="{pdf_path}"'
                    msg.attach(part)

                # 3. Secure Connection using Port 587 (STARTTLS)
                server = smtplib.SMTP("smtp.gmail.com", 587)
                server.starttls() 
                server.login(SENDER_EMAIL, SENDER_PASSWORD)
                server.send_message(msg)
                server.quit()

                st.success(f"✅ Security report successfully sent to {recipient_email}")
                os.remove(pdf_path)

            except Exception as e:
                st.error(f"Error sending email: {e}")
        else:
            st.warning("Please enter a valid email address.")
else:
    st.info("Upload CSV files to begin.")
