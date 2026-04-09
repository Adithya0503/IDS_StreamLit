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
2. **Run** it on your Windows machine. It will install `psutil` and run the **Full Formal Audit**.
3. **Upload** all CSV files from the `audit_output` folder to this dashboard.
4. **Enter an email** to receive the summarized PDF security report.
""")

# -------------------------------------------------------
# STEP 1: FULL FORMAL CMD GENERATOR
# -------------------------------------------------------
st.header("📥 Step 1: Download Audit Collector")

# This version contains the full logic to generate many tables
cmd_code = r"""@echo off
color 0A
title Windows AI Security Audit Collector

echo =====================================================
echo       WINDOWS AI SECURITY DATA COLLECTOR (FULL)
echo =====================================================
echo.

python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python is NOT installed.
    pause
    exit /b
)

echo [STATUS] Verifying required libraries (psutil)...
pip install psutil --quiet

set SCRIPT_NAME=full_audit.py
echo [STATUS] Preparing full audit engine...

:: Writing the full multi-file logic to a temp script
(
echo import csv, json, os, platform, re, socket, subprocess, sys, winreg
echo from datetime import datetime
echo import psutil
echo def run_full_audit^(^):
echo     ts = datetime.now^(^).strftime^("%%Y-%%m-%%d %%H-%%M-%%S"^)
echo     host = socket.gethostname^(^)
echo     folder = f"audit_output/Report_{ts}_{host}"
echo     os.makedirs^(folder, exist_ok=True^)
echo     # --- Section 1: Listening Ports ---
echo     with open^(os.path.join^(folder, "04_LISTENING_PORTS.csv"^), "w", newline="", encoding="utf-8-sig"^) as f:
echo         w = csv.writer^(f^)
echo         w.writerow^Context(["Audit_Reference_Timestamp", "Asset_Hostname", "Section_Title", "Port", "Protocol", "PID"]^)
echo         for c in psutil.net_connections^(kind="inet"^):
echo             if c.status == "LISTEN": w.writerow^([ts, host, "LISTENING_PORTS", c.laddr.port, "TCP", c.pid or ""]^)
echo     # --- Section 2: Processes ---
echo     with open^(os.path.join^(folder, "05_RUNNING_PROCESSES.csv"^), "w", newline="", encoding="utf-8-sig"^) as f:
echo         w = csv.writer^(f^)
echo         w.writerow^Context(["Audit_Reference_Timestamp", "Asset_Hostname", "Section_Title", "PID", "Name", "Memory_MB"]^)
echo         for p in psutil.process_iter^(['pid', 'name', 'memory_info']^):
echo             try: w.writerow^([ts, host, "PROCESSES", p.info['pid'], p.info['name'], round^(p.info['memory_info'].rss/1024/1024, 2^)]^)
echo             except: pass
echo     # --- Section 3: Users ---
echo     with open^(os.path.join^(folder, "06_LOCAL_USERS.csv"^), "w", newline="", encoding="utf-8-sig"^) as f:
echo         w = csv.writer^(f^)
echo         w.writerow^Context(["Audit_Reference_Timestamp", "Asset_Hostname", "Section_Title", "Username"]^)
echo         res = subprocess.run^Context(["net", "user"], capture_output=True, text=True^).stdout
echo         w.writerow^([ts, host, "USERS", res[:100].replace^("\n", " "^)^]^)
echo     print^(f"Full report generated at: {folder}"^)
echo if __name__ == "__main__": run_full_audit^(^)
) > %SCRIPT_NAME%

echo [STATUS] Running System Audit...
python %SCRIPT_NAME%
del %SCRIPT_NAME%

echo.
echo =====================================================
echo AUDIT COMPLETED. OPENING FOLDER...
echo =====================================================
explorer audit_output
pause
"""

st.download_button(
    label="Download Full Audit Collector (.cmd)",
    data=cmd_code,
    file_name="audit_collector.cmd",
    mime="application/octet-stream"
)

# -------------------------------------------------------
# STEP 2: UPLOAD & ANALYSIS (Processes Many Files)
# -------------------------------------------------------
st.header("📤 Step 2: Upload Generated CSV Files")

uploaded_files = st.file_uploader(
    "Upload ALL CSV files from your report folder", 
    type=["csv"], 
    accept_multiple_files=True
)

if uploaded_files:
    file_map = {file.name.upper(): pd.read_csv(file) for file in uploaded_files}
    
    # --- AI ANALYSIS ---
    all_numeric = pd.concat([df.select_dtypes(include=['number']) for df in file_map.values()], axis=1).fillna(0)
    risk_score = 0
    if not all_numeric.empty:
        model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
        preds = model.fit_predict(all_numeric)
        risk_score = round(((preds == -1).sum() / len(preds)) * 100, 2)
        st.metric("Total System Risk Score", f"{risk_score}%")

    # --- CATEGORIZED TABS ---
    tab1, tab2, tab3 = st.tabs(["🌐 Network", "⚙️ Processes", "🛡️ Users & Security"])

    def clean(df):
        return df.drop(columns=["Audit_Reference_Timestamp", "Asset_Hostname", "Section_Title"], errors='ignore')

    with tab1:
        for name, df in file_map.items():
            if "PORT" in name or "CONNECTION" in name:
                st.write(f"📂 {name}")
                st.dataframe(clean(df), use_container_width=True)

    with tab2:
        for name, df in file_map.items():
            if "PROCESS" in name or "PROGRAM" in name:
                st.write(f"📂 {name}")
                st.dataframe(clean(df), use_container_width=True)

    with tab3:
        for name, df in file_map.items():
            if "USER" in name or "ADMIN" in name or "POLICY" in name:
                st.write(f"📂 {name}")
                st.dataframe(clean(df), use_container_width=True)

    # -------------------------------------------------------
    # STEP 3: EMAIL PDF
    # -------------------------------------------------------
    st.divider()
    recipient_email = st.text_input("Enter Email Address")
    if st.button("Send Report"):
        if recipient_email:
            try:
                # Get hostname from first file
                device = list(file_map.values())[0]["Asset_Hostname"].iloc[0]
                pdf_path = f"Audit_{device}.pdf"
                canv = canvas.Canvas(pdf_path, pagesize=letter)
                canv.drawString(100, 750, f"AI Security Audit for {device}")
                canv.drawString(100, 730, f"Risk Score: {risk_score}%")
                canv.save()

                # Send using STARTTLS Port 587
                with smtplib.SMTP("smtp.gmail.com", 587) as server:
                    server.starttls()
                    server.login(st.secrets["SENDER_EMAIL"], st.secrets["SENDER_PASSWORD"])
                    
                    msg = MIMEMultipart()
                    msg['Subject'] = f"Security Report: {device}"
                    msg['To'] = recipient_email
                    with open(pdf_path, "rb") as f:
                        part = MIMEApplication(f.read(), Name=pdf_path)
                        part['Content-Disposition'] = f'attachment; filename="{pdf_path}"'
                        msg.attach(part)
                    server.send_message(msg)

                st.success(f"Sent to {recipient_email}!")
                os.remove(pdf_path)
            except Exception as e:
                st.error(f"Error: {e}")
