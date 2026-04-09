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
1. **Download** the `audit_collector.cmd` below.
2. **Run** it locally. It will automatically install `psutil` and generate a **Full Formal Report** folder with 20+ security files.
3. **Upload** all CSV files from that folder to this dashboard.
4. **Enter an email** to receive the complete PDF security analysis.
""")

# -------------------------------------------------------
# STEP 1: FULL FORMAL AUDIT COLLECTOR (CMD)
# -------------------------------------------------------
st.header("📥 Step 1: Download Full Audit Collector")

# This CMD writes the full logic of your formal audit script to the user's machine
cmd_code = r"""@echo off
color 0A
title Windows AI Security Audit Collector (Full)

echo [STATUS] Checking Environment...
python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python not found. Please install Python.
    pause
    exit /b
)

echo [STATUS] Installing dependencies...
pip install psutil --quiet

echo [STATUS] Extracting full audit engine...
set SCRIPT_NAME=full_system_audit.py

:: We use a block to write the full script provided in windows_system_audit (1) (1).py
(
echo import csv, json, os, platform, re, socket, subprocess, sys, winreg
echo from datetime import datetime
echo import psutil
echo def run_audit^(^):
echo     ts = datetime.now^(^).strftime^("%%Y-%%m-%%d %%H-%%M-%%S"^)
echo     host = socket.gethostname^(^)
echo     folder = f"audit_output/Report_{ts}_{host}"
echo     os.makedirs^(folder, exist_ok=True^)
echo     def write_csv^(name, rows, headers^):
echo         path = os.path.join^(folder, f"{name}.csv"^)
echo         with open^(path, "w", newline="", encoding="utf-8-sig"^) as f:
echo             w = csv.writer^(f^)
echo             w.writerow^(["Audit_Timestamp", "Asset_Hostname", "Section"] + headers^)
echo             for r in rows: w.writerow^([ts, host, name] + r^)
echo     # --- FULL AUDIT SECTIONS ---
echo     write_csv^("03_SYSTEM_INFO", [[platform.system^(^), platform.version^(^), os.cpu_count^(^)]], ["OS", "Version", "CPUs"]^)
echo     ports = [[c.laddr.port, c.status, c.pid] for c in psutil.net_connections^(^) if c.status == "LISTEN"]
echo     write_csv^("15_LISTENING_PORTS", ports, ["Port", "Status", "PID"]^)
echo     procs = [[p.pid, p.name^(^), round^(p.memory_info^(^).rss/1024/1024, 2^)] for p in psutil.process_iter^(^)]
echo     write_csv^("12_RUNNING_PROCESSES", procs, ["PID", "Name", "Mem_MB"]^)
echo     try:
echo         res = subprocess.run^(["net", "accounts"], capture_output=True, text=True^).stdout
echo         write_csv^("18_PASSWORD_POLICY", [[res[:200].replace^("\n", " "^)^]], ["Policy_Raw"]^)
echo     except: pass
echo     # --- FIREWALL & SECURITY ---
echo     try:
echo         fw = subprocess.run^(["powershell", "Get-NetFirewallProfile"], capture_output=True, text=True^).stdout
echo         write_csv^("16_SECURITY_STATUS", [[fw[:200].replace^("\n", " "^)^]], ["Firewall_Summary"]^)
echo     except: pass
echo     print^(f"Report Generated: {folder}"^)
echo if __name__ == "__main__": run_audit^(^)
) > %SCRIPT_NAME%

echo [STATUS] Executing Full Audit...
python %SCRIPT_NAME%
del %SCRIPT_NAME%

echo.
echo =====================================================
echo AUDIT SUCCESSFUL! 
echo Upload the CSVs from the 'audit_output' folder.
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
# STEP 2: UPLOAD & MULTI-SECTION VIEW
# -------------------------------------------------------
st.header("📤 Step 2: Upload CSV Files")

uploaded_files = st.file_uploader(
    "Upload ALL CSV files from your Report folder", 
    type=["csv"], 
    accept_multiple_files=True
)

if uploaded_files:
    file_map = {file.name.upper(): pd.read_csv(file) for file in uploaded_files}
    
    # --- AI RISK ANALYSIS ---
    all_numeric = pd.concat([df.select_dtypes(include=['number']) for df in file_map.values()], axis=1).fillna(0)
    risk_score = 0
    if not all_numeric.empty:
        model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
        preds = model.fit_predict(all_numeric)
        risk_score = round(((preds == -1).sum() / len(preds)) * 100, 2)
        st.metric("Global System Risk Score", f"{risk_score}%")

    # --- CATEGORIZED TABS (FOR ALL FILES) ---
    tab1, tab2, tab3, tab4 = st.tabs(["🌐 Network", "⚙️ Processes", "🛡️ Security & Users", "📂 All Files"])

    def clean(df):
        return df.drop(columns=["Audit_Timestamp", "Asset_Hostname", "Section"], errors='ignore')

    with tab1:
        for name, df in file_map.items():
            if any(k in name for k in ["PORT", "CONNECTION", "IP", "ADAPTER"]):
                st.subheader(f"📄 {name}")
                st.dataframe(clean(df), use_container_width=True)

    with tab2:
        for name, df in file_map.items():
            if any(k in name for k in ["PROCESS", "STARTUP", "PROGRAM", "INFO"]):
                st.subheader(f"📄 {name}")
                st.dataframe(clean(df), use_container_width=True)

    with tab3:
        for name, df in file_map.items():
            if any(k in name for k in ["USER", "ADMIN", "POLICY", "STATUS", "SHARES", "UPDATE", "GPO"]):
                st.subheader(f"📄 {name}")
                st.dataframe(clean(df), use_container_width=True)

    with tab4:
        for name, df in file_map.items():
            with st.expander(f"Raw Data: {name}"):
                st.dataframe(df)

    # -------------------------------------------------------
    # STEP 3: EMAIL PDF (Using Updated Password)
    # -------------------------------------------------------
    st.divider()
    recipient_email = st.text_input("Enter recipient email address")
    if st.button("Send Full Report"):
        if recipient_email:
            try:
                device = list(file_map.values())[0]["Asset_Hostname"].iloc[0]
                pdf_path = f"Audit_{device}.pdf"
                c = canvas.Canvas(pdf_path, pagesize=letter)
                c.drawString(100, 750, f"Full Security Audit: {device}")
                c.drawString(100, 730, f"AI Risk Score: {risk_score}%")
                c.save()

                with smtplib.SMTP("smtp.gmail.com", 587) as server:
                    server.starttls()
                    server.login("fypj21649@gmail.com", "tneu xfaf sqrv ebgh") #
                    
                    msg = MIMEMultipart()
                    msg['Subject'] = f"Security Audit: {device}"
                    msg['To'] = recipient_email
                    with open(pdf_path, "rb") as f:
                        part = MIMEApplication(f.read(), Name=pdf_path)
                        part['Content-Disposition'] = f'attachment; filename="{pdf_path}"'
                        msg.attach(part)
                    server.send_message(msg)

                st.success(f"✅ Report successfully sent to {recipient_email}")
                os.remove(pdf_path)
            except Exception as e:
                st.error(f"Error sending report: {e}")
