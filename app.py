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
2. **Run** it locally. It generates a full security report folder.
3. **Upload** all CSV files from that folder to this dashboard.
4. **Enter an email** to receive the complete PDF security analysis.
""")

# -------------------------------------------------------
# STEP 1: COMPREHENSIVE AUDIT COLLECTOR (CMD)
# -------------------------------------------------------
st.header("📥 Step 1: Download Full Audit Collector")

# This CMD writes a script that captures Hostname, USB status, and RDP status
cmd_code = r"""@echo off
color 0A
title Windows AI Security Audit Collector (Full)

echo [STATUS] Verifying Environment...
python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python not found.
    pause
    exit /b
)

pip install psutil --quiet

set SCRIPT_NAME=full_system_audit.py

(
echo import csv, os, socket, subprocess, sys, winreg, psutil
echo from datetime import datetime
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
echo     # --- 1. System Info ---
echo     write_csv^("03_SYSTEM_INFO", [[platform.system^(^) if 'platform' in dir^(^) else "Windows", socket.gethostname^(^)]], ["OS", "Hostname"]^)
echo     # --- 2. Security Status (USB & RDP) ---
echo     usb_status = "Unknown"
echo     try:
echo         with winreg.OpenKey^(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\USBStor"^) as k:
echo             val, _ = winreg.QueryValueEx^(k, "Start"^)
echo             usb_status = "Disabled" if val == 4 else "Enabled"
echo     except: pass
echo     rdp_status = "Disabled"
echo     try:
echo         with winreg.OpenKey^(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Terminal Server"^) as k:
echo             val, _ = winreg.QueryValueEx^(k, "fDenyTSConnections"^)
echo             rdp_status = "Disabled" if val == 1 else "Enabled"
echo     except: pass
echo     write_csv^("16_SECURITY_STATUS", [[usb_status, rdp_status]], ["USB_Status", "RDP_Status"]^)
echo     # --- 3. Ports & Processes ---
echo     ports = [[c.laddr.port, c.status, c.pid] for c in psutil.net_connections^(^) if c.status == "LISTEN"]
echo     write_csv^("15_LISTENING_PORTS", ports, ["Port", "Status", "PID"]^)
echo     procs = [[p.pid, p.name^(^)] for p in psutil.process_iter^(^)]
echo     write_csv^("12_RUNNING_PROCESSES", procs, ["PID", "Name"]^)
echo     print^(f"Report Generated: {folder}"^)
echo if __name__ == "__main__": run_audit^(^)
) > %SCRIPT_NAME%

python %SCRIPT_NAME%
del %SCRIPT_NAME%
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
    
    # AI Risk Score logic
    all_numeric = pd.concat([df.select_dtypes(include=['number']) for df in file_map.values()], axis=1).fillna(0)
    risk_score = 0
    if not all_numeric.empty:
        model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
        preds = model.fit_predict(all_numeric)
        risk_score = round(((preds == -1).sum() / len(preds)) * 100, 2)
        st.metric("Global System Risk Score", f"{risk_score}%")

    tab1, tab2, tab3 = st.tabs(["🌐 Network", "⚙️ Processes", "🛡️ Security & Users"])
    def clean(df): return df.drop(columns=["Audit_Timestamp", "Asset_Hostname", "Section"], errors='ignore')

    with tab1:
        for name, df in file_map.items():
            if "PORT" in name: st.dataframe(clean(df), use_container_width=True)
    with tab2:
        for name, df in file_map.items():
            if "PROCESS" in name: st.dataframe(clean(df), use_container_width=True)
    with tab3:
        for name, df in file_map.items():
            if any(k in name for k in ["USER", "POLICY", "STATUS", "SECURITY"]): st.dataframe(clean(df), use_container_width=True)

    # -------------------------------------------------------
    # STEP 3: EMAIL PDF (WITH DEVICE, USB, & RDP INFO)
    # -------------------------------------------------------
    st.divider()
    recipient_email = st.text_input("Enter recipient email address")
    if st.button("Send Full Report"):
        if recipient_email:
            try:
                # --- DATA EXTRACTION ---
                # 1. Get Hostname
                device_name = "Unknown_Device"
                for df in file_map.values():
                    if "Asset_Hostname" in df.columns:
                        device_name = str(df["Asset_Hostname"].iloc[0])
                        break
                
                # 2. Get USB & RDP Status from 16_SECURITY_STATUS.CSV
                usb_info = "Data Not Found"
                rdp_info = "Data Not Found"
                for name, df in file_map.items():
                    if "SECURITY_STATUS" in name:
                        if "USB_Status" in df.columns: usb_info = str(df["USB_Status"].iloc[0])
                        if "RDP_Status" in df.columns: rdp_info = str(df["RDP_Status"].iloc[0])
                
                # --- PDF GENERATION ---
                pdf_path = f"Audit_{device_name}.pdf"
                c = canvas.Canvas(pdf_path, pagesize=letter)
                c.setFont("Helvetica-Bold", 18)
                c.drawString(100, 750, f"AI Security Audit: {device_name}")
                
                c.setFont("Helvetica", 12)
                c.drawString(100, 720, f"System Risk Score: {risk_score}%")
                c.drawString(100, 700, f"USB Storage Status: {usb_info}")
                c.drawString(100, 680, f"Remote Desktop (RDP) Status: {rdp_info}")
                
                c.setFont("Helvetica-Bold", 14)
                c.drawString(100, 640, "Security Recommendations:")
                c.setFont("Helvetica", 11)
                recs = [
                    "• Investigate all processes flagged as anomalies.",
                    "• If RDP is 'Enabled' but not required, disable it in Settings.",
                    "• If USB is 'Enabled', ensure unauthorized drives are restricted.",
                    "• Verify Windows Firewall profiles are active."
                ]
                y = 620
                for r in recs:
                    c.drawString(100, y, r); y -= 20
                c.save()

                # --- EMAIL SENDING ---
                with smtplib.SMTP("smtp.gmail.com", 587) as server:
                    server.starttls()
                    server.login("fypj21649@gmail.com", "tneu xfaf sqrv ebgh") #
                    msg = MIMEMultipart()
                    msg['Subject'] = f"🛡️ Security Report - {device_name}"
                    msg['To'] = recipient_email
                    with open(pdf_path, "rb") as f:
                        part = MIMEApplication(f.read(), Name=pdf_path)
                        part['Content-Disposition'] = f'attachment; filename="{pdf_path}"'
                        msg.attach(part)
                    server.send_message(msg)

                st.success(f"✅ Full report sent to {recipient_email}")
                os.remove(pdf_path)
            except Exception as e:
                st.error(f"Error: {e}")
