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
1. **Download** the `windows_system_audit.py` script below.
2. **Run** it locally on Windows to generate your report folder.
3. **Upload** all CSV files from that folder here.
4. **Enter an email** below to receive the PDF report.
""")

# -------------------------------------------------------
# STEP 1: DOWNLOAD SECTION
# -------------------------------------------------------
st.header("📥 Step 1: Download Audit Script")

try:
    with open("windows_system_audit.py", "rb") as file:
        st.download_button(
            label="Download Formal Audit Script (.py)",
            data=file,
            file_name="windows_system_audit.py",
            mime="text/x-python"
        )
except FileNotFoundError:
    st.error("Error: Please ensure 'windows_system_audit.py' is in your GitHub root folder.")

# -------------------------------------------------------
# STEP 2: UPLOAD & ANALYSIS SECTION
# -------------------------------------------------------
st.header("📤 Step 2: Upload Generated CSV Files")

uploaded_files = st.file_uploader(
    "Select all CSV files from your audit report folder", 
    type=["csv"], 
    accept_multiple_files=True
)

if uploaded_files:
    file_map = {file.name.upper(): pd.read_csv(file) for file in uploaded_files}
    
    # --- AI RISK ANALYSIS ---
    all_numeric = pd.concat([df.select_dtypes(include=['number']) for df in file_map.values()], axis=1).fillna(0)

    risk_score = 0
    if not all_numeric.empty:
        model = IsolationForest(n_estimators=150, contamination=0.05, random_state=42)
        preds = model.fit_predict(all_numeric) 
        
        total_points = len(preds)
        anomalies = (preds == -1).sum()
        risk_score = round((anomalies / total_points) * 100, 2)

        col1, col2, col3 = st.columns(3)
        col1.metric("Telemetry Records", total_points)
        col2.metric("Anomalies Detected", anomalies)
        col3.metric("Risk Score", f"{risk_score}%")

    # --- CATEGORIZED TABS ---
    tab1, tab2, tab3, tab4 = st.tabs(["🌐 Network", "⚙️ Processes", "🛡️ Security & Users", "📂 Raw Index"])

    def clean_df(df):
        return df.drop(columns=["Audit_Reference_Timestamp", "Asset_Hostname", "Section_Title"], errors='ignore')

    with tab1:
        for name, df in file_map.items():
            if any(k in name for k in ["PORT", "CONNECTION", "IP"]):
                st.write(f"**Source:** {name}")
                st.dataframe(clean_df(df), use_container_width=True)

    with tab2:
        for name, df in file_map.items():
            if any(k in name for k in ["PROCESS", "STARTUP", "PROGRAM"]):
                st.write(f"**Source:** {name}")
                st.dataframe(clean_df(df), use_container_width=True)

    with tab3:
        for name, df in file_map.items():
            if any(k in name for k in ["USER", "ADMIN", "POLICY", "STATUS", "FIREWALL", "SECURITY", "AUTOPLAY"]):
                st.write(f"**Source:** {name}")
                st.dataframe(clean_df(df), use_container_width=True)

    with tab4:
        for name, df in file_map.items():
            with st.expander(f"View {name}"):
                st.dataframe(df)

    # -------------------------------------------------------
    # STEP 3: EMAIL PDF REPORT (WITH SMART DATA EXTRACTION)
    # -------------------------------------------------------
    st.divider()
    st.header("📧 Step 3: Send PDF Report")
    
    # --- DATA EXTRACTION FOR PDF ---
    # 1. Device Name Extraction
    device_name = "Unknown_Device"
    for df in file_map.values():
        if "Asset_Hostname" in df.columns:
            device_name = str(df["Asset_Hostname"].iloc[0])
            break

    # 2. USB and RDP Status Extraction
    usb_status = "Not Found (Run Full Audit)"
    rdp_status = "Not Found (Run Full Audit)"
    
    for name, df in file_map.items():
        if "SECURITY_STATUS" in name or "REMOTE_PROTOCOLS" in name:
            # Check for USB Registry flags
            if "USBSTOR_START_REGISTRY" in df.columns:
                usb_val = str(df["USBSTOR_START_REGISTRY"].iloc[0])
                usb_status = "Disabled (Secure)" if usb_val == "4" else "Enabled (Check Security)"
            
            # Check for RDP Registry flags
            if "RDP_REGISTRY_ALLOWS_CONNECTIONS" in df.columns:
                rdp_status = "Enabled" if str(df["RDP_REGISTRY_ALLOWS_CONNECTIONS"].iloc[0]).lower() == "yes" else "Disabled"

    recipient_email = st.text_input("Enter the recipient's email address")
    
    if st.button("Send Report to Entered Email"):
        if recipient_email:
            try:
                # 1. Generate PDF
                pdf_path = f"Security_Report_{device_name}.pdf"
                c = canvas.Canvas(pdf_path, pagesize=letter)
                
                # Header
                c.setFont("Helvetica-Bold", 18)
                c.drawString(50, 750, f"AI Security Audit: {device_name}")
                
                # System Info Section
                c.setFont("Helvetica", 12)
                c.drawString(50, 725, f"Risk Score: {risk_score}%")
                c.drawString(50, 705, f"USB Storage Status: {usb_status}")
                c.drawString(50, 685, f"Remote Desktop (RDP): {rdp_status}")
                
                # Recommendations
                c.setFont("Helvetica-Bold", 14)
                c.drawString(50, 640, "🛡️ Security Recommendations:")
                c.setFont("Helvetica", 11)
                recs = [
                    f"• Device '{device_name}' shows a risk level of {risk_score}%.",
                    "• Investigate anomalous processes for unauthorized activity.",
                    "• If RDP is 'Enabled' but not required, disable it via Registry/Settings.",
                    "• Ensure all Windows Firewall profiles are enabled.",
                    "• Audit Local Administrator accounts for unknown users."
                ]
                y = 620
                for r in recs:
                    c.drawString(60, y, r); y -= 20
                c.save()

                # 2. Setup Email Credentials
                SENDER_EMAIL = "fypj21649@gmail.com" 
                SENDER_PASSWORD = "tneu xfaf sqrv ebgh" 

                msg = MIMEMultipart()
                msg['From'] = SENDER_EMAIL
                msg['To'] = recipient_email 
                msg['Subject'] = f"🛡️ Windows Security Report - {device_name}"
                
                body = f"Hello,\n\nAttached is the security report for {device_name}.\nRisk Score: {risk_score}%\nUSB Status: {usb_status}\nRDP Status: {rdp_status}"
                msg.attach(MIMEText(body, 'plain'))

                with open(pdf_path, "rb") as f:
                    part = MIMEApplication(f.read(), Name=pdf_path)
                    part['Content-Disposition'] = f'attachment; filename="{pdf_path}"'
                    msg.attach(part)

                # 3. Connection Logic
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
    st.info("Upload CSV files from your report folder to begin.")
