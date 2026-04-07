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
2. **Run** it on your Windows machine to generate a report folder.
3. **Upload** all CSV files from that folder to this dashboard.
4. **Enter an email** to receive a summarized PDF security report.
""")

# -------------------------------------------------------
# STEP 1: DOWNLOAD SECTION
# -------------------------------------------------------
st.header("📥 Step 1: Download Audit Script")

try:
    # Ensure windows_system_audit.py is in your GitHub root directory
    with open("windows_system_audit.py", "rb") as file:
        st.download_button(
            label="Download Formal Audit Script (.py)",
            data=file,
            file_name="windows_system_audit.py",
            mime="text/x-python"
        )
    st.info("💡 Run locally using: `python windows_system_audit.py`")
except FileNotFoundError:
    st.error("Error: 'windows_system_audit.py' not found in your GitHub repository.")

# -------------------------------------------------------
# STEP 2: UPLOAD & ANALYSIS SECTION
# -------------------------------------------------------
st.header("📤 Step 2: Upload Generated CSV Files")

uploaded_files = st.file_uploader(
    "Select all CSV files from your audit_output/Report_... folder", 
    type=["csv"], 
    accept_multiple_files=True
)

if uploaded_files:
    # Create a mapping of filename to DataFrame
    file_map = {file.name.upper(): pd.read_csv(file) for file in uploaded_files}
    
    # --- AI RISK ANALYSIS ---
    st.header("📊 AI Risk Analysis")
    
    # Extract numeric data for Isolation Forest
    all_numeric = pd.concat([df.select_dtypes(include=['number']) for df in file_map.values()], axis=1).fillna(0)

    risk_score = 0
    if not all_numeric.empty:
        model = IsolationForest(n_estimators=150, contamination=0.05, random_state=42)
        preds = model.fit_predict(all_numeric) # Anomaly prediction: 1=Normal, -1=Anomaly
        
        total_points = len(preds)
        anomalies = (preds == -1).sum()
        risk_score = round((anomalies / total_points) * 100, 2)

        col1, col2, col3 = st.columns(3)
        col1.metric("Telemetry Records", total_points)
        col2.metric("Anomalies Detected", anomalies)
        col3.metric("Risk Score", f"{risk_score}%")

        if risk_score > 20:
            st.error("🚨 HIGH RISK: Significant anomalies detected. Review the tabs below.")
        else:
            st.success("✅ LOW RISK: System telemetry is within normal parameters.")

    # --- CATEGORIZED TABS ---
    tab1, tab2, tab3, tab4 = st.tabs(["🌐 Network", "⚙️ Processes", "🛡️ Security & Users", "📂 Raw Index"])

    def clean_df(df):
        # Remove metadata columns for cleaner display
        return df.drop(columns=["Audit_Reference_Timestamp", "Asset_Hostname", "Section_Title"], errors='ignore')

    with tab1:
        for name, df in file_map.items():
            if any(k in name for k in ["PORT", "CONNECTION", "IP"]):
                st.write(f"**Source:** {name}")
                st.dataframe(clean_display(df) if 'clean_display' in locals() else clean_df(df), use_container_width=True)

    with tab2:
        for name, df in file_map.items():
            if any(k in name for k in ["PROCESS", "STARTUP", "PROGRAM"]):
                st.write(f"**Source:** {name}")
                st.dataframe(clean_df(df), use_container_width=True)

    with tab3:
        for name, df in file_map.items():
            if any(k in name for k in ["USER", "ADMIN", "POLICY", "STATUS", "FIREWALL"]):
                st.write(f"**Source:** {name}")
                st.dataframe(clean_df(df), use_container_width=True)

    with tab4:
        for name, df in file_map.items():
            with st.expander(f"View {name}"):
                st.dataframe(df)

    # -------------------------------------------------------
    # STEP 3: EMAIL PDF REPORT (FIXED CONNECTIVITY)
    # -------------------------------------------------------
    st.divider()
    st.header("📧 Step 3: Send PDF Report")
    
    # Identify device name from metadata
    first_df = list(file_map.values())[0]
    device_name = first_df["Asset_Hostname"].iloc[0] if "Asset_Hostname" in first_df.columns else "Unknown_Device"

    recipient_email = st.text_input("Enter the recipient's email address")
    
    if st.button("Send Report to Entered Email"):
        if recipient_email:
            try:
                # 1. Generate PDF Report
                pdf_path = f"Security_Report_{device_name}.pdf"
                c = canvas.Canvas(pdf_path, pagesize=letter)
                c.setFont("Helvetica-Bold", 16)
                c.drawString(50, 750, f"AI Security Audit: {device_name}")
                c.setFont("Helvetica", 12)
                c.drawString(50, 730, f"Risk Score: {risk_score}%")
                c.drawString(50, 715, f"Date: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M')}")

                c.setFont("Helvetica-Bold", 14)
                c.drawString(50, 680, "🛡️ Security Recommendations:")
                c.setFont("Helvetica", 11)
                recs = [
                    "• Investigate anomalous processes for unauthorized activity.",
                    "• Review 'OpenPort' list; close ports like 3389 (RDP) if not required.",
                    "• Verify 'Firewall' profiles are 'ON' for all network interfaces.",
                    "• Audit Local Administrator accounts for unauthorized users."
                ]
                y_pos = 660
                for line in recs:
                    c.drawString(60, y_pos, line); y_pos -= 20
                c.save()

                # 2. Setup Credentials from Secrets
                SENDER_EMAIL = st.secrets["SENDER_EMAIL"]
                SENDER_PASSWORD = st.secrets["SENDER_PASSWORD"]

                msg = MIMEMultipart()
                msg['From'] = SENDER_EMAIL
                msg['To'] = recipient_email 
                msg['Subject'] = f"🛡️ Windows Security Report - {device_name}"
                msg.attach(MIMEText(f"Attached is the security report for {device_name}.\nRisk Score: {risk_score}%", 'plain'))

                with open(pdf_path, "rb") as attachment:
                    part = MIMEApplication(attachment.read(), Name=pdf_path)
                    part['Content-Disposition'] = f'attachment; filename="{pdf_path}"'
                    msg.attach(part)

                # 3. Secure Connection using STARTTLS (Port 587)
                # Most robust method for cloud-to-gmail connections
                server = smtplib.SMTP("smtp.gmail.com", 587)
                server.starttls() 
                server.login(SENDER_EMAIL, SENDER_PASSWORD)
                server.send_message(msg)
                server.quit()

                st.success(f"✅ Security report has been sent to {recipient_email}")
                os.remove(pdf_path) 

            except Exception as e:
                st.error(f"Error sending email: {e}")
        else:
            st.warning("Please enter a valid email address.")
else:
    st.info("Upload your audit CSV files to begin.")
