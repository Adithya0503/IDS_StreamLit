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
1. **Download** the formal Audit Script (`windows_system_audit.py`).
2. **Run** it on your Windows machine to generate a report folder.
3. **Upload** all CSV files from that folder to this dashboard.
4. **Analyze** results and **Email** a PDF report to yourself.
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
    # Map filenames to DataFrames
    file_map = {file.name.upper(): pd.read_csv(file) for file in uploaded_files}
    
    # --- AI RISK ANALYSIS ---
    st.header("📊 AI Risk Analysis")
    
    # Isolation Forest looks for statistical outliers in numeric telemetry
    all_numeric = pd.concat([df.select_dtypes(include=['number']) for df in file_map.values()], axis=1).fillna(0)

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

        if risk_score > 20:
            st.error("🚨 HIGH RISK: Significant anomalies detected. Review the Network and Process tabs.")
        else:
            st.success("✅ LOW RISK: System behavior appears stable.")

    # --- CATEGORIZED TABLES ---
    st.header("🔍 Detailed Security Audit")
    tab1, tab2, tab3, tab4 = st.tabs(["🌐 Network", "⚙️ Processes", "🛡️ Security & Users", "📂 Raw Index"])

    def clean_df(df):
        # Remove formal report metadata for cleaner UI display
        return df.drop(columns=["Audit_Reference_Timestamp", "Asset_Hostname", "Section_Title"], errors='ignore')

    with tab1:
        st.subheader("Listening Ports & Connections")
        for name, df in file_map.items():
            if any(k in name for k in ["PORT", "CONNECTION", "IP"]):
                st.write(f"**Source:** {name}")
                st.dataframe(clean_df(df), use_container_width=True)

    with tab2:
        st.subheader("Running Processes & Startups")
        for name, df in file_map.items():
            if any(k in name for k in ["PROCESS", "STARTUP", "PROGRAM"]):
                st.write(f"**Source:** {name}")
                st.dataframe(clean_df(df), use_container_width=True)

    with tab3:
        st.subheader("System Security & User Accounts")
        for name, df in file_map.items():
            if any(k in name for k in ["USER", "ADMIN", "POLICY", "STATUS", "FIREWALL"]):
                st.write(f"**Source:** {name}")
                st.dataframe(clean_df(df), use_container_width=True)

    with tab4:
        st.subheader("Full Report File Access")
        for name, df in file_map.items():
            with st.expander(f"View {name}"):
                st.dataframe(df)

    # -------------------------------------------------------
    # STEP 3: EMAIL & PDF REPORTING
    # -------------------------------------------------------
    st.divider()
    st.header("📧 Step 3: Receive PDF Report via Email")
    
    # Extract Device Name for the report header
    first_df = list(file_map.values())[0]
    device_name = first_df["Asset_Hostname"].iloc[0] if "Asset_Hostname" in first_df.columns else "Unknown_Device"

    user_email = st.text_input("Enter Email Address")
    
    if st.button("Generate & Send PDF"):
        if user_email:
            try:
                # 1. Generate PDF
                pdf_path = f"Security_Report_{device_name}.pdf"
                c = canvas.Canvas(pdf_path, pagesize=letter)
                c.setTitle(f"Audit Report - {device_name}")
                
                c.setFont("Helvetica-Bold", 18)
                c.drawString(50, 750, "🛡️ Windows AI Security Audit Report")
                
                c.setFont("Helvetica", 12)
                c.drawString(50, 730, f"Target Device: {device_name}")
                c.drawString(50, 715, f"AI Risk Score: {risk_score}%")
                c.drawString(50, 700, f"Analysis Timestamp: {pd.Timestamp.now()}")

                c.setFont("Helvetica-Bold", 14)
                c.drawString(50, 660, "💡 Security Recommendations:")
                c.setFont("Helvetica", 11)
                recs = [
                    "• Investigate high-memory or unknown processes marked as anomalies.",
                    "• Review 'OpenPort' list; close ports like 3389 (RDP) if not required.",
                    "• Verify 'Firewall_Public' status is 'ON' for all network interfaces.",
                    "• Ensure 'Local Administrators' list only contains authorized users."
                ]
                y = 640
                for r in recs:
                    c.drawString(60, y, r)
                    y -= 20
                
                c.save()

                # 2. Setup Email (Replace credentials with Environment Variables in production)
                # You must use a Gmail 'App Password' for this to work.
                SENDER = "your-email@gmail.com" 
                PASSWORD = "your-app-password" 

                msg = MIMEMultipart()
                msg['From'] = SENDER
                msg['To'] = user_email
                msg['Subject'] = f"Security Audit: {device_name} ({risk_score}% Risk)"
                
                body = f"Hello,\n\nPlease find the attached AI Security Report for the device: {device_name}."
                msg.attach(MIMEText(body, 'plain'))

                with open(pdf_path, "rb") as f:
                    part = MIMEApplication(f.read(), Name=pdf_path)
                    part['Content-Disposition'] = f'attachment; filename="{pdf_path}"'
                    msg.attach(part)

                # 3. Send
                with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                    server.login(SENDER, PASSWORD)
                    server.send_message(msg)

                st.success(f"✅ PDF Report sent to {user_email}!")
                os.remove(pdf_path) # Security: remove file after sending

            except Exception as e:
                st.error(f"Error sending email: {e}")
        else:
            st.warning("Please enter a valid email address.")

else:
    st.info("Please upload the CSV files from your report folder to begin analysis.")
