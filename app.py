import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
import os

# --- PAGE CONFIG ---
st.set_page_config(page_title="Windows AI Security Analyzer Pro", layout="wide")

st.title("🛡️ Windows AI Security Anomaly Detection System")

st.markdown("""
### 📋 Instructions
1. **Download** the new Audit Script below.
2. **Run** it on a Windows machine (requires Python).
3. **Upload** all generated CSV files from the `audit_output/Report_...` folder.
""")

# -------------------------------------------------------
# DOWNLOAD SECTION
# -------------------------------------------------------
st.header("📥 Step 1: Download Audit Script")

# We read the local windows_system_audit.py to offer it for download
try:
    with open("windows_system_audit.py", "rb") as file:
        st.download_button(
            label="Download Formal Audit Script (.py)",
            data=file,
            file_name="windows_system_audit.py",
            mime="text/x-python"
        )
    st.info("💡 Run this script locally using: `python windows_system_audit.py`")
except FileNotFoundError:
    st.error("Error: 'windows_system_audit.py' not found in the repository. Please ensure the file is uploaded to GitHub.")

# -------------------------------------------------------
# UPLOAD SECTION
# -------------------------------------------------------
st.header("📤 Step 2: Upload Generated CSV Files")

# Allow multiple files to handle the new folder-based report format
uploaded_files = st.file_uploader(
    "Select all CSV files from your report folder", 
    type=["csv"], 
    accept_multiple_files=True
)

if uploaded_files:
    # Map filenames to DataFrames for easy access
    file_map = {file.name.upper(): pd.read_csv(file) for file in uploaded_files}
    
    # --- AI ANOMALY DETECTION ---
    st.header("📊 AI Risk Analysis")
    
    # Combine numeric data from all uploaded files for the AI model
    all_numeric = pd.concat([df.select_dtypes(include=['number']) for df in file_map.values()], axis=1).fillna(0)

    if not all_numeric.empty:
        model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
        preds = model.fit_predict(all_numeric)
        
        total_points = len(preds)
        anomalies = (preds == -1).sum()
        risk_score = round((anomalies / total_points) * 100, 2)

        col1, col2, col3 = st.columns(3)
        col1.metric("Telemetry Points", total_points)
        col2.metric("Anomalies Detected", anomalies)
        col3.metric("System Risk Score", f"{risk_score}%")

        if risk_score > 15:
            st.error("🚨 HIGH RISK: Significant statistical anomalies detected.")
        else:
            st.success("✅ LOW RISK: System telemetry appears normal.")

    # --- CATEGORIZED TABLES ---
    st.header("🔍 Detailed Security Audit")
    tab1, tab2, tab3, tab4 = st.tabs(["🌐 Network", "⚙️ Processes", "🛡️ Security & Users", "📂 Raw Data Index"])

    # Utility function to remove metadata columns from display
    def clean_display(df):
        return df.drop(columns=["Audit_Reference_Timestamp", "Asset_Hostname", "Section_Title"], errors='ignore')

    with tab1:
        st.subheader("Listening Ports & Active Connections")
        for name, df in file_map.items():
            if any(k in name for k in ["PORT", "CONNECTION", "IP"]):
                st.write(f"**Section:** {name}")
                st.dataframe(clean_display(df), use_container_width=True)

    with tab2:
        st.subheader("Running Processes & Startup Programs")
        for name, df in file_map.items():
            if any(k in name for k in ["PROCESS", "STARTUP", "PROGRAM"]):
                st.write(f"**Section:** {name}")
                st.dataframe(clean_display(df), use_container_width=True)

    with tab3:
        st.subheader("Local Users, Admins & Security Policies")
        for name, df in file_map.items():
            if any(k in name for k in ["USER", "ADMIN", "POLICY", "STATUS", "FIREWALL"]):
                st.write(f"**Section:** {name}")
                st.dataframe(clean_display(df), use_container_width=True)

    with tab4:
        st.subheader("Full Report File Index")
        for name, df in file_map.items():
            with st.expander(f"📄 View Raw File: {name}"):
                st.dataframe(df)

else:
    st.info("Waiting for report files... Run the script locally and upload the resulting CSVs.")
