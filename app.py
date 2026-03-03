import streamlit as st
import pandas as pd
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt

st.set_page_config(page_title="Windows AI Security Analyzer", layout="wide")

st.title("🛡 Windows AI Security Anomaly Detection System")

st.markdown("""
This tool allows users to:

1. Download the Windows Audit Collector
2. Run it locally to generate system telemetry
3. Upload the generated CSV file
4. Detect anomalies using AI
""")

# -------------------------------------------------------
# EMBEDDED CMD SCRIPT (WITH INSTALLED APPS)
# -------------------------------------------------------

cmd_script = r"""@echo off
color 0A
title Windows Security Audit Collector

echo =====================================================
echo        WINDOWS SECURITY AUDIT DATA COLLECTOR
echo =====================================================
echo.

python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo Python is NOT installed on this system.
    echo Please install Python from:
    echo https://www.python.org/downloads/
    pause
    exit /b
)

echo Python detected successfully.
echo.

pip show psutil >nul 2>&1 || (
    echo Installing required package: psutil
    pip install psutil
)

echo Running system audit...
echo.

set SCRIPT_NAME=temp_audit_script.py

echo import os> %SCRIPT_NAME%
echo import csv>> %SCRIPT_NAME%
echo import socket>> %SCRIPT_NAME%
echo import psutil>> %SCRIPT_NAME%
echo import winreg>> %SCRIPT_NAME%
echo from datetime import datetime>> %SCRIPT_NAME%
echo.>> %SCRIPT_NAME%
echo hostname = socket.gethostname()>> %SCRIPT_NAME%
echo timestamp = datetime.now().strftime("%%Y%%m%%d_%%H%%M%%S")>> %SCRIPT_NAME%
echo filename = hostname + "_audit_" + timestamp + ".csv">> %SCRIPT_NAME%
echo.>> %SCRIPT_NAME%
echo def get_installed_apps():>> %SCRIPT_NAME%
echo     apps = []>> %SCRIPT_NAME%
echo     registry_paths = [>> %SCRIPT_NAME%
echo         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",>> %SCRIPT_NAME%
echo         r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall">> %SCRIPT_NAME%
echo     ]>> %SCRIPT_NAME%
echo     for path in registry_paths:>> %SCRIPT_NAME%
echo         try:>> %SCRIPT_NAME%
echo             reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)>> %SCRIPT_NAME%
echo             for i in range(winreg.QueryInfoKey(reg_key)[0]):>> %SCRIPT_NAME%
echo                 subkey_name = winreg.EnumKey(reg_key, i)>> %SCRIPT_NAME%
echo                 subkey = winreg.OpenKey(reg_key, subkey_name)>> %SCRIPT_NAME%
echo                 try:>> %SCRIPT_NAME%
echo                     name = winreg.QueryValueEx(subkey, "DisplayName")[0]>> %SCRIPT_NAME%
echo                     apps.append(name)>> %SCRIPT_NAME%
echo                 except:>> %SCRIPT_NAME%
echo                     pass>> %SCRIPT_NAME%
echo         except:>> %SCRIPT_NAME%
echo             pass>> %SCRIPT_NAME%
echo     return apps>> %SCRIPT_NAME%
echo.>> %SCRIPT_NAME%
echo with open(filename, "w", newline="", encoding="utf-8") as file:>> %SCRIPT_NAME%
echo     writer = csv.writer(file)>> %SCRIPT_NAME%
echo     writer.writerow(["Type","Value1","Value2","Value3"])>> %SCRIPT_NAME%
echo.>> %SCRIPT_NAME%
echo     writer.writerow(["CPU_Percent", psutil.cpu_percent(), "", ""])>> %SCRIPT_NAME%
echo     writer.writerow(["Memory_Percent", psutil.virtual_memory().percent, "", ""])>> %SCRIPT_NAME%
echo.>> %SCRIPT_NAME%
echo     for proc in psutil.process_iter(['pid','cpu_percent','memory_percent']):>> %SCRIPT_NAME%
echo         try:>> %SCRIPT_NAME%
echo             writer.writerow(["Process", proc.info['pid'], proc.info['cpu_percent'], round(proc.info['memory_percent'],2)])>> %SCRIPT_NAME%
echo         except:>> %SCRIPT_NAME%
echo             pass>> %SCRIPT_NAME%
echo.>> %SCRIPT_NAME%
echo     for conn in psutil.net_connections(kind='inet'):>> %SCRIPT_NAME%
echo         if conn.status == psutil.CONN_LISTEN:>> %SCRIPT_NAME%
echo             writer.writerow(["OpenPort", conn.laddr.port, conn.pid, ""])>> %SCRIPT_NAME%
echo.>> %SCRIPT_NAME%
echo     installed_apps = get_installed_apps()>> %SCRIPT_NAME%
echo     for app in installed_apps:>> %SCRIPT_NAME%
echo         writer.writerow(["InstalledApp", app, "", ""])>> %SCRIPT_NAME%
echo.>> %SCRIPT_NAME%
echo print("Audit file created:", filename)>> %SCRIPT_NAME%

python %SCRIPT_NAME%
del %SCRIPT_NAME%

echo.
echo AUDIT COMPLETED SUCCESSFULLY
explorer .
pause
"""

# -------------------------------------------------------
# DOWNLOAD SECTION
# -------------------------------------------------------

st.header("📥 Step 1: Download Audit Script")

st.download_button(
    label="Download Audit Script (.cmd)",
    data=cmd_script,
    file_name="audit_script.cmd",
    mime="application/octet-stream"
)

st.info("Run the downloaded CMD file to generate the audit CSV file.")

# -------------------------------------------------------
# UPLOAD SECTION
# -------------------------------------------------------

st.header("📤 Step 2: Upload Generated CSV File")

uploaded_file = st.file_uploader("Upload audit CSV file", type=["csv"])

if uploaded_file:

    try:
        df = pd.read_csv(uploaded_file)
        st.success("CSV File Loaded Successfully")

        if "Value1" not in df.columns:
            st.error("Invalid CSV structure.")
            st.stop()

        numeric_df = df.select_dtypes(include=['number'])

        if numeric_df.empty:
            st.error("No numeric data available for analysis.")
            st.stop()

        # ---------------- AI MODEL ----------------
        model = IsolationForest(
            n_estimators=150,
            contamination=0.05,
            random_state=42
        )

        model.fit(numeric_df)
        predictions = model.predict(numeric_df)

        df["Anomaly"] = predictions
        df["Anomaly"] = df["Anomaly"].map({1: "Normal", -1: "Anomaly"})

        anomaly_df = df[df["Anomaly"] == "Anomaly"]

        total_records = len(df)
        total_anomalies = len(anomaly_df)

        # ---------------- RISK SCORE ----------------
        risk_score = round((total_anomalies / total_records) * 100, 2)

        if risk_score < 10:
            severity = "Low"
            color = "green"
        elif risk_score < 30:
            severity = "Medium"
            color = "orange"
        else:
            severity = "High"
            color = "red"

        # ---------------- RESULTS ----------------
        st.header("📊 AI Analysis Results")

        col1, col2, col3 = st.columns(3)
        col1.metric("Total Records", total_records)
        col2.metric("Total Anomalies", total_anomalies)
        col3.metric("Risk Score (%)", risk_score)

        st.markdown(
            f"### 🚨 Severity Level: <span style='color:{color}'>{severity}</span>",
            unsafe_allow_html=True
        )

        # ---------------- VISUALIZATION ----------------
        st.subheader("📈 Analysis Visualization")

        colA, colB = st.columns(2)

        with colA:
            fig1, ax1 = plt.subplots(figsize=(3, 3))
            ax1.pie(
                [total_records - total_anomalies, total_anomalies],
                labels=["Normal", "Anomaly"],
                autopct="%1.1f%%"
            )
            ax1.set_title("Distribution")
            st.pyplot(fig1)

        with colB:
            fig2, ax2 = plt.subplots(figsize=(3, 3))
            categories = ["Normal", "Anomaly"]
            values = [total_records - total_anomalies, total_anomalies]
            ax2.bar(categories, values)
            ax2.set_title("Record Count Comparison")
            ax2.set_ylabel("Number of Records")
            st.pyplot(fig2)

        # ---------------- ANOMALY TABLE ----------------
        if total_anomalies > 0:
            st.subheader("⚠ Detected Anomalies")
            st.dataframe(anomaly_df)
        else:
            st.success("No anomalies detected.")

        # ---------------- INSTALLED APPLICATIONS ----------------
        st.subheader("💻 Installed Applications")

        apps_df = df[df["Type"] == "InstalledApp"]

        if not apps_df.empty:
            st.dataframe(
                apps_df[["Value1"]]
                .rename(columns={"Value1": "Application Name"})
            )
        else:
            st.info("No installed application data found.")

    except Exception as e:
        st.error(f"Error processing file: {e}")