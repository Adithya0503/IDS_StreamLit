@echo off
color 0A
title Windows AI Security Audit Collector

echo =====================================================
echo       WINDOWS AI SECURITY DATA COLLECTOR
echo =====================================================
echo.

:: 1. Check for Python
python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python is NOT installed.
    echo Please install Python from https://www.python.org/
    pause
    exit /b
)

:: 2. Install Required Dependencies
echo [STATUS] Verifying required libraries (psutil)...
pip install psutil --quiet [cite: 4]

:: 3. Create the Python Script File
set SCRIPT_NAME=windows_system_audit.py
echo [STATUS] Preparing audit engine...

:: This block writes the full windows_system_audit.py to the disk
(
echo import csv, json, os, platform, re, socket, subprocess, sys, winreg
echo from datetime import datetime
echo import psutil
echo SCRIPT_VERSION = "2.0"
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
) > %SCRIPT_NAME% [cite: 5]

:: 4. Run the Script
echo [STATUS] Running System Audit...
python %SCRIPT_NAME% 

:: 5. Cleanup and Finish
echo.
echo =====================================================
echo AUDIT COMPLETED SUCCESSFULLY 
echo Please upload the CSV files from the 'audit_output' 
echo folder to the AI Security Website.
echo =====================================================
explorer audit_output 
pause
