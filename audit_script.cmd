@echo off
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
echo from datetime import datetime>> %SCRIPT_NAME%
echo hostname = socket.gethostname()>> %SCRIPT_NAME%
echo timestamp = datetime.now().strftime("%%Y%%m%%d_%%H%%M%%S")>> %SCRIPT_NAME%
echo filename = hostname + "_audit_" + timestamp + ".csv">> %SCRIPT_NAME%
echo with open(filename, "w", newline="") as file:>> %SCRIPT_NAME%
echo     writer = csv.writer(file)>> %SCRIPT_NAME%
echo     writer.writerow(["Type","Value1","Value2","Value3"])>> %SCRIPT_NAME%
echo     writer.writerow(["CPU_Percent", psutil.cpu_percent(), "", ""])>> %SCRIPT_NAME%
echo     writer.writerow(["Memory_Percent", psutil.virtual_memory().percent, "", ""])>> %SCRIPT_NAME%
echo     for proc in psutil.process_iter(['pid','cpu_percent','memory_percent']):>> %SCRIPT_NAME%
echo         try:>> %SCRIPT_NAME%
echo             writer.writerow(["Process", proc.info['pid'], proc.info['cpu_percent'], round(proc.info['memory_percent'],2)])>> %SCRIPT_NAME%
echo         except:>> %SCRIPT_NAME%
echo             pass>> %SCRIPT_NAME%
echo     for conn in psutil.net_connections(kind='inet'):>> %SCRIPT_NAME%
echo         if conn.status == psutil.CONN_LISTEN:>> %SCRIPT_NAME%
echo             writer.writerow(["OpenPort", conn.laddr.port, conn.pid, ""])>> %SCRIPT_NAME%
echo print("Audit file created:", filename)>> %SCRIPT_NAME%

python %SCRIPT_NAME%
del %SCRIPT_NAME%

echo.
echo AUDIT COMPLETED SUCCESSFULLY
explorer .
pause