"""
Windows system audit — formal multi-file CSV report.

Default output: audit_output/Report_<YYYYMMDD_HHMMSS>_<hostname>/
  00_COVER_AND_MANIFEST.csv   — report title, timestamps, tool version (2-column formal cover)
  01_FILES_INDEX.csv          — index of all section files (read this first after the cover)
  02_*.csv …                  — one wide table per topic, UTF-8 BOM for Excel

Each data file includes columns: Audit_Reference_Timestamp, Asset_Hostname, Section_Title,
then named data columns (no anonymous value1/value2).

Optional: set EXPORT_TIDY_FACTS=1 to also write 99_LONG_FORMAT_FACTS.csv (tidy key-value).

Remote access: RDP, WinRM, OpenSSH, Remote Registry. Service stop audit off by default.

Override directory: environment variable AUDIT_CSV_DIR
"""
from __future__ import annotations

import csv
import json
import os
import platform
import re
import socket
import subprocess
import sys
import winreg
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import psutil

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
SCRIPT_VERSION = "2.0"
# Original script stopped Bluetooth/WLAN/location services — off by default.
ENABLE_SERVICE_STOP_AUDIT = False
# Set True to skip full audit when 172.30.x.x is detected (legacy behavior).
EXIT_ON_172_30 = True


def _run_ps_json(args: List[str]) -> Any:
    r = subprocess.run(
        ["powershell", "-NoProfile", "-Command", args[0]],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        raise RuntimeError(r.stderr or r.stdout or "PowerShell error")
    out = r.stdout.strip()
    if not out:
        return None
    return json.loads(out)


def _normalize_ps_json_list(data: Any) -> List[Dict[str, Any]]:
    if data is None:
        return []
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    return []


class TidyAuditWriter:
    """
    One CSV schema for every row (Excel / SQL friendly):
    Audit_Timestamp | Table | Record_ID | Field_Name | Field_Value

    - Single-row sections use Record_ID "".
    - Repeated records (processes, connections, programs) use Record_ID 1, 2, 3, ...
    """

    HEADER = ["Audit_Timestamp", "Table", "Record_ID", "Field_Name", "Field_Value"]

    def __init__(self, path: str, audit_ts: str, *, file_mode: str = "a") -> None:
        self.audit_ts = audit_ts
        self._file = open(path, file_mode, newline="", encoding="utf-8")
        self._w = csv.writer(self._file)
        self._w.writerow(self.HEADER)

    def close(self) -> None:
        self._file.close()

    def write_dict(self, table: str, data: Dict[str, Any], record_id: str = "") -> None:
        for k, v in data.items():
            self._w.writerow([self.audit_ts, table, record_id, k, _csv_val(v)])

    def write_rows(self, table: str, rows: List[Dict[str, Any]]) -> None:
        for i, row in enumerate(rows, 1):
            rid = str(i)
            for k, v in row.items():
                self._w.writerow([self.audit_ts, table, rid, k, _csv_val(v)])

    def write_marker(self, label: str, detail: str = "") -> None:
        self.write_dict("MARKER", {"Label": label, "Detail": detail})


class FormalReportWriter:
    """
    Formal audit package: numbered wide CSVs, cover manifest, files index, utf-8-sig for Excel.
    """

    ENCODING = "utf-8-sig"

    def __init__(self, audit_root: str, audit_ts: str, hostname: str, run_id: str) -> None:
        self.audit_ts = audit_ts
        self.hostname = hostname
        self.run_id = run_id
        self.report_dir = os.path.join(audit_root, f"Report_{run_id}_{hostname}")
        os.makedirs(self.report_dir, exist_ok=True)
        self._index_rows: List[Dict[str, Any]] = []

    def report_path(self) -> str:
        return self.report_dir

    def _sanitize_suffix(self, name: str) -> str:
        return re.sub(r"[^A-Za-z0-9_]+", "_", name).strip("_") or "Section"

    def write_cover_manifest(self, extra: Optional[Dict[str, str]] = None) -> None:
        pairs: List[Tuple[str, str]] = [
            ("Report_Title", "Windows System Security & Configuration Audit"),
            ("Report_Format_Version", "1.0"),
            ("Generated_Local_Time", self.audit_ts),
            ("Asset_Hostname", self.hostname),
            ("Report_Run_Id", self.run_id),
            ("Tool_Version", SCRIPT_VERSION),
            ("Python_Version", sys.version.split()[0]),
            ("OS_Platform", platform.platform()),
            ("Output_Directory", self.report_dir),
            ("Section_Catalog_File", "01_FILES_INDEX.csv"),
        ]
        if extra:
            pairs.extend((k, str(v)) for k, v in extra.items())
        path = os.path.join(self.report_dir, "00_COVER_AND_MANIFEST.csv")
        with open(path, "w", newline="", encoding=self.ENCODING) as f:
            w = csv.writer(f)
            w.writerow(["Field", "Value"])
            for field, value in pairs:
                w.writerow([field, value])
        self._index_rows.append(
            {
                "Sequence": 0,
                "Filename": "00_COVER_AND_MANIFEST.csv",
                "Section_Title": "Cover and manifest",
                "Description": "Report identification and generation metadata",
                "Record_Count": len(pairs),
            }
        )

    def write_wide_table(
        self,
        seq: int,
        file_suffix: str,
        section_title: str,
        rows: List[Dict[str, Any]],
        description: str = "",
    ) -> None:
        if not rows:
            rows = [{"Note": "No records in this section"}]
        col_order: List[str] = []
        seen: set[str] = set()
        for r in rows:
            for k in r:
                if k not in seen:
                    seen.add(k)
                    col_order.append(k)
        fieldnames = [
            "Audit_Reference_Timestamp",
            "Asset_Hostname",
            "Section_Title",
        ] + col_order
        fname = f"{seq:02d}_{self._sanitize_suffix(file_suffix)}.csv"
        path = os.path.join(self.report_dir, fname)
        with open(path, "w", newline="", encoding=self.ENCODING) as f:
            w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            w.writeheader()
            for r in rows:
                row_out: Dict[str, Any] = {
                    "Audit_Reference_Timestamp": self.audit_ts,
                    "Asset_Hostname": self.hostname,
                    "Section_Title": section_title,
                }
                for k in col_order:
                    row_out[k] = _csv_val(r.get(k))
                w.writerow(row_out)
        self._index_rows.append(
            {
                "Sequence": seq,
                "Filename": fname,
                "Section_Title": section_title,
                "Description": description or section_title,
                "Record_Count": len(rows),
            }
        )

    def finalize_index(self) -> None:
        """Write 01_FILES_INDEX.csv — catalog of all section files (sorted by Sequence)."""
        rows = sorted(self._index_rows, key=lambda x: (x["Sequence"], x["Filename"]))
        path = os.path.join(self.report_dir, "01_FILES_INDEX.csv")
        fieldnames = [
            "Sequence",
            "Filename",
            "Section_Title",
            "Description",
            "Record_Count",
        ]
        with open(path, "w", newline="", encoding=self.ENCODING) as f:
            w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            w.writeheader()
            for r in rows:
                w.writerow(r)


def _csv_val(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, (dict, list)):
        return json.dumps(v, ensure_ascii=False)
    return str(v)


def _reg_str(key: int, sub: str, name: str) -> str:
    try:
        with winreg.OpenKey(key, sub) as k:
            v, _ = winreg.QueryValueEx(k, name)
            return str(v)
    except OSError:
        return "Unknown"


def get_service_state_sc(service_name: str) -> str:
    try:
        r = subprocess.run(
            ["sc", "query", service_name], capture_output=True, text=True, timeout=30
        )
        if "RUNNING" in r.stdout:
            return "Running"
        if "STOPPED" in r.stdout:
            return "Stopped"
        return "Unknown"
    except Exception as e:
        return f"Error:{e}"


def is_port_listening_tcp(port: int) -> bool:
    try:
        for c in psutil.net_connections(kind="inet"):
            if (
                c.status == psutil.CONN_LISTEN
                and c.type == socket.SOCK_STREAM
                and c.laddr
                and c.laddr.port == port
            ):
                return True
    except Exception:
        pass
    return False


def is_rdp_registry_allowing_connections() -> str:
    v = _reg_str(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Terminal Server",
        "fDenyTSConnections",
    )
    if v == "0":
        return "Yes"
    if v == "1":
        return "No"
    return "Unknown"


def get_remote_protocols_audit() -> List[Dict[str, Any]]:
    """RDP, WinRM, OpenSSH Server, Remote Registry — service + port + registry where relevant."""
    rows: List[Dict[str, Any]] = []

    rdp_allow = is_rdp_registry_allowing_connections()
    rdp_nla = _reg_str(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
        "SecurityLayer",
    )
    rows.append(
        {
            "Protocol": "RDP",
            "Registry_fDenyTSConnections_Allows_RDP": rdp_allow,
            "RDP_Tcp_SecurityLayer": rdp_nla,
            "Service_TermService": get_service_state_sc("TermService"),
            "TCP_3389_Listening": "Yes" if is_port_listening_tcp(3389) else "No",
            "UDP_3389_Common": "Yes" if _udp_port_open(3389) else "No",
        }
    )

    rows.append(
        {
            "Protocol": "WinRM",
            "Service_WinRM": get_service_state_sc("WinRM"),
            "HTTP_5985_Listening": "Yes" if is_port_listening_tcp(5985) else "No",
            "HTTPS_5986_Listening": "Yes" if is_port_listening_tcp(5986) else "No",
        }
    )

    rows.append(
        {
            "Protocol": "OpenSSH_Server",
            "Service_sshd": get_service_state_sc("sshd"),
            "TCP_22_Listening": "Yes" if is_port_listening_tcp(22) else "No",
        }
    )

    rows.append(
        {
            "Protocol": "Remote_Registry",
            "Service_RemoteRegistry": get_service_state_sc("RemoteRegistry"),
            "Notes": "Remote Registry uses RPC; assess service state, not a single TCP port",
        }
    )

    return rows


def _udp_port_open(port: int) -> bool:
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.type == socket.SOCK_DGRAM and c.laddr and c.laddr.port == port:
                return True
    except Exception:
        pass
    return False


def collect_all_ips(hostname: str) -> Tuple[bool, List[Dict[str, Any]]]:
    """Returns (has_172_30_range, rows)."""
    infos = socket.getaddrinfo(hostname, None)
    unique_ips = sorted({info[4][0] for info in infos if "." in info[4][0]})
    contains_172_30 = any(ip.startswith("172.30.") for ip in unique_ips)
    rows = [
        {
            "Hostname": hostname,
            "IPv4_Address": ip,
            "In_172_30_Range": "Yes" if ip.startswith("172.30.") else "No",
        }
        for ip in unique_ips
    ]
    return contains_172_30, rows


def getAll_IPs(writer: TidyAuditWriter, hostname: str) -> bool:
    """Returns True if any 172.30.x.x present (optional early exit)."""
    contains_172_30, rows = collect_all_ips(hostname)
    if rows:
        writer.write_rows("ALL_IPS", rows)
    return contains_172_30


def get_system_info_dict() -> Dict[str, Any]:
    hostname = socket.gethostname()

    def ethernet_mac() -> str:
        for interface, addrs in psutil.net_if_addrs().items():
            if "eth" in interface.lower():
                for addr in addrs:
                    if addr.family == psutil.AF_LINK:
                        return addr.address
        return ""

    mac = ethernet_mac() or "NA-MAC-ERROR"
    try:
        ip_address = socket.gethostbyname(hostname)
    except Exception:
        ip_address = "Unknown"

    if os.name == "nt":
        try:
            serial_number = (
                subprocess.check_output("wmic bios get serialnumber", shell=True)
                .decode(errors="replace")
                .split("\n")[1]
                .strip()
            )
        except Exception:
            serial_number = "Not Available"
    else:
        serial_number = "Not Available [non-Windows]"

    last_update = "Not Applicable"
    if os.name == "nt":
        try:
            ps_script = """
            $lastUpdate = Get-HotFix | Sort-Object -Property InstalledOn | Select-Object -Last 1
            if ($lastUpdate) {
                $lastUpdate.InstalledOn.ToString('dd/MM/yyyy HH:mm:ss')
            } else {
                "Not Available"
            }
            """
            last_update = (
                subprocess.check_output(
                    ["powershell", "-NoProfile", "-Command", ps_script], stderr=subprocess.STDOUT
                )
                .decode(errors="replace")
                .strip()
            )
        except Exception as e:
            last_update = f"Error: {e}"

    license_status = "Not Applicable"
    if os.name == "nt":
        try:
            lic = subprocess.check_output(
                'wmic path SoftwareLicensingProduct where "PartialProductKey is not null" get LicenseStatus /value',
                shell=True,
            ).decode(errors="replace")
            license_status = "Licensed" if "LicenseStatus=1" in lic else "Not Licensed"
        except Exception:
            license_status = "Not Available"

    product_id = "Not Available"
    if os.name == "nt":
        try:
            product_id = (
                subprocess.check_output("wmic os get serialnumber", shell=True)
                .decode(errors="replace")
                .split("\n")[1]
                .strip()
            )
        except Exception:
            pass

    bios_version = "Not Available"
    if os.name == "nt":
        try:
            bios_version = (
                subprocess.check_output("wmic bios get smbiosbiosversion", shell=True)
                .decode(errors="replace")
                .split("\n")[1]
                .strip()
            )
        except Exception:
            pass

    processor = "Unknown"
    if os.name == "nt":
        try:
            processor = (
                subprocess.run(
                    ["wmic", "cpu", "get", "name", "/value"], capture_output=True, text=True
                )
                .stdout.split("=", 1)[-1]
                .strip()
            )
        except Exception as e:
            processor = f"Unknown ({e})"

    connectivity = "Disconnected"
    for _, stats in psutil.net_if_stats().items():
        if stats.isup:
            connectivity = "Connected"
            break

    network_info: Dict[str, Dict[str, str]] = {}
    for interface_name, interface_addresses in psutil.net_if_addrs().items():
        for address in interface_addresses:
            if str(address.family) == "AddressFamily.AF_INET":
                network_info.setdefault(interface_name, {})["IPv4 Address"] = address.address
            if str(address.family) == "AddressFamily.AF_LINK":
                network_info.setdefault(interface_name, {})["MAC Address"] = address.address

    primary_interface = None
    for interface_name, details in network_info.items():
        if "IPv4 Address" in details and details["IPv4 Address"] != "127.0.0.1":
            primary_interface = interface_name
            break

    pri_ip = "Not Available"
    pri_mac = "Not Available"
    if primary_interface:
        pri_ip = network_info[primary_interface].get("IPv4 Address", "Not Available")
        pri_mac = network_info[primary_interface].get("MAC Address", "Not Available")

    wifi_interface = "Not Applicable"
    if os.name == "nt":
        try:
            service_status = subprocess.check_output("sc query wlansvc", shell=True).decode(
                errors="replace"
            )
            wifi_interface = (
                "Wi-Fi Available"
                if "RUNNING" in service_status
                else "wlansvc not running"
            )
        except Exception:
            wifi_interface = "wlansvc query failed"

    last_updated = "Not Available"
    if os.name == "nt":
        try:
            systeminfo_output = subprocess.check_output("systeminfo", shell=True).decode(
                errors="replace"
            )
            for line in systeminfo_output.split("\n"):
                if "Original Install Date" in line:
                    last_updated = line.split(":", 1)[1].strip()
                    break
        except Exception:
            last_updated = "Not Available"

    domain = "Not Applicable"
    if os.name == "nt":
        try:
            domain = (
                subprocess.check_output("wmic computersystem get domain", shell=True)
                .decode(errors="replace")
                .split("\n")[1]
                .strip()
            )
        except Exception:
            domain = "Not Available"

    boot_time = ""
    try:
        boot_time = datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        pass

    mem = psutil.virtual_memory()
    disk = psutil.disk_usage(os.environ.get("SystemDrive", "C:"))

    return {
        "Hostname_DNS": hostname,
        "Primary_IP_gethostbyname": ip_address,
        "Ethernet_MAC_or_first_eth": mac,
        "BIOS_Serial": serial_number,
        "Computer_Name": platform.node(),
        "OS_Name": platform.system(),
        "Last_Hotfix_Date_PowerShell": last_update,
        "OS_Version": platform.version(),
        "Windows_Service_Pack": platform.win32_ver()[2] if os.name == "nt" else "N/A",
        "OS_Config_Note": "Member Workstation" if os.name == "nt" else "N/A",
        "License_Status_WMI": license_status,
        "OS_Serial_ProductId_WMI": product_id,
        "BIOS_Version": bios_version,
        "Windows_Directory": os.environ.get("WINDIR", ""),
        "System32_Path": os.path.join(os.environ.get("WINDIR", ""), "system32")
        if os.name == "nt"
        else "",
        "Processor": processor,
        "Machine_Arch": platform.machine(),
        "Network_Connectivity_Summary": connectivity,
        "Primary_Non_Loopback_Interface": primary_interface or "",
        "Primary_Interface_IPv4": pri_ip,
        "Primary_Interface_MAC": pri_mac,
        "WiFi_WlanSvc_Status_Message": wifi_interface,
        "OS_Original_Install_Date_systeminfo": last_updated,
        "Domain_WMI": domain,
        "Boot_Time": boot_time,
        "Memory_Total_GB": round(mem.total / (1024**3), 2),
        "Memory_Available_GB": round(mem.available / (1024**3), 2),
        "Disk_SystemDrive_Total_GB": round(disk.total / (1024**3), 2),
        "Disk_SystemDrive_Free_GB": round(disk.free / (1024**3), 2),
    }


def get_installed_programs_rows() -> List[Dict[str, Any]]:
    programs: List[Dict[str, Any]] = []
    registry_paths = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ]

    def is_system_software(name: str) -> bool:
        keys = ("Driver", "Visual C++", "Runtime", "Microsoft")
        return any(k in name for k in keys)

    for reg_path in registry_paths:
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
            for i in range(0, winreg.QueryInfoKey(reg_key)[0]):
                sub_key_name = winreg.EnumKey(reg_key, i)
                sub_key = winreg.OpenKey(reg_key, sub_key_name)
                try:
                    program_name = winreg.QueryValueEx(sub_key, "DisplayName")[0]
                    try:
                        install_date = winreg.QueryValueEx(sub_key, "InstallDate")[0]
                    except OSError:
                        install_date = ""
                    try:
                        ver = winreg.QueryValueEx(sub_key, "DisplayVersion")[0]
                    except OSError:
                        ver = ""
                    try:
                        pub = winreg.QueryValueEx(sub_key, "Publisher")[0]
                    except OSError:
                        pub = ""
                    programs.append(
                        {
                            "DisplayName": program_name,
                            "DisplayVersion": ver,
                            "Publisher": pub,
                            "InstallDate_YYYYMMDD": install_date,
                            "Category": "System" if is_system_software(program_name) else "UserInstalled",
                            "RegistryHive": "HKLM",
                            "UninstallSubKey": sub_key_name,
                        }
                    )
                except OSError:
                    continue
        except OSError:
            continue
    return programs


def get_startup_programs() -> List[tuple]:
    startup_programs: List[tuple] = []
    reg_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]
    for hive, reg_path in reg_paths:
        try:
            with winreg.OpenKey(hive, reg_path) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        startup_programs.append((hive, reg_path, name, value))
                        i += 1
                    except OSError:
                        break
        except FileNotFoundError:
            continue
    return startup_programs


PROTOCOL_PORTS = {
    "HTTP": [80],
    "HTTPS": [443],
    "FTP": [21],
    "SMTP": [25],
    "DNS": [53],
    "LDAP": [389, 636],
    "Telnet": [23],
    "SFTP": [22],
    "RDP": [3389],
    "IMAP": [143],
    "POP3": [110],
}


def get_protocol_from_port(port: Any, connection_type: str) -> str:
    if connection_type == "UDP":
        return "UDP"
    try:
        p = int(port)
    except Exception:
        return "TCP"
    for protocol, ports in PROTOCOL_PORTS.items():
        if p in ports:
            return protocol
    return "TCP"


def fetch_connections() -> List[Dict[str, Any]]:
    connections: List[Dict[str, Any]] = []
    for conn in psutil.net_connections(kind="inet"):
        if conn.type == socket.SOCK_STREAM:
            connection_type = "TCP"
        elif conn.type == socket.SOCK_DGRAM:
            connection_type = "UDP"
        else:
            connection_type = "Other"
        source_ip, source_port = conn.laddr
        dest_ip, dest_port = conn.raddr if conn.raddr else ("", "")
        if dest_port == "":
            dest_port = ""
        conn_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        process_name = "Unknown"
        if conn.pid:
            try:
                process_name = psutil.Process(conn.pid).name()
            except Exception:
                process_name = "Unknown"
        status = conn.status if conn.type == socket.SOCK_STREAM else "N/A"
        protocol_type = get_protocol_from_port(dest_port, connection_type)
        connections.append(
            {
                "Protocol_Type_Inferred": protocol_type,
                "Transport": connection_type,
                "Source_IP": source_ip,
                "Source_Port": source_port,
                "Destination_IP": dest_ip,
                "Destination_Port": dest_port,
                "Observed_At": conn_time,
                "TCP_Status": status,
                "PID": conn.pid or "",
                "Process_Name": process_name,
            }
        )
    return connections


def get_service_name_port(port: int, protocol: str) -> str:
    try:
        return socket.getservbyport(port, protocol)
    except OSError:
        return "Unknown"


def fetch_open_ports() -> List[Dict[str, Any]]:
    open_ports: List[Dict[str, Any]] = []
    for conn in psutil.net_connections(kind="inet"):
        if conn.status != psutil.CONN_LISTEN:
            continue
        if conn.type == socket.SOCK_STREAM:
            protocol = "TCP"
        elif conn.type == socket.SOCK_DGRAM:
            protocol = "UDP"
        else:
            protocol = "Other"
        port_number = conn.laddr.port
        service_name = get_service_name_port(port_number, protocol.lower())
        bound_ip = conn.laddr.ip
        pid = conn.pid
        process_name = "Unknown"
        if pid:
            try:
                process_name = psutil.Process(pid).name()
            except Exception:
                pass
        open_ports.append(
            {
                "Port": port_number,
                "Protocol": protocol,
                "Service_Name_getservbyport": service_name,
                "Process_Name": process_name,
                "Bound_IP": bound_ip,
                "PID": pid or "",
            }
        )
    return open_ports


def get_process_info_rows() -> List[Dict[str, Any]]:
    """cpu_num is not a valid psutil as_dict attr on many versions; use cpu_affinity() instead."""
    processes: List[Dict[str, Any]] = []
    _attrs = [
        "pid",
        "name",
        "status",
        "memory_info",
        "num_threads",
        "username",
        "create_time",
        "exe",
    ]
    for proc in psutil.process_iter(_attrs):
        try:
            pinfo = proc.as_dict(attrs=_attrs)
            pid = pinfo["pid"]
            mem_mb = pinfo["memory_info"].rss / (1024 * 1024) if pinfo.get("memory_info") else ""
            st = pinfo.get("create_time")
            start_time = (
                datetime.fromtimestamp(st).strftime("%Y-%m-%d %H:%M:%S") if st else ""
            )
            try:
                aff = proc.cpu_affinity()
                cpu_affinity_str = ",".join(str(x) for x in aff) if aff is not None else ""
            except (psutil.AccessDenied, NotImplementedError, AttributeError):
                cpu_affinity_str = ""
            processes.append(
                {
                    "PID": pid,
                    "Process_Name": pinfo.get("name"),
                    "Status": pinfo.get("status"),
                    "Memory_RSS_MB": round(mem_mb, 2) if mem_mb != "" else "",
                    "Thread_Count": pinfo.get("num_threads"),
                    "User_Name": pinfo.get("username") or "",
                    "Start_Time": start_time,
                    "Executable_Path": pinfo.get("exe") or "",
                    "CPU_Affinity_Allowed_CPUs": cpu_affinity_str,
                    "Note": "CPU% requires interval; not sampled in this pass",
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return processes


def get_registry_value1() -> str:
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\USBStor") as k:
            v, _ = winreg.QueryValueEx(k, "Start")
            return str(v)
    except FileNotFoundError:
        return "Key not found"
    except OSError:
        return "Error"


def get_firewall_status() -> Dict[str, str]:
    command = ["powershell", "-NoProfile", "-Command", "Get-NetFirewallProfile | Select-Object Name, Enabled"]
    result = subprocess.run(command, capture_output=True, text=True)
    status: Dict[str, str] = {}
    for line in result.stdout.splitlines():
        if "Domain" in line:
            status["Firewall_Domain"] = "ON" if "True" in line else "OFF"
        elif "Private" in line:
            status["Firewall_Private"] = "ON" if "True" in line else "OFF"
        elif "Public" in line:
            status["Firewall_Public"] = "ON" if "True" in line else "OFF"
    return status


def collect_whoami() -> Optional[Dict[str, Any]]:
    try:
        result = subprocess.run(["whoami"], capture_output=True, text=True, check=True)
        return {"Interactive_User_Context": result.stdout.strip()}
    except subprocess.CalledProcessError:
        return None


def append_whoami(writer: TidyAuditWriter) -> None:
    d = collect_whoami()
    if d:
        writer.write_dict("WHOAMI", d)


def collect_local_admins() -> List[Dict[str, Any]]:
    cmd = "Get-LocalGroupMember -Group 'Administrators' | Select-Object ObjectClass, Name, PrincipalSource | ConvertTo-Json"
    try:
        data = _run_ps_json([cmd])
        rows: List[Dict[str, Any]] = []
        for admin in _normalize_ps_json_list(data):
            rows.append(
                {
                    "ObjectClass": str(admin.get("ObjectClass", "")),
                    "Name": str(admin.get("Name", "")),
                    "PrincipalSource_Raw": str(admin.get("PrincipalSource", "")),
                }
            )
        return rows
    except Exception as e:
        return [{"Error": str(e)}]


def append_local_admins(writer: TidyAuditWriter) -> None:
    rows = collect_local_admins()
    if rows:
        writer.write_rows("LOCAL_ADMINS", rows)


def collect_local_users() -> List[Dict[str, Any]]:
    cmd = """
    Get-LocalUser | Select-Object Name, Enabled, SID,
      @{Name='IsAdministrator'; Expression={($_ | Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue).Count -gt 0}} | ConvertTo-Json
    """
    try:
        data = _run_ps_json([cmd])
        rows: List[Dict[str, Any]] = []
        for u in _normalize_ps_json_list(data):
            rows.append(
                {
                    "Name": str(u.get("Name", "")),
                    "Enabled": str(u.get("Enabled", "")),
                    "IsAdministrator": str(u.get("IsAdministrator", "")),
                    "SID": str(u.get("SID", "")),
                }
            )
        return rows
    except Exception as e:
        return [{"Error": str(e)}]


def append_local_users(writer: TidyAuditWriter) -> None:
    rows = collect_local_users()
    if rows:
        writer.write_rows("LOCAL_USERS", rows)


def collect_net_adapters() -> List[Dict[str, Any]]:
    cmd = "Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed | ConvertTo-Json"
    try:
        data = _run_ps_json([cmd])
        rows: List[Dict[str, Any]] = []
        for a in _normalize_ps_json_list(data):
            rows.append(
                {
                    "Name": str(a.get("Name", "")),
                    "InterfaceDescription": str(a.get("InterfaceDescription", "")),
                    "Status": str(a.get("Status", "")),
                    "MacAddress": str(a.get("MacAddress", "")),
                    "LinkSpeed": str(a.get("LinkSpeed", "")),
                }
            )
        return rows
    except Exception as e:
        return [{"Error": str(e)}]


def append_net_adapters(writer: TidyAuditWriter) -> None:
    rows = collect_net_adapters()
    if rows:
        writer.write_rows("NET_ADAPTERS", rows)


def collect_net_interfaces_netsh() -> List[Dict[str, Any]]:
    try:
        result = subprocess.run(
            ["netsh", "interface", "show", "interface"],
            capture_output=True,
            text=True,
            check=True,
        )
        lines = result.stdout.splitlines()
        rows: List[Dict[str, Any]] = []
        for line in lines[3:]:
            parts = [p for p in line.split(" ") if p]
            if len(parts) >= 4:
                rows.append(
                    {
                        "Admin_State": parts[0],
                        "State": parts[1],
                        "Type": parts[2],
                        "Interface_Name": " ".join(parts[3:]),
                    }
                )
        return rows
    except Exception as e:
        return [{"Error": str(e)}]


def append_interfaces(writer: TidyAuditWriter) -> None:
    rows = collect_net_interfaces_netsh()
    if rows:
        writer.write_rows("NET_INTERFACES_NETSH", rows)


def collect_portable_devices() -> List[Dict[str, Any]]:
    cmd = r"""
    Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows Portable Devices\Devices' -ErrorAction SilentlyContinue |
    ForEach-Object {
        $friendlyName = $null
        try { $friendlyName = (Get-ItemProperty -Path $_.PSPath -Name FriendlyName -ErrorAction Stop).FriendlyName } catch {}
        [PSCustomObject]@{ Name = $_.Name; FriendlyName = $friendlyName }
    } | ConvertTo-Json
    """
    try:
        data = _run_ps_json([cmd])
        rows: List[Dict[str, Any]] = []
        for d in _normalize_ps_json_list(data):
            rows.append(
                {"Registry_Name": str(d.get("Name", "")), "FriendlyName": str(d.get("FriendlyName", ""))}
            )
        return rows
    except Exception as e:
        return [{"Error": str(e)}]


def append_portable_devices(writer: TidyAuditWriter) -> None:
    rows = collect_portable_devices()
    if rows:
        writer.write_rows("PORTABLE_DEVICES", rows)


def get_shared_folders_rows() -> List[Dict[str, Any]]:
    ps_command = r"""
    Get-SmbShare -ErrorAction SilentlyContinue | ForEach-Object {
        $shareName = $_.Name
        $sharePath = $_.Path
        $permissions = Get-SmbShareAccess -Name $shareName -ErrorAction SilentlyContinue | Select-Object AccountName, AccessRight
        $everyoneAccess = $permissions | Where-Object { $_.AccountName -like '*Everyone*' }
        $isUnprotected = if ($everyoneAccess -and $everyoneAccess.AccessRight -ne 'None') { 'Unprotected' } else { 'Protected' }
        [PSCustomObject]@{
            ShareName = $shareName
            SharePath = $sharePath
            Status = $isUnprotected
            EveryoneAccess = if ($everyoneAccess) { $everyoneAccess.AccessRight } else { 'No' }
        }
    } | ConvertTo-Json
    """
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps_command], capture_output=True, text=True
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr or "Get-SmbShare failed")
    raw = (result.stdout or "").strip()
    if not raw:
        return []
    data = json.loads(raw)
    if isinstance(data, dict):
        return [data]
    return list(data)


def get_local_password_policies_dict() -> Dict[str, str]:
    result = subprocess.run(["net", "accounts"], capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr)
    output = result.stdout
    patterns = {
        "Force_user_logoff_after_expiry": r"Force user logoff how long after time expires:\s+(.+)",
        "Minimum_password_age_days": r"Minimum password age \(days\):\s+(\d+)",
        "Maximum_password_age_days": r"Maximum password age \(days\):\s+(\d+)",
        "Minimum_password_length": r"Minimum password length:\s+(\d+)",
        "Password_history_length": r"Length of password history maintained:\s+(\d+)",
        "Lockout_threshold": r"Lockout threshold:\s+(.+)",
        "Lockout_duration_minutes": r"Lockout duration \(minutes\):\s+(\d+)",
        "Lockout_observation_window_minutes": r"Lockout observation window \(minutes\):\s+(\d+)",
    }
    policies: Dict[str, str] = {}
    for key, pattern in patterns.items():
        m = re.search(pattern, output)
        policies[key] = m.group(1).strip() if m else "Unknown"
    return policies


def is_autoplay_status() -> str:
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers",
        )
        try:
            value, _ = winreg.QueryValueEx(key, "DisableAutoplay")
            status = "Disabled" if value == 1 else "Enabled"
        except FileNotFoundError:
            status = "Enabled"
        winreg.CloseKey(key)
        return status
    except Exception:
        return "Unknown"


def get_last_windows_update_dict() -> Dict[str, str]:
    cmd = """
    Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1 | Select-Object HotFixID, InstalledOn, Description | ConvertTo-Json
    """
    result = subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr or result.stdout or "Get-HotFix failed")
    raw = (result.stdout or "").strip()
    if not raw:
        return {"HotFixID": "", "InstalledOn": "", "Description": ""}
    update = json.loads(raw)
    hotfix_id = str(update.get("HotFixID", ""))
    installed_on = update.get("InstalledOn", "")
    desc = str(update.get("Description", ""))
    if isinstance(installed_on, str) and "T" in installed_on:
        try:
            installed_on = datetime.fromisoformat(installed_on.rstrip("Z")).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        except Exception:
            pass
    return {"HotFixID": hotfix_id, "InstalledOn": str(installed_on), "Description": desc}


def get_applied_gpos_list() -> List[str]:
    result = subprocess.run(["gpresult", "/r"], capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr)
    gpos: List[str] = []
    in_sec = False
    for line in result.stdout.splitlines():
        if "Applied Group Policy Objects" in line:
            in_sec = True
            continue
        if in_sec:
            if line.strip() == "":
                break
            if line.strip() and not line.strip().startswith("---"):
                gpos.append(line.strip())
    return gpos


def collect_manage_services_audit() -> List[Dict[str, Any]]:
    if not ENABLE_SERVICE_STOP_AUDIT:
        return [
            {
                "Skipped": "ENABLE_SERVICE_STOP_AUDIT is False",
                "Note": "Set ENABLE_SERVICE_STOP_AUDIT True only if stopping services is intentional",
            }
        ]
    services = ["bthserv", "WlanSvc", "lfsvc"]
    try:
        rows: List[Dict[str, Any]] = []
        for service in services:
            status_result = subprocess.run(["sc", "query", service], capture_output=True, text=True)
            initial = "Running" if "RUNNING" in status_result.stdout else "Stopped"
            stopped = "No"
            if initial == "Running":
                stop_result = subprocess.run(["sc", "stop", service], capture_output=True, text=True)
                if stop_result.returncode == 0 and (
                    "STOP_PENDING" in stop_result.stdout or "STOPPED" in stop_result.stdout
                ):
                    stopped = "Yes"
                else:
                    stopped = "Failed"
            rows.append(
                {"Service": service, "Initial_Status": initial, "Stop_Requested_Result": stopped}
            )
        return rows
    except Exception as e:
        return [{"Error": str(e)}]


def manage_services_audit(writer: TidyAuditWriter) -> None:
    rows = collect_manage_services_audit()
    if rows:
        writer.write_rows("SERVICE_STOP_AUDIT", rows)


def _registry_hive_label(hive: Any) -> str:
    if hive == winreg.HKEY_LOCAL_MACHINE:
        return "HKLM"
    if hive == winreg.HKEY_CURRENT_USER:
        return "HKCU"
    return str(hive)


def run_audit_formal(audit_root: str, audit_ts: str, run_id: str, hostname: str) -> str:
    """Writes formal multi-file CSV report. Returns path to report directory."""
    fr = FormalReportWriter(audit_root, audit_ts, hostname, run_id)
    seq = 2

    def sn() -> int:
        nonlocal seq
        s = seq
        seq += 1
        return s

    fr.write_cover_manifest()

    contains_172_30, ip_rows = collect_all_ips(hostname)
    fr.write_wide_table(
        sn(),
        "ALL_IPS",
        "IPv4 addresses (hostname resolution)",
        ip_rows,
        "All IPv4 addresses returned for the asset hostname",
    )

    if EXIT_ON_172_30 and contains_172_30:
        fr.write_wide_table(
            sn(),
            "AUDIT_TERMINATION",
            "Audit stopped early",
            [{"Status": "Terminated", "Reason": "172.30.x.x address detected (EXIT_ON_172_30)"}],
            "Legacy exit condition",
        )
        fr.finalize_index()
        return fr.report_path()

    fr.write_wide_table(
        sn(),
        "SYSTEM_INFO",
        "System overview",
        [get_system_info_dict()],
        "OS, hardware, network summary, disk and memory",
    )

    fr.write_wide_table(
        sn(),
        "REMOTE_PROTOCOLS",
        "Remote access protocols",
        get_remote_protocols_audit(),
        "RDP, WinRM, OpenSSH, Remote Registry",
    )

    whoami_d = collect_whoami()
    if whoami_d:
        fr.write_wide_table(sn(), "WHOAMI", "Interactive user context", [whoami_d], "whoami output")

    fr.write_wide_table(
        sn(),
        "LOCAL_ADMINS",
        "Local Administrators group",
        collect_local_admins(),
        "Members of the local Administrators group",
    )

    fr.write_wide_table(
        sn(),
        "LOCAL_USERS",
        "Local user accounts",
        collect_local_users(),
        "Local users and admin flag",
    )

    fr.write_wide_table(
        sn(),
        "NET_ADAPTERS",
        "Network adapters",
        collect_net_adapters(),
        "Physical/logical adapters from Get-NetAdapter",
    )

    fr.write_wide_table(
        sn(),
        "NET_INTERFACES_NETSH",
        "Interface status (netsh)",
        collect_net_interfaces_netsh(),
        "Administrative state of interfaces",
    )

    fr.write_wide_table(
        sn(),
        "PORTABLE_DEVICES",
        "Portable device registry",
        collect_portable_devices(),
        "Windows Portable Devices registry entries",
    )

    fr.write_wide_table(
        sn(),
        "INSTALLED_PROGRAMS",
        "Installed programs (uninstall registry)",
        get_installed_programs_rows(),
        "HKLM uninstall registry",
    )

    fr.write_wide_table(
        sn(),
        "RUNNING_PROCESSES",
        "Running processes",
        get_process_info_rows(),
        "Process list snapshot",
    )

    su_rows: List[Dict[str, Any]] = []
    for hive, reg_path, name, value in get_startup_programs():
        su_rows.append(
            {
                "Registry_Hive": _registry_hive_label(hive),
                "Registry_Path": reg_path,
                "Value_Name": name,
                "Command_Line": value,
            }
        )
    fr.write_wide_table(
        sn(),
        "STARTUP_PROGRAMS",
        "Startup registry entries",
        su_rows,
        "Run / RunOnce keys",
    )

    fr.write_wide_table(
        sn(),
        "ESTABLISHED_CONNECTIONS",
        "Network connections",
        fetch_connections(),
        "psutil net_connections snapshot",
    )

    fr.write_wide_table(
        sn(),
        "LISTENING_PORTS",
        "Listening ports",
        fetch_open_ports(),
        "TCP/UDP listeners",
    )

    fw = get_firewall_status()
    fr.write_wide_table(
        sn(),
        "SECURITY_STATUS",
        "Security posture summary",
        [
            {
                "USBStor_Start_Registry": get_registry_value1(),
                "RDP_Registry_Allows_Connections": is_rdp_registry_allowing_connections(),
                "Kaspersky_Placeholder": "RXs",
                "Firewall_Domain": fw.get("Firewall_Domain", "Unknown"),
                "Firewall_Private": fw.get("Firewall_Private", "Unknown"),
                "Firewall_Public": fw.get("Firewall_Public", "Unknown"),
            }
        ],
        "USB storage, RDP policy, firewall profiles",
    )

    try:
        shares = get_shared_folders_rows()
        fr.write_wide_table(
            sn(),
            "SMB_SHARES",
            "SMB shares",
            shares if shares else [{"Info": "No shares returned"}],
            "Share paths and Everyone access summary",
        )
    except Exception as e:
        fr.write_wide_table(sn(), "SMB_SHARES", "SMB shares", [{"Error": str(e)}], "")

    try:
        fr.write_wide_table(
            sn(),
            "PASSWORD_POLICY",
            "Local password policy",
            [get_local_password_policies_dict()],
            "net accounts",
        )
    except Exception as e:
        fr.write_wide_table(sn(), "PASSWORD_POLICY", "Local password policy", [{"Error": str(e)}], "")

    fr.write_wide_table(
        sn(),
        "AUTOPLAY",
        "Autoplay (current user)",
        [{"User_Autoplay_Status": is_autoplay_status()}],
        "Registry AutoplayHandlers",
    )

    try:
        fr.write_wide_table(
            sn(),
            "LAST_WINDOWS_UPDATE",
            "Most recent hotfix",
            [get_last_windows_update_dict()],
            "Get-HotFix latest",
        )
    except Exception as e:
        fr.write_wide_table(sn(), "LAST_WINDOWS_UPDATE", "Most recent hotfix", [{"Error": str(e)}], "")

    try:
        gpos = get_applied_gpos_list()
        fr.write_wide_table(
            sn(),
            "APPLIED_GPOS",
            "Applied Group Policy objects",
            [{"GPO_Name": g} for g in gpos] if gpos else [{"GPO_Name": "None"}],
            "gpresult /r",
        )
    except Exception as e:
        fr.write_wide_table(sn(), "APPLIED_GPOS", "Applied Group Policy objects", [{"Error": str(e)}], "")

    fr.write_wide_table(
        sn(),
        "SERVICE_STOP_AUDIT",
        "Optional service stop audit",
        collect_manage_services_audit(),
        "Bluetooth/WLAN/location if ENABLE_SERVICE_STOP_AUDIT",
    )

    duration_s = (
        datetime.now() - datetime.strptime(audit_ts, "%Y-%m-%d %H:%M:%S")
    ).total_seconds()
    fr.write_wide_table(
        sn(),
        "AUDIT_COMPLETION",
        "Run completion",
        [
            {
                "Status": "Completed",
                "Duration_Seconds": round(duration_s, 3),
                "Tool_Version": SCRIPT_VERSION,
            }
        ],
        "Successful end of collection",
    )

    fr.finalize_index()
    return fr.report_path()


def run_audit_tidy(csvfilename: str, audit_ts: str) -> None:
    """Legacy single-file tidy CSV (Audit_Timestamp, Table, Record_ID, Field_Name, Field_Value)."""
    writer = TidyAuditWriter(csvfilename, audit_ts, file_mode="w")
    try:
        writer.write_marker("AUDIT_START", SCRIPT_VERSION)
        writer.write_dict(
            "AUDIT_META",
            {
                "Audit_Timestamp": audit_ts,
                "Hostname": socket.gethostname(),
                "Script_Version": SCRIPT_VERSION,
                "Python_Version": sys.version.split()[0],
                "Platform": platform.platform(),
            },
        )

        hostname = socket.gethostname()
        if EXIT_ON_172_30 and getAll_IPs(writer, hostname):
            writer.write_marker("EARLY_EXIT", "172.30.x.x detected")
            return

        writer.write_dict("SYSTEM_INFO", get_system_info_dict())

        writer.write_rows("REMOTE_PROTOCOLS", get_remote_protocols_audit())

        append_whoami(writer)
        append_local_admins(writer)
        append_local_users(writer)
        append_net_adapters(writer)
        append_interfaces(writer)
        append_portable_devices(writer)

        writer.write_rows("INSTALLED_PROGRAMS", get_installed_programs_rows())

        writer.write_rows("RUNNING_PROCESSES", get_process_info_rows())

        su_rows = []
        for hive, reg_path, name, value in get_startup_programs():
            su_rows.append(
                {
                    "Registry_Hive": _registry_hive_label(hive),
                    "Registry_Path": reg_path,
                    "Value_Name": name,
                    "Command_Line": value,
                }
            )
        if su_rows:
            writer.write_rows("STARTUP_PROGRAMS", su_rows)

        writer.write_rows("ESTABLISHED_CONNECTIONS", fetch_connections())
        writer.write_rows("LISTENING_PORTS", fetch_open_ports())

        fw = get_firewall_status()
        writer.write_dict(
            "SECURITY_STATUS",
            {
                "USBStor_Start_Registry": get_registry_value1(),
                "RDP_Registry_Allows_Connections": is_rdp_registry_allowing_connections(),
                "Kaspersky_Placeholder": "RXs",
                "Firewall_Domain": fw.get("Firewall_Domain", "Unknown"),
                "Firewall_Private": fw.get("Firewall_Private", "Unknown"),
                "Firewall_Public": fw.get("Firewall_Public", "Unknown"),
            },
        )

        try:
            shares = get_shared_folders_rows()
            if shares:
                writer.write_rows("SMB_SHARES", shares)
            else:
                writer.write_dict("SMB_SHARES", {"Info": "No shares returned"})
        except Exception as e:
            writer.write_dict("SMB_SHARES", {"Error": str(e)})

        try:
            writer.write_dict("PASSWORD_POLICY", get_local_password_policies_dict())
        except Exception as e:
            writer.write_dict("PASSWORD_POLICY", {"Error": str(e)})

        writer.write_dict("AUTOPLAY", {"User_Autoplay_Status": is_autoplay_status()})

        try:
            writer.write_dict("LAST_WINDOWS_UPDATE", get_last_windows_update_dict())
        except Exception as e:
            writer.write_dict("LAST_WINDOWS_UPDATE", {"Error": str(e)})

        try:
            gpos = get_applied_gpos_list()
            if gpos:
                writer.write_rows("APPLIED_GPOS", [{"GPO_Name": g} for g in gpos])
            else:
                writer.write_dict("APPLIED_GPOS", {"GPO_Name": "None"})
        except Exception as e:
            writer.write_dict("APPLIED_GPOS", {"Error": str(e)})

        manage_services_audit(writer)

        writer.write_marker(
            "SUCCESS",
            str(
                (
                    datetime.now() - datetime.strptime(audit_ts, "%Y-%m-%d %H:%M:%S")
                ).total_seconds()
            ),
        )
    finally:
        writer.close()


def main() -> None:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    audit_folder = os.environ.get("AUDIT_CSV_DIR", os.path.join(current_dir, "audit_output"))
    if not os.path.exists(audit_folder):
        os.makedirs(audit_folder)

    audit_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    hostname = socket.gethostname()

    try:
        report_path = run_audit_formal(audit_folder, audit_ts, run_id, hostname)
        print(f"Formal report directory: {report_path}")
        if os.environ.get("EXPORT_TIDY_FACTS", "").strip().lower() in ("1", "true", "yes"):
            tidy_path = os.path.join(report_path, "99_LONG_FORMAT_FACTS.csv")
            run_audit_tidy(tidy_path, audit_ts)
            print(f"Also wrote tidy long-format CSV: {tidy_path}")
    except Exception as e:
        print(f"An error occurred: {e}")
        raise


if __name__ == "__main__":
    main()
