import logging
import psutil
import socket
import ipaddress
import time
from datetime import datetime, timezone
import os

from .base_monitor import BaseMonitor
from config.settings import SettingsManager
from utils.process_utils import verify_file_signature

logger = logging.getLogger(__name__)

# Living off the land binaries
LOL_BINS = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe"}

# User writable directories
USER_WRITABLE_DIRS = [
    os.environ.get("TEMP", "C:\\Temp").lower(),
    os.environ.get("APPDATA", "C:\\Users\\Default\\AppData\\Roaming").lower(),
    os.environ.get("LOCALAPPDATA", "C:\\Users\\Default\\AppData\\Local").lower(),
    "c:\\users\\"
]

def is_public_ip(ip_addr: str) -> bool:
    """Check if an IP address is public (not loopback, not private)."""
    try:
        ip = ipaddress.ip_address(ip_addr)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast)
    except ValueError:
        return False

def is_in_user_dir(path: str) -> bool:
    """Check if path is in a common user-writable directory."""
    if not path:
        return False
    p = path.lower()
    return any(p.startswith(d) for d in USER_WRITABLE_DIRS)


class NetworkMonitor(BaseMonitor):
    """
    State-polling Network Monitor using psutil.net_connections().
    Tracks connections by a unique tuple key and generates events for
    new connections, state changes, and closed connections.
    """

    def __init__(self, interval: float = None):
        if interval is None:
            interval = SettingsManager.get_float("network_monitor_interval", default=5.0)
        super().__init__("NetworkMonitor", interval)

        # Connection Cache: { connection_key: { ...state... } }
        self._connection_cache = {}
        self._connection_error_logged = False
        
        # Rate Limiting: { pid: [timestamp, timestamp, ...] }
        self._connection_rate = {}
        self.RATE_LIMIT_THRESHOLD = 50 # connections per 10 seconds

    def _get_process_info(self, pid: int):
        """Retrieve process name, path, and username safely."""
        name = "Unknown"
        path = ""
        username = ""
        if pid == 0:
            return "System Idle Process", "", "NT AUTHORITY\\SYSTEM"
        elif pid == 4:
            return "System", "", "NT AUTHORITY\\SYSTEM"

        try:
            p = psutil.Process(pid)
            name = p.name()
            path = p.exe()
            username = p.username()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        return name, path, username

    def _assess_suspicion(self, name: str, path: str, remote_ip: str, pid: int) -> tuple[bool, str]:
        """Check for suspicious network activity."""
        is_suspicious = False
        reasons = []

        # 1. Connection from LOL bins to Public IPs
        if name.lower() in LOL_BINS and remote_ip and is_public_ip(remote_ip):
            is_suspicious = True
            reasons.append(f"Public network connection from LOLBin ({name})")

        # 2. Connection from user-writable directories
        if is_in_user_dir(path):
            is_suspicious = True
            reasons.append(f"Network connection from executable in user directory")

        # 3. Connection from unsigned process
        if path and os.path.exists(path):
            sig = verify_file_signature(path)
            if sig != "Valid":
                is_suspicious = True
                reasons.append(f"Network connection from unsigned process")

        # 4. Excessive connection rate
        now = time.time()
        rate_list = self._connection_rate.get(pid, [])
        # Keep only timestamps from the last 10 seconds
        rate_list = [t for t in rate_list if now - t <= 10.0]
        rate_list.append(now)
        self._connection_rate[pid] = rate_list

        if len(rate_list) > self.RATE_LIMIT_THRESHOLD:
            is_suspicious = True
            reasons.append(f"Excessive connection rate ({len(rate_list)} conns in 10s)")

        return is_suspicious, ", ".join(reasons)

    def monitor(self):
        """Poll psutil for current connections and diff against the cache."""
        try:
            current_conns = psutil.net_connections(kind='all')
        except (psutil.AccessDenied, RuntimeError, OSError) as exc:
            if not self._connection_error_logged:
                logger.warning("Network connection table is unavailable; collector will retry: %s", exc)
                self._connection_error_logged = True
            return
        self._connection_error_logged = False

        current_keys = set()

        for conn in current_conns:
            pid = conn.pid
            if pid is None:
                continue

            # Connection key tuple as requested
            protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
            local_ip = conn.laddr.ip if conn.laddr else ""
            local_port = conn.laddr.port if conn.laddr else 0
            remote_ip = conn.raddr.ip if conn.raddr else ""
            remote_port = conn.raddr.port if conn.raddr else 0
            status = conn.status

            conn_key = (protocol, local_ip, local_port, remote_ip, remote_port, pid)
            current_keys.add(conn_key)

            if conn_key not in self._connection_cache:
                # NEW CONNECTION
                name, path, username = self._get_process_info(pid)
                is_suspicious, reasons = self._assess_suspicion(name, path, remote_ip, pid)

                event_data = {
                    "pid": pid,
                    "process_name": name,
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "protocol": protocol,
                    "status": "NEW - " + status,
                    "username": username,
                    "is_suspicious": is_suspicious,
                    "suspicion_reasons": reasons,
                    "timestamp": datetime.now(timezone.utc),
                }

                self.publish_event("network_event", event_data)
                
                self._connection_cache[conn_key] = {
                    "status": status,
                    "process_name": name,
                    "username": username
                }

            else:
                # EXISTING CONNECTION - Check for state change
                cached_conn = self._connection_cache[conn_key]
                if cached_conn["status"] != status:
                    cached_conn["status"] = status
                    
                    event_data = {
                        "pid": pid,
                        "process_name": cached_conn["process_name"],
                        "local_ip": local_ip,
                        "local_port": local_port,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "protocol": protocol,
                        "status": "STATE_CHANGE - " + status,
                        "username": cached_conn["username"],
                        "is_suspicious": False, # Just a state change
                        "suspicion_reasons": "",
                        "timestamp": datetime.now(timezone.utc),
                    }
                    self.publish_event("network_event", event_data)

        # Detect CLOSED connections
        closed_keys = set(self._connection_cache.keys()) - current_keys
        for closed_key in closed_keys:
            cached_conn = self._connection_cache.pop(closed_key)
            protocol, local_ip, local_port, remote_ip, remote_port, pid = closed_key

            event_data = {
                "pid": pid,
                "process_name": cached_conn["process_name"],
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "protocol": protocol,
                "status": "CLOSED",
                "username": cached_conn["username"],
                "is_suspicious": False,
                "suspicion_reasons": "",
                "timestamp": datetime.now(timezone.utc),
            }
            self.publish_event("network_event", event_data)
