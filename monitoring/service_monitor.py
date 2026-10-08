import logging
import psutil
from datetime import datetime, timezone
import os

from .base_monitor import BaseMonitor
from utils.process_utils import verify_file_signature
from config.settings import SettingsManager

logger = logging.getLogger(__name__)

class ServiceMonitor(BaseMonitor):
    def __init__(self, interval: float = None):
        if interval is None:
            interval = SettingsManager.get_float("service_monitor_interval", default=10.0)
        super().__init__("ServiceMonitor", interval)
        
        # Cache to store static info and state about services
        # Key: Service Name (string)
        self._service_cache = {}
        
        # List of potentially suspicious directories
        # We expand common env vars to their absolute paths to easily check prefixes
        self.suspicious_dirs = [
            os.environ.get('USERPROFILE', 'C:\\Users').lower(),
            os.environ.get('TEMP', 'C:\\Temp').lower(),
            os.environ.get('APPDATA', 'C:\\Users\\Default\\AppData\\Roaming').lower(),
            os.environ.get('LOCALAPPDATA', 'C:\\Users\\Default\\AppData\\Local').lower(),
            "c:\\temp",
            "c:\\programdata" # Sometimes used by malware
        ]

    def _is_suspicious_path(self, binpath: str) -> bool:
        if not binpath:
            return False
            
        # Clean up path (sometimes paths contain quotes or arguments)
        clean_path = binpath.replace('"', '').strip().lower()
        
        for s_dir in self.suspicious_dirs:
            if clean_path.startswith(s_dir):
                return True
        return False

    def _extract_exe_path(self, binpath: str) -> str:
        """Attempts to extract just the executable path from a binpath string."""
        if not binpath:
            return ""
        
        # If it's quoted, extract what's inside quotes
        if binpath.startswith('"'):
            end_quote = binpath.find('"', 1)
            if end_quote != -1:
                return binpath[1:end_quote]
                
        # Otherwise, split by space and assume the first part is the exe,
        # but this fails for paths with spaces. Usually services are quoted if they have spaces.
        return binpath.split(" ")[0]

    def monitor(self):
        try:
            services = list(psutil.win_service_iter())
        except Exception as e:
            logger.error(f"Failed to iterate Windows services: {e}")
            return
            
        current_service_names = set()
        
        for service in services:
            # Check for early stop
            if self._stop_event.is_set():
                break
                
            try:
                name = service.name()
                current_service_names.add(name)
                
                status = service.status()
                
                # Check cache for state changes
                if name in self._service_cache:
                    if self._service_cache[name]["status"] == status:
                        # No change in state, skip publishing to save DB writes
                        continue
                    else:
                        # Status changed! Update cache
                        self._service_cache[name]["status"] = status
                        cached_info = self._service_cache[name]
                else:
                    # New service discovered
                    display_name = service.display_name()
                    binpath = service.binpath()
                    
                    exe_path = self._extract_exe_path(binpath)
                    
                    is_signed = False
                    digital_signature = "Unknown"
                    if exe_path and os.path.exists(exe_path):
                        digital_signature = verify_file_signature(exe_path)
                        is_signed = (digital_signature == "Valid")
                    
                    is_suspicious = False
                    reasons = []
                    
                    if self._is_suspicious_path(binpath):
                        is_suspicious = True
                        reasons.append("Path in user/temp directory")
                        
                    if digital_signature == "Invalid":
                        is_suspicious = True
                        reasons.append("Invalid digital signature")
                    elif digital_signature == "Unsigned" and is_suspicious:
                        # Unsigned combined with bad path is high risk
                        reasons.append("Unsigned executable")
                    
                    cached_info = {
                        "name": name,
                        "display_name": display_name,
                        "binpath": binpath,
                        "status": status,
                        "is_signed": is_signed,
                        "is_suspicious": is_suspicious,
                        "suspicion_reasons": ", ".join(reasons) if reasons else ""
                    }
                    self._service_cache[name] = cached_info
                
                # Publish event
                event_data = {
                    "name": cached_info["name"],
                    "display_name": cached_info["display_name"],
                    "status": cached_info["status"],
                    "binpath": cached_info["binpath"],
                    "is_signed": cached_info["is_signed"],
                    "is_suspicious": cached_info["is_suspicious"],
                    "suspicion_reasons": cached_info["suspicion_reasons"],
                    "timestamp": datetime.now(timezone.utc)
                }
                
                self.publish_event("service_event", event_data)
                
            except psutil.AccessDenied:
                pass
            except psutil.NoSuchProcess:
                pass
            except Exception as e:
                logger.error(f"Error processing service {service}: {e}")
                
        # Remove deleted services from cache (optional cleanup)
        dead_services = set(self._service_cache.keys()) - current_service_names
        for s in dead_services:
            del self._service_cache[s]
