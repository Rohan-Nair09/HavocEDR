import logging
import threading
import win32api
import win32con
import win32event
from datetime import datetime, timezone
import os

from .base_monitor import BaseMonitor
from utils.process_utils import verify_file_signature

logger = logging.getLogger(__name__)

class RegistryMonitor(BaseMonitor):
    def __init__(self, interval: float = None):
        # Interval is not used for polling here since this is event-driven,
        # but we pass it to BaseMonitor for its internal loop logic (timeout).
        if interval is None:
            from config.settings import SettingsManager
            interval = SettingsManager.get_float("registry_monitor_interval", default=5.0)
        super().__init__("RegistryMonitor", interval)
        
        # Define the target hives and subkeys
        self.targets = [
            (win32con.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU"),
            (win32con.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKCU"),
            (win32con.HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM"),
            (win32con.HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKLM"),
            (win32con.HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Services", "HKLM")
        ]
        
        self.suspicious_dirs = [
            os.environ.get('USERPROFILE', 'C:\\Users').lower(),
            os.environ.get('TEMP', 'C:\\Temp').lower(),
            os.environ.get('APPDATA', 'C:\\Users\\Default\\AppData\\Roaming').lower(),
            os.environ.get('LOCALAPPDATA', 'C:\\Users\\Default\\AppData\\Local').lower()
        ]
        
        self.suspicious_binaries = [
            "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", 
            "rundll32.exe", "regsvr32.exe", "mshta.exe"
        ]

        # Baseline cache: { (hive_str, subkey): { "value_name": "data" } }
        self._baseline = {}
        
        # Win32 resources
        self._key_handles = []
        self._events = []
        self._hives_map = {}

    def _extract_exe_path(self, val: str) -> str:
        """Extract path from command line to verify signature."""
        if not val or not isinstance(val, str):
            return ""
        if val.startswith('"'):
            end_idx = val.find('"', 1)
            if end_idx != -1:
                return val[1:end_idx]
        return val.split(" ")[0]

    def _check_suspicious(self, value_data: str) -> tuple[bool, str, bool]:
        """Returns (is_suspicious, reasons, is_signed)"""
        is_suspicious = False
        reasons = []
        is_signed = True
        
        if not isinstance(value_data, str):
            return is_suspicious, "", is_signed

        val_lower = value_data.lower()
        
        # Check suspicious binaries
        for bin_name in self.suspicious_binaries:
            if bin_name in val_lower:
                is_suspicious = True
                reasons.append(f"Suspicious binary: {bin_name}")
                break
                
        # Check suspicious directories
        exe_path = self._extract_exe_path(value_data)
        if exe_path:
            clean_path = exe_path.lower()
            for s_dir in self.suspicious_dirs:
                if clean_path.startswith(s_dir):
                    is_suspicious = True
                    reasons.append("User/Temp directory in Run key")
                    break
                    
            if os.path.exists(exe_path):
                sig = verify_file_signature(exe_path)
                if sig != "Valid":
                    is_signed = False
                    if sig == "Invalid":
                        is_suspicious = True
                        reasons.append("Invalid signature")
            else:
                is_signed = False # File doesn't exist to verify

        return is_suspicious, ", ".join(reasons), is_signed

    def _snapshot_key(self, hkey, subkey: str) -> dict:
        """Reads all values of a registry key and returns them as a dictionary."""
        snapshot = {}
        try:
            # We open the key specifically for reading
            # KEY_READ includes KEY_QUERY_VALUE, KEY_ENUMERATE_SUB_KEYS, and KEY_NOTIFY
            key_handle = win32api.RegOpenKeyEx(hkey, subkey, 0, win32con.KEY_READ)
            idx = 0
            while True:
                try:
                    val_name, val_data, val_type = win32api.RegEnumValue(key_handle, idx)
                    snapshot[val_name] = str(val_data)
                    idx += 1
                except win32api.error as e:
                    if e.winerror == 259: # ERROR_NO_MORE_ITEMS
                        break
                    raise
            win32api.RegCloseKey(key_handle)
        except Exception as e:
            logger.debug(f"Could not snapshot registry key {subkey}: {e}")
        return snapshot

    def on_start(self):
        """Build baseline and open registry handles before the main loop."""
        logger.info("Building Registry Baseline...")
        for hkey, subkey, hive_str in self.targets:
            try:
                # Build snapshot
                snapshot = self._snapshot_key(hkey, subkey)
                self._baseline[(hive_str, subkey)] = snapshot
                
                # Open handle for notification
                # KEY_NOTIFY is required
                handle = win32api.RegOpenKeyEx(hkey, subkey, 0, win32con.KEY_NOTIFY | win32con.KEY_READ)
                evt = win32event.CreateEvent(None, 0, 0, None)
                
                # Register for change notification
                win32api.RegNotifyChangeKeyValue(
                    handle, 
                    True, # Watch subtrees (for services mainly, though Run keys don't usually need it)
                    1 | 4, # REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET
                    evt, 
                    True # Asynchronous
                )
                
                self._key_handles.append(handle)
                self._events.append(evt)
                self._hives_map[evt] = (hkey, subkey, hive_str, handle)
                
            except Exception as e:
                logger.error(f"Failed to setup monitor for {hive_str}\\{subkey}: {e}")

        # Also add a custom event to allow waking up the wait loop to exit gracefully
        self._quit_event = win32event.CreateEvent(None, 0, 0, None)
        self._events.append(self._quit_event)

    def stop(self):
        super().stop()
        if hasattr(self, '_quit_event') and self._quit_event:
            win32event.SetEvent(self._quit_event)

    def on_stop(self):
        """Cleanup handles."""
        for h in self._key_handles:
            try:
                win32api.RegCloseKey(h)
            except:
                pass
        for e in self._events:
            try:
                win32api.CloseHandle(e)
            except:
                pass

    def monitor(self):
        """Event-driven wait loop."""
        if not self._events:
            # If nothing to monitor, just sleep
            time.sleep(self.interval)
            return

        # Wait for any of the events to be signaled
        # Timeout is set to self.interval so the thread can still occasionally check self._stop_event
        # but the wait uses milliseconds.
        rc = win32event.WaitForMultipleObjects(self._events, False, int(self.interval * 1000))
        
        if rc == win32event.WAIT_TIMEOUT:
            return
            
        # If it's not a timeout, an event was signaled
        idx = rc - win32event.WAIT_OBJECT_0
        if idx < 0 or idx >= len(self._events):
            return
            
        signaled_event = self._events[idx]
        
        if signaled_event == self._quit_event:
            return # We are stopping
            
        # A registry key changed
        hkey, subkey, hive_str, handle = self._hives_map[signaled_event]
        
        logger.info(f"Registry change detected in {hive_str}\\{subkey}")
        
        # Take a new snapshot
        new_snapshot = self._snapshot_key(hkey, subkey)
        old_snapshot = self._baseline.get((hive_str, subkey), {})
        
        # Compare snapshots
        # 1. Added values
        for val_name, val_data in new_snapshot.items():
            if val_name not in old_snapshot:
                self._process_change(hive_str, subkey, val_name, "", val_data, "added")
            elif old_snapshot[val_name] != val_data:
                # 2. Modified values
                self._process_change(hive_str, subkey, val_name, old_snapshot[val_name], val_data, "modified")
                
        # 3. Deleted values
        for val_name, val_data in old_snapshot.items():
            if val_name not in new_snapshot:
                self._process_change(hive_str, subkey, val_name, val_data, "", "deleted")
                
        # Update baseline
        self._baseline[(hive_str, subkey)] = new_snapshot
        
        # Re-register for notifications
        try:
            win32api.RegNotifyChangeKeyValue(
                handle, 
                True, 
                1 | 4, # REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET
                signaled_event, 
                True
            )
        except Exception as e:
            logger.error(f"Failed to re-register notification for {hive_str}\\{subkey}: {e}")

    def _process_change(self, hive, key_path, value_name, old_value, new_value, change_type):
        """Processes the delta and publishes the event."""
        # For deletion, we don't necessarily flag it as suspicious (usually added/modified matters more)
        is_suspicious = False
        reasons = ""
        is_signed = True
        
        if change_type in ["added", "modified"]:
            is_suspicious, reasons, is_signed = self._check_suspicious(new_value)
            
        event_data = {
            "hive": hive,
            "key_path": key_path,
            "value_name": value_name,
            "old_value": old_value,
            "new_value": new_value,
            "change_type": change_type,
            "is_signed": is_signed,
            "is_suspicious": is_suspicious,
            "suspicion_reasons": reasons,
            "timestamp": datetime.now(timezone.utc)
        }
        
        self.publish_event("registry_event", event_data)
