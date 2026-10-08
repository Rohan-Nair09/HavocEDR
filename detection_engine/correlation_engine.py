import time
import logging
from collections import deque
from .alert_manager import alert_manager
from monitoring.events import event_bus

logger = logging.getLogger(__name__)

class CorrelationEngine:
    """
    Evaluates streams of telemetry events for stateful cross-event patterns.
    """
    def __init__(self):
        # Tracking recent USB insertions: list of (timestamp, drive_letter)
        self.recent_usbs = []
        
        # Tracking recent file creations on USBs: list of (timestamp, file_path)
        self.usb_file_creations = []

        # Tracking file modifications for Ransomware heuristic
        # deque of timestamps
        self.file_modifications = deque()

    def process_usb_event(self, data: dict):
        if data.get("action") == "inserted":
            drive = data.get("drive_letter")
            if drive:
                self.recent_usbs.append((time.time(), drive))

    def process_file_event(self, data: dict):
        now = time.time()
        
        # Rule 6: Mass File Modification (Ransomware heuristic)
        if data.get("action") == "modified":
            self.file_modifications.append(now)
            
            # Prune old events (older than 60 seconds)
            while self.file_modifications and now - self.file_modifications[0] > 60:
                self.file_modifications.popleft()
                
            if len(self.file_modifications) >= 50:
                alert_manager.emit_alert(
                    title="Mass File Modification Detected",
                    description="50+ file modifications occurred within 60 seconds. Potential ransomware activity.",
                    severity="Critical",
                    source_modules=["FIM"],
                    related_event_ids=[],
                    threat_type="Impact"
                )
                self.file_modifications.clear() # Reset after alert

        # Support for USB Malware execution: track executable creations on recent USB drives
        if data.get("action") == "created":
            path = data.get("file_path", "").upper()
            if path.endswith(".EXE") or path.endswith(".BAT") or path.endswith(".CMD") or path.endswith(".PS1"):
                # Check if it's on a recently inserted USB (within 5 mins)
                for t, drive in self.recent_usbs:
                    if now - t <= 300 and path.startswith(drive.upper()):
                        self.usb_file_creations.append((now, path))

    def process_process_event(self, data: dict):
        now = time.time()
        path = data.get("executable_path", "").upper()
        
        if data.get("action") == "started":
            # Check if this process was recently dropped on a USB
            # Clean up old creations first
            self.usb_file_creations = [(t, p) for t, p in self.usb_file_creations if now - t <= 300]
            
            for t, fpath in self.usb_file_creations:
                if fpath == path:
                    alert_manager.emit_alert(
                        title="USB Malware Execution",
                        description=f"An executable dropped on a recently inserted USB drive was executed.\nFile: {path}",
                        severity="Critical",
                        source_modules=["USBMonitor", "FIM", "ProcessMonitor"],
                        related_event_ids=[],
                        threat_type="Execution"
                    )
                    event_bus.publish("response_candidate", {
                        "reason": "usb_executable_execution",
                        "pid": data.get("pid"),
                        "process_name": data.get("name", ""),
                        "executable_path": data.get("executable_path", ""),
                    })
                    break

    def cleanup(self):
        """Periodic cleanup of old state."""
        now = time.time()
        self.recent_usbs = [(t, d) for t, d in self.recent_usbs if now - t <= 300]
        self.usb_file_creations = [(t, p) for t, p in self.usb_file_creations if now - t <= 300]
