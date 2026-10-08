import logging
import psutil
from collections import deque
from datetime import datetime, timezone
import time
from typing import Dict, Any

from .base_monitor import BaseMonitor
from utils.process_utils import calculate_sha256, verify_file_signature
from config.settings import SettingsManager

logger = logging.getLogger(__name__)

class ProcessMonitor(BaseMonitor):
    def __init__(self, interval: float = None):
        # Fetch the interval from settings if not provided
        if interval is None:
            interval = SettingsManager.get_float("process_monitor_interval")
            
        super().__init__("ProcessMonitor", interval)
        
        # Cache to store static info about processes to avoid re-hashing and re-verifying
        # Key: PID, Value: Dict of static info
        self._process_cache: Dict[int, Dict[str, Any]] = {}
        # Hashing and Authenticode checks can be expensive. Spread first-run
        # enrichment over several cycles so a large process list does not
        # compete with the dashboard during startup.
        self._enrichment_queue = deque()
        self._enrichment_per_cycle = 8

    def on_start(self):
        logger.info("Initializing process cache...")
        # Optional: pre-warm the cache, but doing it in the first loop is also fine.
        pass

    def monitor(self):
        current_pids = set(psutil.pids())
        
        # Remove dead processes from cache
        dead_pids = set(self._process_cache.keys()) - current_pids
        for pid in dead_pids:
            del self._process_cache[pid]

        for pid in current_pids:
            # Check if we should abort early
            if self._stop_event.is_set():
                break
                
            try:
                proc = psutil.Process(pid)
                
                # Psutil can raise exceptions if the process dies while we query it
                with proc.oneshot():
                    start_time = proc.create_time()
                    is_new_process = not (
                        pid in self._process_cache
                        and self._process_cache[pid]["start_time"] == start_time
                    )
                    
                    # If we have it in cache and start time matches, it's the same process
                    if pid in self._process_cache and self._process_cache[pid]["start_time"] == start_time:
                        static_info = self._process_cache[pid]
                    else:
                        # New process or PID reused, gather static info
                        try:
                            exe_path = proc.exe()
                        except (psutil.AccessDenied, psutil.ZombieProcess):
                            exe_path = ""
                            
                        try:
                            cmdline_list = proc.cmdline()
                            command_line = " ".join(cmdline_list) if cmdline_list else ""
                        except psutil.AccessDenied:
                            command_line = ""

                        try:
                            username = proc.username()
                        except psutil.AccessDenied:
                            username = ""

                        parent = proc.parent()
                        parent_pid = parent.pid if parent else 0
                        parent_name = parent.name() if parent else ""

                        static_info = {
                            "name": proc.name(),
                            "path": exe_path,
                            "command_line": command_line,
                            "user": username,
                            "parent_pid": parent_pid,
                            "parent_name": parent_name,
                            "start_time": start_time,
                            "process_hash": "",
                            "digital_signature": "Pending" if exe_path else "Unknown",
                        }
                        self._process_cache[pid] = static_info
                        if exe_path:
                            self._enrichment_queue.append((pid, start_time, exe_path))

                    # Gather dynamic info (fast operations)
                    cpu_percent = proc.cpu_percent()
                    ram_info = proc.memory_info()
                    ram_usage_mb = ram_info.rss / (1024 * 1024)
                    thread_count = proc.num_threads()
                    status = proc.status()

                    # Threat Score (Basic rule-based logic for now, AI/ML will enhance later)
                    is_suspicious = False
                    threat_score = 0.0
                    
                    if static_info["digital_signature"] == "Invalid":
                        threat_score += 40.0
                        is_suspicious = True
                    elif static_info["digital_signature"] == "Unsigned" and static_info["path"].lower().startswith("c:\\windows"):
                        threat_score += 60.0 # Unsigned binary in Windows folder is highly suspicious
                        is_suspicious = True
                        
                    # Prepare the event data
                    event_data = {
                        "pid": pid,
                        "name": static_info["name"],
                        "parent_pid": static_info["parent_pid"],
                        "parent_name": static_info["parent_name"],
                        "path": static_info["path"],
                        "command_line": static_info["command_line"],
                        "user": static_info["user"],
                        "cpu_percent": round(cpu_percent, 2),
                        "ram_usage_mb": round(ram_usage_mb, 2),
                        "thread_count": thread_count,
                        "status": status,
                        "start_time": datetime.fromtimestamp(static_info["start_time"], timezone.utc),
                        "process_hash": static_info["process_hash"],
                        "digital_signature": static_info["digital_signature"],
                        "threat_score": threat_score,
                        "is_suspicious": is_suspicious,
                        "timestamp": datetime.now(timezone.utc)
                    }

                    # Publish the event via EventBus
                    self.publish_event("process_event", event_data)
                    if is_new_process:
                        # Keep the persisted snapshot schema clean while
                        # providing correlation logic an explicit transition.
                        self.publish_event("process_start_event", {
                            "pid": pid,
                            "name": static_info["name"],
                            "action": "started",
                            "executable_path": static_info["path"],
                            "timestamp": event_data["timestamp"],
                        })

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # These are transient errors common when querying processes, skip silently
                pass
            except Exception as e:
                logger.error(f"Unexpected error monitoring PID {pid}: {e}")

        self._enrich_pending_processes()

    def _enrich_pending_processes(self):
        """Hash and verify a small number of process images per monitor cycle."""
        for _ in range(min(self._enrichment_per_cycle, len(self._enrichment_queue))):
            pid, start_time, exe_path = self._enrichment_queue.popleft()
            static_info = self._process_cache.get(pid)
            if static_info is None or static_info.get("start_time") != start_time:
                continue
            try:
                static_info["process_hash"] = calculate_sha256(exe_path)
                static_info["digital_signature"] = verify_file_signature(exe_path)
            except Exception as exc:
                logger.debug("Could not enrich process image %s: %s", exe_path, exc)
