import logging
import os
import threading
from datetime import datetime, timezone
from watchdog.observers import Observer
from watchdog.events import (
    FileSystemEventHandler,
    FileCreatedEvent,
    FileModifiedEvent,
    FileDeletedEvent,
    FileMovedEvent
)

from .base_monitor import BaseMonitor
from utils.process_utils import calculate_sha256
from config.settings import SettingsManager

logger = logging.getLogger(__name__)

# Security-relevant file extensions (default hash targets)
SECURITY_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".bat", ".cmd",
    ".ps1", ".vbs", ".js", ".scr"
}

# Directories commonly used for persistence
STARTUP_DIRS = [
    os.path.join(os.environ.get("PROGRAMDATA", "C:\\ProgramData"),
                 "Microsoft", "Windows", "Start Menu", "Programs", "Startup").lower(),
    os.path.join(os.environ.get("APPDATA", ""),
                 "Microsoft", "Windows", "Start Menu", "Programs", "Startup").lower(),
]

# Default protected directories
DEFAULT_PROTECTED_DIRS = [
    "C:\\Windows\\System32\\drivers",
    "C:\\Windows\\System32\\config",
    os.path.join(os.environ.get("PROGRAMDATA", "C:\\ProgramData"),
                 "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
    os.path.join(os.environ.get("APPDATA", ""),
                 "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
]


class FIMEventHandler(FileSystemEventHandler):
    """
    Custom watchdog handler that detects file creation, modification,
    deletion, and movement. Publishes events through the parent monitor's
    publish_event method.
    """

    def __init__(self, monitor: "FIMMonitor"):
        super().__init__()
        self._monitor = monitor

    # ---- watchdog callbacks ----

    def on_created(self, event):
        if event.is_directory:
            return
        self._handle_event(event.src_path, "created")

    def on_modified(self, event):
        if event.is_directory:
            return
        self._handle_event(event.src_path, "modified")

    def on_deleted(self, event):
        if event.is_directory:
            return
        self._handle_event(event.src_path, "deleted")

    def on_moved(self, event):
        if event.is_directory:
            return
        self._handle_move(event.src_path, event.dest_path)

    # ---- internal logic ----

    def _is_security_file(self, path: str) -> bool:
        """Check if the file extension is security-relevant."""
        _, ext = os.path.splitext(path)
        return ext.lower() in SECURITY_EXTENSIONS

    def _handle_event(self, file_path: str, action: str):
        """Process a create / modify / delete event."""
        # Only hash security-relevant files
        if not self._is_security_file(file_path):
            return

        sha256 = ""
        old_sha256 = ""
        is_suspicious = False
        reasons = []

        if action == "deleted":
            # Retrieve the cached hash before removing from baseline
            old_sha256 = self._monitor.baseline_cache.pop(file_path, "")
        elif action == "created":
            sha256 = calculate_sha256(file_path)
            self._monitor.baseline_cache[file_path] = sha256
            is_suspicious, reasons = self._assess_suspicion(file_path, action)
        elif action == "modified":
            old_sha256 = self._monitor.baseline_cache.get(file_path, "")
            sha256 = calculate_sha256(file_path)

            # Only publish if the hash actually changed
            if sha256 == old_sha256 and old_sha256 != "":
                return

            self._monitor.baseline_cache[file_path] = sha256
            is_suspicious, reasons = self._assess_suspicion(file_path, action)

        event_data = {
            "file_path": file_path,
            "previous_file_path": "",
            "action": action,
            "sha256": sha256,
            "old_sha256": old_sha256,
            "is_suspicious": is_suspicious,
            "suspicion_reasons": ", ".join(reasons) if reasons else "",
            "timestamp": datetime.now(timezone.utc),
        }

        self._monitor.publish_event("file_event", event_data)

    def _handle_move(self, src_path: str, dest_path: str):
        """Process a file-moved (rename) event."""
        if not self._is_security_file(dest_path) and not self._is_security_file(src_path):
            return

        old_sha256 = self._monitor.baseline_cache.pop(src_path, "")
        sha256 = calculate_sha256(dest_path) if os.path.exists(dest_path) else old_sha256

        # Update baseline under the new path
        if sha256:
            self._monitor.baseline_cache[dest_path] = sha256

        is_suspicious, reasons = self._assess_suspicion(dest_path, "moved")
        # If an executable was renamed into a protected location, that's notable
        if self._is_security_file(dest_path) and not self._is_security_file(src_path):
            is_suspicious = True
            reasons.append("Non-security file renamed to security extension")

        event_data = {
            "file_path": dest_path,
            "previous_file_path": src_path,
            "action": "moved",
            "sha256": sha256,
            "old_sha256": old_sha256,
            "is_suspicious": is_suspicious,
            "suspicion_reasons": ", ".join(reasons) if reasons else "",
            "timestamp": datetime.now(timezone.utc),
        }

        self._monitor.publish_event("file_event", event_data)

    def _assess_suspicion(self, file_path: str, action: str) -> tuple:
        """Evaluate whether the file event is suspicious."""
        is_suspicious = False
        reasons = []
        _, ext = os.path.splitext(file_path)
        ext_lower = ext.lower()
        path_lower = file_path.lower()

        # Check if the file is in a startup folder
        for startup_dir in STARTUP_DIRS:
            if startup_dir and path_lower.startswith(startup_dir):
                if ext_lower in {".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".scr"}:
                    is_suspicious = True
                    reasons.append(f"Executable in Startup folder ({action})")
                break

        # Driver modification
        if ext_lower == ".sys" and action in ("modified", "created"):
            is_suspicious = True
            reasons.append(f"Driver file {action}")

        # DLL modification in protected directories
        if ext_lower == ".dll" and action in ("modified", "created"):
            is_suspicious = True
            reasons.append(f"DLL {action} in protected directory")

        # PowerShell / Batch creation
        if ext_lower in (".ps1", ".bat", ".cmd") and action == "created":
            is_suspicious = True
            reasons.append(f"Script file created ({ext_lower})")

        return is_suspicious, reasons


class FIMMonitor(BaseMonitor):
    """
    File Integrity Monitor using the watchdog library for event-driven
    filesystem monitoring. Maintains a SHA256 baseline cache and only
    publishes events when actual changes are detected.
    """

    def __init__(self, interval: float = None, protected_dirs: list = None):
        if interval is None:
            interval = SettingsManager.get_float("fim_monitor_interval", default=5.0)
        super().__init__("FIMMonitor", interval)

        # Load protected dirs from settings or use defaults
        if protected_dirs is not None:
            self.protected_dirs = protected_dirs
        else:
            configured = SettingsManager.get("fim_protected_dirs")
            if configured:
                # Expect a comma-separated string from settings
                self.protected_dirs = [d.strip() for d in configured.split(",") if d.strip()]
            else:
                self.protected_dirs = DEFAULT_PROTECTED_DIRS

        # SHA256 baseline cache: { absolute_file_path: sha256_hex }
        self.baseline_cache: dict[str, str] = {}

        # watchdog Observer
        self._observer = None
        self._handler = FIMEventHandler(self)

    def _build_baseline(self):
        """Walk all protected directories and hash security-relevant files."""
        logger.info("Building FIM baseline cache...")
        count = 0
        for dir_path in self.protected_dirs:
            if not os.path.isdir(dir_path):
                logger.warning(f"FIM protected directory does not exist: {dir_path}")
                continue
            try:
                for root, _, files in os.walk(dir_path):
                    for fname in files:
                        _, ext = os.path.splitext(fname)
                        if ext.lower() in SECURITY_EXTENSIONS:
                            full_path = os.path.join(root, fname)
                            sha = calculate_sha256(full_path)
                            if sha:
                                self.baseline_cache[full_path] = sha
                                count += 1
            except PermissionError:
                logger.warning(f"Permission denied scanning: {dir_path}")
            except Exception as e:
                logger.error(f"Error scanning {dir_path}: {e}")

        logger.info(f"FIM baseline complete: {count} files hashed.")

    def on_start(self):
        """Build baseline and start the watchdog observer."""
        self._build_baseline()

        self._observer = Observer()
        scheduled = 0
        for dir_path in self.protected_dirs:
            if os.path.isdir(dir_path):
                try:
                    # Watchdog needs directory access when its emitter threads
                    # start; preflight here so one protected folder does not
                    # kill monitoring for every other readable location.
                    with os.scandir(dir_path):
                        pass
                    self._observer.schedule(self._handler, dir_path, recursive=True)
                    scheduled += 1
                    logger.info(f"FIM watching: {dir_path}")
                except OSError as exc:
                    logger.warning("FIM skipping inaccessible directory %s: %s", dir_path, exc)
            else:
                logger.warning(f"FIM skipping non-existent directory: {dir_path}")

        if not scheduled:
            self._observer = None
            logger.warning("FIM has no accessible protected directories; collection is paused.")
            return
        try:
            self._observer.start()
            logger.info("FIM Observer started for %d directories.", scheduled)
        except OSError as exc:
            self._observer = None
            logger.error("FIM observer could not start: %s", exc)

    def on_stop(self):
        """Stop the watchdog observer."""
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5.0)
            logger.info("FIM Observer stopped.")

    def monitor(self):
        """
        The watchdog Observer runs its own internal thread, so our monitor()
        method simply sleeps. The BaseMonitor loop calls this at each interval,
        giving us a natural checkpoint to verify the observer is still alive.
        """
        if self._observer and not self._observer.is_alive():
            logger.error("FIM Observer died unexpectedly. Restarting...")
            self.on_start()
