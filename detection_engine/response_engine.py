"""Opt-in, narrowly scoped automated process response."""

import logging
import threading
from datetime import datetime, timezone

import psutil

from config.settings import SettingsManager
from dashboard.process_actions import terminate_process

logger = logging.getLogger(__name__)


class AutomaticResponseEngine:
    """Stops only USB executables that match the high-severity correlation rule.

    The action is disabled unless the operator selects Automated mode and
    explicitly enables both process termination and USB auto-termination.
    The shared guarded terminator revalidates PID, image path, and start time.
    """

    def handle_candidate(self, candidate):
        if candidate.get("reason") != "usb_executable_execution":
            return False
        if (SettingsManager.get("response_mode") or "Monitor Only").casefold() != "automated":
            return False
        if (SettingsManager.get("response_terminate_process") or "false").casefold() != "true":
            return False
        if (SettingsManager.get("response_auto_usb_termination") or "false").casefold() != "true":
            return False

        try:
            pid = int(candidate.get("pid"))
        except (TypeError, ValueError):
            logger.warning("Automatic response skipped: USB execution alert has no valid PID.")
            return False

        thread = threading.Thread(
            target=self._terminate_candidate,
            args=(pid, str(candidate.get("process_name") or ""), str(candidate.get("executable_path") or "")),
            name=f"HavocEDRResponse-{pid}",
            daemon=True,
        )
        thread.start()
        return True

    @staticmethod
    def _terminate_candidate(pid, expected_name, expected_path):
        try:
            process = psutil.Process(pid)
            started = datetime.fromtimestamp(process.create_time(), timezone.utc)
            stopped = terminate_process(
                pid,
                expected_name=expected_name,
                expected_path=expected_path,
                expected_start_time=started,
            )
            logger.warning("Automated USB execution response stopped process(es): %s", stopped)
        except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError, OSError, RuntimeError) as exc:
            logger.error("Automated USB execution response failed for PID %s: %s", pid, exc)


automatic_response_engine = AutomaticResponseEngine()
