import unittest
from datetime import datetime, timezone
import time
from unittest.mock import patch

from detection_engine.correlation_engine import CorrelationEngine
from detection_engine.response_engine import AutomaticResponseEngine
from monitoring.events import event_bus


class FakeProcess:
    def name(self):
        return "sample.exe"

    def exe(self):
        return r"E:\sample.exe"

    def create_time(self):
        return 1000.0


class AutomaticResponseTests(unittest.TestCase):
    candidate = {
        "reason": "usb_executable_execution",
        "pid": 4567,
        "process_name": "sample.exe",
        "executable_path": r"E:\sample.exe",
    }

    def test_requires_automated_mode_and_both_explicit_opt_ins(self):
        engine = AutomaticResponseEngine()
        values = {
            "response_mode": "Automated",
            "response_terminate_process": "true",
            "response_auto_usb_termination": "true",
        }
        with patch("detection_engine.response_engine.SettingsManager.get", side_effect=lambda key: values[key]), patch(
            "detection_engine.response_engine.threading.Thread"
        ) as thread:
            self.assertTrue(engine.handle_candidate(self.candidate))
        thread.return_value.start.assert_called_once()

    def test_monitor_mode_does_not_schedule_response(self):
        engine = AutomaticResponseEngine()
        values = {
            "response_mode": "Monitor Only",
            "response_terminate_process": "true",
            "response_auto_usb_termination": "true",
        }
        with patch("detection_engine.response_engine.SettingsManager.get", side_effect=lambda key: values[key]), patch(
            "detection_engine.response_engine.threading.Thread"
        ) as thread:
            self.assertFalse(engine.handle_candidate(self.candidate))
        thread.assert_not_called()

    def test_only_usb_execution_candidates_are_actionable(self):
        engine = AutomaticResponseEngine()
        candidate = dict(self.candidate, reason="unrelated_alert")
        with patch("detection_engine.response_engine.SettingsManager.get") as get_setting, patch(
            "detection_engine.response_engine.threading.Thread"
        ) as thread:
            self.assertFalse(engine.handle_candidate(candidate))
        get_setting.assert_not_called()
        thread.assert_not_called()

    def test_execution_reuses_guarded_process_terminator(self):
        engine = AutomaticResponseEngine()
        with patch("detection_engine.response_engine.psutil.Process", return_value=FakeProcess()), patch(
            "detection_engine.response_engine.terminate_process", return_value=[4567]
        ) as terminate:
            engine._terminate_candidate(4567, "sample.exe", r"E:\sample.exe")
        terminate.assert_called_once_with(
            4567,
            expected_name="sample.exe",
            expected_path=r"E:\sample.exe",
            expected_start_time=datetime.fromtimestamp(1000.0, timezone.utc),
        )

    def test_usb_execution_correlation_publishes_response_candidate(self):
        engine = CorrelationEngine()
        now = time.time()
        engine.recent_usbs = [(now, "E:\\")]
        engine.usb_file_creations = [(now, r"E:\sample.exe".upper())]
        candidates = []
        callback = candidates.append
        event_bus.subscribe("response_candidate", callback)
        try:
            with patch("detection_engine.correlation_engine.alert_manager.emit_alert"):
                engine.process_process_event({
                    "action": "started",
                    "pid": 4567,
                    "name": "sample.exe",
                    "executable_path": r"E:\sample.exe",
                })
        finally:
            event_bus.unsubscribe("response_candidate", callback)

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["reason"], "usb_executable_execution")
        self.assertEqual(candidates[0]["pid"], 4567)


if __name__ == "__main__":
    unittest.main()
