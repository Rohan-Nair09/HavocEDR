import unittest
import subprocess
import sys
import time
from datetime import datetime, timezone
from unittest.mock import patch

import psutil

from dashboard.process_actions import terminate_process


class FakeProcess:
    def __init__(self, pid, name="DemoApp.exe", exe=r"C:\Program Files\Demo\DemoApp.exe", start_time=1000.0):
        self.pid = pid
        self._name = name
        self._exe = exe
        self._start_time = start_time
        self.alive = True
        self.terminated = False
        self.killed = False
        self._children = []

    def name(self):
        return self._name

    def exe(self):
        return self._exe

    def create_time(self):
        return self._start_time

    def children(self, recursive=False):
        return self._children

    def terminate(self):
        self.terminated = True
        self.alive = False

    def kill(self):
        self.killed = True
        self.alive = False

    def is_running(self):
        return self.alive


class ProcessActionTests(unittest.TestCase):
    def test_terminates_the_selected_process_after_snapshot_match(self):
        process = FakeProcess(8123)
        with patch("dashboard.process_actions.psutil.Process", return_value=process), patch(
            "dashboard.process_actions.psutil.wait_procs", return_value=([], [])
        ):
            stopped = terminate_process(
                8123,
                expected_name="DemoApp.exe",
                expected_path=process.exe(),
                expected_start_time=datetime.fromtimestamp(1000.0, timezone.utc),
            )
        self.assertEqual(stopped, [8123])
        self.assertTrue(process.terminated)

    def test_refuses_pid_reused_by_a_different_process(self):
        process = FakeProcess(8123)
        with patch("dashboard.process_actions.psutil.Process", return_value=process):
            with self.assertRaisesRegex(ValueError, "different process"):
                terminate_process(8123, expected_name="OldApp.exe")
        self.assertFalse(process.terminated)

    def test_refuses_protected_system_pid(self):
        process = FakeProcess(4, name="System", exe=r"C:\Windows\System32\ntoskrnl.exe")
        with patch("dashboard.process_actions.psutil.Process", return_value=process):
            with self.assertRaisesRegex(ValueError, "protected system"):
                terminate_process(4)
        self.assertFalse(process.terminated)

    def test_process_tree_stops_children_and_parent(self):
        root = FakeProcess(8123)
        child = FakeProcess(8124)
        root._children = [child]
        with patch("dashboard.process_actions.psutil.Process", return_value=root), patch(
            "dashboard.process_actions.psutil.wait_procs", return_value=([], [])
        ):
            stopped = terminate_process(8123, expected_name=root.name(), include_children=True)
        self.assertEqual(stopped, [8124, 8123])
        self.assertTrue(child.terminated)
        self.assertTrue(root.terminated)

    def test_refuses_pid_reused_by_a_new_instance_of_the_same_process(self):
        process = FakeProcess(8123, start_time=2000.0)
        with patch("dashboard.process_actions.psutil.Process", return_value=process):
            with self.assertRaisesRegex(ValueError, "reused"):
                terminate_process(
                    8123,
                    expected_name=process.name(),
                    expected_path=process.exe(),
                    expected_start_time=datetime.fromtimestamp(1000.0, timezone.utc),
                )
        self.assertFalse(process.terminated)

    def test_terminates_only_a_temporary_python_worker(self):
        worker = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            deadline = time.monotonic() + 5
            while worker.poll() is None and time.monotonic() < deadline:
                try:
                    process = psutil.Process(worker.pid)
                    name, path, started = process.name(), process.exe(), process.create_time()
                    break
                except psutil.NoSuchProcess:
                    time.sleep(0.05)
            else:
                self.fail("temporary worker did not start")
            stopped = terminate_process(
                worker.pid,
                expected_name=name,
                expected_path=path,
                expected_start_time=datetime.fromtimestamp(started, timezone.utc),
            )
            self.assertEqual(stopped, [worker.pid])
            self.assertIsNotNone(worker.poll())
        finally:
            if worker.poll() is None:
                worker.kill()
                worker.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
