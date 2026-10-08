import os
import sys
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QMessageBox, QPushButton

from dashboard.pages.processes_page import ProcessesPage
from dashboard.pages.settings_page import SettingsPage


class ResponseUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication(sys.argv)

    def test_terminate_button_invokes_guarded_action_for_selected_row(self):
        page = ProcessesPage()
        page.process_model.set_data([{
            "pid": 8123,
            "name": "DemoApp.exe",
            "path": r"C:\Program Files\Demo\DemoApp.exe",
        }])
        page.table.selectRow(0)
        button = page.findChild(QPushButton, "terminate_process_button")
        self.assertIsNotNone(button)
        settings = {
            "response_mode": "Ask Before Responding",
            "response_terminate_process": "true",
        }
        with patch("dashboard.pages.processes_page.SettingsManager.get", side_effect=lambda key: settings.get(key, "")), patch(
            "dashboard.pages.processes_page.QMessageBox.question", return_value=QMessageBox.Yes
        ), patch("dashboard.pages.processes_page.QMessageBox.information"), patch(
            "dashboard.pages.processes_page.terminate_process", return_value=[8123]
        ) as response:
            button.click()
        response.assert_called_once_with(
            8123,
            expected_name="DemoApp.exe",
            expected_path=r"C:\Program Files\Demo\DemoApp.exe",
            expected_start_time=None,
            include_children=False,
        )
        page.close()

    def test_quarantine_and_network_response_controls_are_available_but_opt_in(self):
        with patch("dashboard.pages.settings_page.SettingsManager.get", return_value=""):
            settings = SettingsPage()
        self.assertTrue(settings.controls["response_quarantine_file"].isEnabled())
        self.assertFalse(settings.controls["response_quarantine_file"].isChecked())
        self.assertTrue(settings.controls["response_block_network"].isEnabled())
        self.assertFalse(settings.controls["response_block_network"].isChecked())
        response_mode = settings.controls["response_mode"]
        self.assertEqual(
            [response_mode.itemText(i) for i in range(response_mode.count())],
            ["Ask Before Responding", "Monitor Only", "Automated"],
        )
        settings.close()


if __name__ == "__main__":
    unittest.main()
