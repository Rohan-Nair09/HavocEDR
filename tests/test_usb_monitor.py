import unittest

from monitoring.events import event_bus
from monitoring.usb_monitor import USBMonitor


class FakeDisk:
    PNPDeviceID = r"USB\VID_1234&PID_ABCD\SERIAL123"
    Caption = "Validation USB"
    Model = "Validation USB"


class FakeWmiConnection:
    def Win32_DiskDrive(self, **_kwargs):
        return [FakeDisk()]


class USBMonitorLogicTests(unittest.TestCase):
    def test_insert_and_removal_events_match_the_same_drive(self):
        monitor = USBMonitor(interval=0.1)
        events = []
        callback = events.append
        event_bus.subscribe("usb_event", callback)
        monitor._get_current_removable_drives = lambda: {"E:\\"}
        try:
            monitor._handle_wmi_creation(FakeWmiConnection())
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["action"], "inserted")
            self.assertEqual(events[0]["drive_letter"], "E:\\")
            self.assertIn(FakeDisk.PNPDeviceID, monitor._known_devices)

            monitor._get_current_removable_drives = lambda: set()
            monitor.monitor()
            self.assertEqual(len(events), 2)
            self.assertEqual(events[1]["action"], "removed")
            self.assertEqual(events[1]["device_id"], FakeDisk.PNPDeviceID)
            self.assertFalse(monitor._known_devices)
        finally:
            event_bus.unsubscribe("usb_event", callback)

    def test_drive_polling_detects_insert_and_remove_without_wmi(self):
        monitor = USBMonitor(interval=0.1)
        events = []
        callback = events.append
        event_bus.subscribe("usb_event", callback)
        drives = set()
        monitor._get_current_removable_drives = lambda: set(drives)
        try:
            drives.add("F:\\")
            monitor.monitor()
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["action"], "inserted")
            self.assertEqual(events[0]["drive_letter"], "F:\\")
            self.assertIn("DRIVE:F:\\", monitor._known_devices)
            self.assertEqual(events[0]["device_id"], "")

            drives.clear()
            monitor.monitor()
            self.assertEqual(len(events), 2)
            self.assertEqual(events[1]["action"], "removed")
            self.assertEqual(events[1]["drive_letter"], "F:\\")
            self.assertEqual(events[1]["device_id"], "")
            self.assertFalse(monitor._known_devices)
        finally:
            event_bus.unsubscribe("usb_event", callback)

    def test_removal_matches_device_reported_before_drive_mount(self):
        monitor = USBMonitor(interval=0.1)
        events = []
        callback = events.append
        event_bus.subscribe("usb_event", callback)
        drives = set()
        monitor._get_current_removable_drives = lambda: set(drives)
        try:
            # WMI can deliver device identity before the volume appears.
            monitor._handle_wmi_creation(FakeWmiConnection())
            self.assertEqual(events[0]["drive_letter"], "")

            drives.add("E:\\")
            monitor.monitor()
            self.assertEqual(len(events), 1)

            drives.clear()
            monitor.monitor()
            self.assertEqual(events[1]["action"], "removed")
            self.assertEqual(events[1]["device_id"], FakeDisk.PNPDeviceID)
            self.assertEqual(events[1]["drive_letter"], "E:\\")
        finally:
            event_bus.unsubscribe("usb_event", callback)


if __name__ == "__main__":
    unittest.main()
