import logging
import gc
import threading
import string
import os
import re
from datetime import datetime, timezone

from .base_monitor import BaseMonitor
from config.settings import SettingsManager

logger = logging.getLogger(__name__)


class USBMonitor(BaseMonitor):
    """
    Event-driven USB Monitor using WMI notifications.
    Detects USB storage device insertion and removal, captures device metadata,
    and tracks previously seen devices for suspicion analysis.
    """

    def __init__(self, interval: float = None):
        if interval is None:
            interval = SettingsManager.get_float("usb_monitor_interval", default=5.0)
        super().__init__("USBMonitor", interval)

        # Track known devices: { device_id: { metadata } }
        self._known_devices: dict[str, dict] = {}
        # Track previously seen devices across sessions (serial numbers)
        self._seen_serials: set[str] = set()
        # Track currently mounted drive letters for removal detection
        self._last_drives: set[str] = set()
        self._devices_lock = threading.RLock()

        # WMI watcher threads
        self._wmi_thread = None
        self._wmi_stop = threading.Event()

    def _get_current_removable_drives(self) -> set[str]:
        """Get the set of currently mounted removable drive letters."""
        drives = set()
        bitmask = __import__('ctypes').windll.kernel32.GetLogicalDrives()
        for i, letter in enumerate(string.ascii_uppercase):
            if bitmask & (1 << i):
                drive = f"{letter}:\\"
                try:
                    drive_type = __import__('ctypes').windll.kernel32.GetDriveTypeW(drive)
                    if drive_type == 2:  # DRIVE_REMOVABLE
                        drives.add(drive)
                except Exception:
                    pass
        return drives

    def _parse_device_id(self, device_id: str) -> dict:
        """Extract vendor ID, product ID, and serial number from a PnP device ID."""
        vendor_id = ""
        product_id = ""
        serial_number = ""

        if not device_id:
            return {"vendor_id": vendor_id, "product_id": product_id, "serial_number": serial_number}

        # USB device IDs typically look like: USB\VID_xxxx&PID_xxxx\serial
        vid_match = re.search(r'VID_([0-9A-Fa-f]{4})', device_id)
        pid_match = re.search(r'PID_([0-9A-Fa-f]{4})', device_id)

        if vid_match:
            vendor_id = vid_match.group(1)
        if pid_match:
            product_id = pid_match.group(1)

        # Serial number is typically the last segment after the last backslash
        parts = device_id.split("\\")
        if len(parts) >= 3:
            serial_number = parts[-1]

        return {"vendor_id": vendor_id, "product_id": product_id, "serial_number": serial_number}

    def _find_drive_letter_for_device(self, new_drives: set[str]) -> str:
        """Find the drive letter associated with a newly inserted device."""
        added = new_drives - self._last_drives
        if added:
            return added.pop()
        return ""

    def _assess_suspicion(self, device_id: str, serial_number: str,
                          previously_seen: bool) -> tuple[bool, str]:
        """Evaluate whether the USB event is suspicious."""
        is_suspicious = False
        reasons = []

        if not previously_seen:
            is_suspicious = True
            reasons.append("First-time USB device connected")

        if not serial_number or serial_number.strip() == "":
            is_suspicious = True
            reasons.append("USB device has no serial number")

        return is_suspicious, ", ".join(reasons) if reasons else ""

    def on_start(self):
        """Capture the initial set of removable drives and start WMI watcher."""
        self._last_drives = self._get_current_removable_drives()
        logger.info(f"Initial removable drives: {self._last_drives or 'None'}")

        # Start WMI event watcher in a separate thread (requires COM init)
        self._wmi_stop.clear()
        self._wmi_thread = threading.Thread(
            target=self._wmi_watcher_loop,
            name="USBWMIWatcher",
            daemon=True
        )
        self._wmi_thread.start()

    def _wmi_watcher_loop(self):
        """WMI event subscription loop — runs in its own thread with COM initialized."""
        pythoncom = None
        wmi_connection = None
        watcher = None
        event = None
        try:
            # The wmi package connects to Windows Management at import time.
            # Keep this optional dependency out of the app's import path.
            import pythoncom as pythoncom_module
            pythoncom = pythoncom_module
            pythoncom.CoInitialize()
            import wmi

            wmi_connection = wmi.WMI()

            # Watch for USB storage device creation events
            watcher = wmi_connection.Win32_USBControllerDevice.watch_for(
                notification_type="Creation",
                delay_secs=1
            )

            while not self._wmi_stop.is_set():
                try:
                    # Non-blocking check with timeout
                    event = watcher(timeout_ms=2000)
                    if event:
                        self._handle_wmi_creation(wmi_connection)
                except wmi.x_wmi_timed_out:
                    continue
                except Exception as e:
                    if not self._wmi_stop.is_set():
                        logger.error(f"WMI watcher error: {e}")
                    break

        except Exception as e:
            logger.error(f"Failed to start WMI USB watcher: {e}")
        finally:
            # Release COM-backed WMI proxies before uninitializing this thread's
            # COM apartment. Leaving them alive until after CoUninitialize can
            # emit pywin32 IUnknown release warnings during normal shutdown.
            if watcher is not None:
                try:
                    watcher.wmi_event.Cancel()
                except Exception:
                    pass
                try:
                    watcher.wmi_event = None
                except Exception:
                    pass
            if wmi_connection is not None:
                try:
                    wmi_connection._classes_map.clear()
                    wmi_connection._namespace = None
                except Exception:
                    pass
            event = None
            watcher = None
            wmi_connection = None
            gc.collect()
            if pythoncom is not None:
                pythoncom.CoUninitialize()

    def _handle_wmi_creation(self, wmi_conn):
        """Handle a WMI USB creation event by querying current USB devices."""
        try:
            current_drives = self._get_current_removable_drives()
            with self._devices_lock:
                newly_added = sorted(current_drives - self._last_drives)
                self._last_drives = current_drives

            # Query USB disk drives for metadata
            for disk in wmi_conn.Win32_DiskDrive(InterfaceType="USB"):
                device_id = disk.PNPDeviceID or ""
                device_name = disk.Caption or disk.Model or "Unknown USB Device"

                drive_letter = newly_added.pop(0) if newly_added else ""
                if not drive_letter:
                    # The polling fallback may have seen the new volume first.
                    with self._devices_lock:
                        provisional = [
                            info.get("drive_letter", "")
                            for key, info in self._known_devices.items()
                            if key.startswith("DRIVE:")
                            and info.get("drive_letter") in current_drives
                        ]
                    if len(provisional) == 1:
                        drive_letter = provisional[0]

                parsed = self._parse_device_id(device_id)
                serial_number = parsed["serial_number"]

                previously_seen = serial_number in self._seen_serials
                if serial_number:
                    self._seen_serials.add(serial_number)

                is_suspicious, reasons = self._assess_suspicion(
                    device_id, serial_number, previously_seen
                )

                event_data = {
                    "device_name": device_name,
                    "device_id": device_id,
                    "vendor_id": parsed["vendor_id"],
                    "product_id": parsed["product_id"],
                    "serial_number": serial_number,
                    "drive_letter": drive_letter,
                    "action": "inserted",
                    "previously_seen": previously_seen,
                    "is_suspicious": is_suspicious,
                    "suspicion_reasons": reasons,
                    "timestamp": datetime.now(timezone.utc),
                }

                with self._devices_lock:
                    provisional_key = f"DRIVE:{drive_letter}" if drive_letter else ""
                    provisional = self._known_devices.pop(provisional_key, None) if provisional_key else None
                    already_known = device_id in self._known_devices
                    if not already_known:
                        self._known_devices[device_id or provisional_key] = {
                            "device_name": device_name,
                            "device_id": device_id,
                            "drive_letter": drive_letter or (provisional or {}).get("drive_letter", ""),
                        }
                    should_publish = provisional is None and not already_known

                if should_publish:
                    self.publish_event("usb_event", event_data)
                    logger.info(f"USB Inserted: {device_name} (Drive: {drive_letter or 'N/A'})")

        except Exception as e:
            logger.error(f"Error handling USB creation: {e}")

    def stop(self):
        """Signal the WMI watcher to stop before calling parent stop."""
        self._wmi_stop.set()
        super().stop()

    def on_stop(self):
        """Cleanup WMI watcher thread."""
        if self._wmi_thread and self._wmi_thread.is_alive():
            self._wmi_thread.join(timeout=5.0)

    def monitor(self):
        """
        Poll mounted removable drives as a fallback for both insertions and
        removals. This keeps basic USB telemetry available when Windows denies
        the optional WMI notification subscription.
        """
        current_drives = self._get_current_removable_drives()
        with self._devices_lock:
            added_drives = current_drives - self._last_drives
            removed_drives = self._last_drives - current_drives
            self._last_drives = current_drives

        # Polling can identify the drive letter even when WMI cannot provide
        # the device's PnP ID or serial number.
        for drive in added_drives:
            key = f"DRIVE:{drive}"
            with self._devices_lock:
                unidentified = [
                    info for info in self._known_devices.values()
                    if info.get("device_id") and not info.get("drive_letter")
                ]
                if len(unidentified) == 1:
                    unidentified[0]["drive_letter"] = drive
                    continue
                if any(info.get("drive_letter") == drive for info in self._known_devices.values()):
                    continue
                self._known_devices[key] = {
                    "device_name": f"Removable storage ({drive})",
                    "device_id": "",
                    "drive_letter": drive,
                }
            parsed = self._parse_device_id("")
            suspicious, reasons = self._assess_suspicion("", "", False)
            self.publish_event("usb_event", {
                "device_name": f"Removable storage ({drive})",
                "device_id": "",
                "vendor_id": parsed["vendor_id"],
                "product_id": parsed["product_id"],
                "serial_number": parsed["serial_number"],
                "drive_letter": drive,
                "action": "inserted",
                "previously_seen": False,
                "is_suspicious": suspicious,
                "suspicion_reasons": reasons,
                "timestamp": datetime.now(timezone.utc),
            })
            logger.info("Removable storage inserted (Drive: %s; WMI identity unavailable)", drive)

        if removed_drives:
            # A removable drive was removed
            for drive in removed_drives:
                # Try to find which device was on this drive
                device_name = f"Unknown USB Device (was {drive})"
                device_id = ""

                # Match the removed drive to its insertion record instead of
                # attributing the event to an arbitrary connected device.
                with self._devices_lock:
                    to_remove = [
                        did for did, info in self._known_devices.items()
                        if info.get("drive_letter") == drive
                    ]
                    if not to_remove:
                        # WMI can report the PnP device before Windows mounts
                        # its volume. If there is exactly one unmatched USB
                        # device, attach this removal to that identity.
                        unidentified = [
                            did for did, info in self._known_devices.items()
                            if info.get("device_id") and not info.get("drive_letter")
                        ]
                        if len(unidentified) == 1:
                            to_remove = unidentified
                            self._known_devices[to_remove[0]]["drive_letter"] = drive
                    if to_remove:
                        device_id = self._known_devices[to_remove[0]].get("device_id", "")
                        device_name = self._known_devices[to_remove[0]].get("device_name", device_name)

                    for did in to_remove:
                        del self._known_devices[did]

                parsed = self._parse_device_id(device_id)

                event_data = {
                    "device_name": device_name,
                    "device_id": device_id,
                    "vendor_id": parsed["vendor_id"],
                    "product_id": parsed["product_id"],
                    "serial_number": parsed["serial_number"],
                    "drive_letter": drive,
                    "action": "removed",
                    "previously_seen": True,
                    "is_suspicious": False,
                    "suspicion_reasons": "",
                    "timestamp": datetime.now(timezone.utc),
                }

                self.publish_event("usb_event", event_data)
                logger.info(f"USB Removed: {device_name} (Drive: {drive})")
