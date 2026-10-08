import logging
import threading
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import win32evtlog
import win32event

from .base_monitor import BaseMonitor
from config.settings import SettingsManager
from utils.process_utils import verify_file_signature

logger = logging.getLogger(__name__)

# Living off the land binaries
LOL_BINS = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"}

class SysmonCollector(BaseMonitor):
    """
    Event-driven Sysmon Collector using EvtSubscribe.
    Gracefully disables itself if Sysmon is not installed.
    """

    def __init__(self):
        super().__init__("SysmonCollector", interval=15.0) # Interval used for heartbeat
        self.channel = "Microsoft-Windows-Sysmon/Operational"
        self._subscription = None
        self._is_enabled = False

    def _check_sysmon_installed(self) -> bool:
        """Check if the Sysmon event log channel exists."""
        try:
            # Try to query the channel metadata
            handle = win32evtlog.EvtOpenChannelConfig(self.channel)
            if handle:
                return True
        except Exception:
            return False
        return False

    def _assess_suspicion(self, event_id: int, data: dict) -> tuple[bool, str]:
        """Apply threat logic to Sysmon events."""
        is_suspicious = False
        reasons = []

        if event_id == 1: # Process Creation
            image = data.get("Image", "").lower()
            original_file_name = data.get("OriginalFileName", "").lower()
            
            # Check for LOLBins running from unusual paths
            img_name = image.split("\\")[-1] if "\\" in image else image
            if img_name in LOL_BINS or original_file_name in LOL_BINS:
                if not (image.startswith("c:\\windows\\system32\\") or image.startswith("c:\\windows\\syswow64\\")):
                    is_suspicious = True
                    reasons.append(f"LOLBin executed from unusual path: {image}")

        elif event_id == 3: # Network Connection
            image = data.get("Image", "").lower()
            dest_ip = data.get("DestinationIp", "")
            img_name = image.split("\\")[-1] if "\\" in image else image
            
            # LOLBin network connection
            if img_name in LOL_BINS:
                # Basic public IP check (Sysmon includes IsLocal property in newer versions, but we can check IP)
                if not dest_ip.startswith(("10.", "192.168.", "172.", "127.")):
                    is_suspicious = True
                    reasons.append(f"Network connection to Public IP from LOLBin: {image}")

        elif event_id == 6: # Driver Loaded (Phase 9B, but good to have logic ready)
            signature_status = data.get("SignatureStatus", "")
            if signature_status != "Valid":
                is_suspicious = True
                reasons.append(f"Unsigned or invalid driver loaded: {data.get('ImageLoaded', '')}")

        elif event_id == 13: # Registry Event
            target_obj = data.get("TargetObject", "").lower()
            if "currentversion\\run" in target_obj or "currentversion\\runonce" in target_obj or "startup" in target_obj:
                is_suspicious = True
                reasons.append(f"Registry persistence mechanism modified: {target_obj}")

        return is_suspicious, ", ".join(reasons)

    def _event_callback(self, action, context, event_handle):
        """Callback for EvtSubscribe."""
        if action == win32evtlog.EvtSubscribeActionDeliver:
            try:
                xml_content = win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml)
                self._process_event_xml(xml_content)
            except Exception as e:
                logger.error(f"Error rendering Sysmon event: {e}")

    def _process_event_xml(self, xml_string: str):
        """Parse Sysmon XML and publish event."""
        try:
            root = ET.fromstring(xml_string)
            # Find namespace
            ns = root.tag.split('}')[0].strip('{')
            namespace = {'ns': ns} if ns else {}

            # Extract basic info
            system = root.find('ns:System', namespace) if namespace else root.find('System')
            event_id = int(system.find('ns:EventID', namespace).text if namespace else system.find('EventID').text)
            
            # Map Event IDs to names
            event_names = {
                1: "Process Creation",
                3: "Network Connection",
                7: "Image Loaded",
                11: "File Created",
                13: "Registry Value Set"
            }
            event_name = event_names.get(event_id, f"Event {event_id}")

            computer = system.find('ns:Computer', namespace).text if namespace else system.find('Computer').text

            # Extract EventData
            event_data_node = root.find('ns:EventData', namespace) if namespace else root.find('EventData')
            event_data_dict = {}
            if event_data_node is not None:
                for data_node in event_data_node:
                    name = data_node.get("Name")
                    value = data_node.text or ""
                    if name:
                        event_data_dict[name] = value

            process_guid = event_data_dict.get("ProcessGuid", "")
            process_id = int(event_data_dict.get("ProcessId", 0))
            image = event_data_dict.get("Image", "")
            user = event_data_dict.get("User", "")

            is_suspicious, reasons = self._assess_suspicion(event_id, event_data_dict)

            sysmon_event = {
                "event_id": event_id,
                "event_name": event_name,
                "process_guid": process_guid,
                "process_id": process_id,
                "image": image,
                "user": user,
                "computer": computer,
                "event_data": json.dumps(event_data_dict),
                "is_suspicious": is_suspicious,
                "suspicion_reasons": reasons,
                "timestamp": datetime.now(timezone.utc),
            }

            self.publish_event("sysmon_event", sysmon_event)

        except Exception as e:
            logger.error(f"Error parsing Sysmon XML: {e}")

    def on_start(self):
        """Check for Sysmon and subscribe if available."""
        if not self._check_sysmon_installed():
            logger.warning("Sysmon is not installed or accessible. SysmonCollector will disable itself gracefully.")
            self._is_enabled = False
            return

        self._is_enabled = True
        logger.info("Sysmon detected. Initializing subscription...")

        # Subscribe to Event IDs 1, 3, 7, 11, 13
        query = "*[System[(EventID=1 or EventID=3 or EventID=7 or EventID=11 or EventID=13)]]"
        
        try:
            self._subscription = win32evtlog.EvtSubscribe(
                self.channel,
                win32evtlog.EvtSubscribeToFutureEvents,
                Query=query,
                Callback=self._event_callback
            )
            logger.info("SysmonCollector subscribed successfully.")
        except Exception as e:
            logger.error(f"Failed to subscribe to Sysmon events: {e}")
            self._is_enabled = False

    def on_stop(self):
        """Clean up the subscription."""
        if self._subscription:
            # win32evtlog subscriptions don't have a direct close method like handles,
            # they are tied to the lifetime of the handle object
            self._subscription = None
            logger.info("SysmonCollector subscription closed.")

    def monitor(self):
        """
        Since EvtSubscribe uses a callback thread from the Windows Event Log service,
        this monitor loop just acts as a heartbeat to keep the BaseMonitor alive
        and allow graceful shutdown via stop_event.
        """
        if not self._is_enabled:
            # If not enabled, we just sleep. The thread will eventually close when stopped.
            pass
