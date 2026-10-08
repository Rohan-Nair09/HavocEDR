import logging
from PySide6.QtCore import QObject, Signal
from monitoring.events import event_bus

logger = logging.getLogger(__name__)

class UIEventBridge(QObject):
    """
    Acts as a thread-safe bridge between the backend EventBus (which fires
    callbacks on various monitoring threads) and the Qt UI (which must be
    updated on the main thread).
    """
    # Define Qt Signals for the events we want to route to the UI
    alert_received = Signal(dict)
    process_received = Signal(dict)
    network_received = Signal(dict)
    registry_received = Signal(dict)
    file_received = Signal(dict)
    usb_received = Signal(dict)
    sysmon_received = Signal(dict)
    service_received = Signal(dict)

    def __init__(self):
        super().__init__()
        
    def start_listening(self):
        """Subscribe to the backend EventBus."""
        event_bus.subscribe("alert_event", self._on_alert)
        event_bus.subscribe("process_event", self._on_process)
        event_bus.subscribe("network_event", self._on_network)
        event_bus.subscribe("registry_event", self._on_registry)
        event_bus.subscribe("file_event", self._on_file)
        event_bus.subscribe("usb_event", self._on_usb)
        event_bus.subscribe("sysmon_event", self._on_sysmon)
        event_bus.subscribe("service_event", self._on_service)
        logger.info("UIEventBridge subscribed to backend EventBus.")

    def stop_listening(self):
        """Unsubscribe to prevent memory leaks on shutdown."""
        event_bus.unsubscribe("alert_event", self._on_alert)
        event_bus.unsubscribe("process_event", self._on_process)
        event_bus.unsubscribe("network_event", self._on_network)
        event_bus.unsubscribe("registry_event", self._on_registry)
        event_bus.unsubscribe("file_event", self._on_file)
        event_bus.unsubscribe("usb_event", self._on_usb)
        event_bus.unsubscribe("sysmon_event", self._on_sysmon)
        event_bus.unsubscribe("service_event", self._on_service)

    # --- Callbacks that run on backend threads ---
    # We simply emit the Qt Signal, which Qt safely queues to the main thread.

    def _on_alert(self, data: dict):
        self.alert_received.emit(data)

    def _on_process(self, data: dict):
        self.process_received.emit(data)

    def _on_network(self, data: dict):
        self.network_received.emit(data)

    def _on_registry(self, data: dict):
        self.registry_received.emit(data)

    def _on_file(self, data: dict):
        self.file_received.emit(data)

    def _on_usb(self, data: dict):
        self.usb_received.emit(data)

    def _on_sysmon(self, data: dict):
        self.sysmon_received.emit(data)

    def _on_service(self, data: dict):
        self.service_received.emit(data)

# Global instance to be used by the main window
ui_event_bridge = UIEventBridge()
