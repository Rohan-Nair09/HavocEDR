import logging
from monitoring.events import event_bus
from monitoring.base_monitor import BaseMonitor
from .rule_engine import RuleEngine
from .correlation_engine import CorrelationEngine
from config.settings import SettingsManager
from .response_engine import automatic_response_engine

logger = logging.getLogger(__name__)

class ThreatEngine(BaseMonitor):
    """
    Subscribes to all telemetry events from the EventBus, routes them through
    the Rule Engine and Correlation Engine, and emits alerts.
    Runs as a background thread to allow periodic cleanup of state.
    """
    def __init__(self, interval: float = 10.0):
        super().__init__("ThreatEngine", interval)
        self.rule_engine = RuleEngine()
        self.correlation_engine = CorrelationEngine()

    @staticmethod
    def _enabled(key, default=True):
        value = SettingsManager.get(key)
        if not value:
            return default
        return str(value).strip().casefold() in {"1", "true", "yes", "on", "enabled"}

    def on_start(self):
        """Subscribe to all relevant EventBus channels."""
        event_bus.subscribe("registry_event", self.handle_registry)
        event_bus.subscribe("file_event", self.handle_file)
        event_bus.subscribe("network_event", self.handle_network)
        event_bus.subscribe("service_event", self.handle_service)
        event_bus.subscribe("usb_event", self.handle_usb)
        event_bus.subscribe("process_event", self.handle_process)
        event_bus.subscribe("process_start_event", self.handle_process_start)
        event_bus.subscribe("response_candidate", automatic_response_engine.handle_candidate)
        # Note: Sysmon events can also be routed here, but we'll focus on native monitors for the baseline rules

    def on_stop(self):
        """Unsubscribe on shutdown."""
        event_bus.unsubscribe("registry_event", self.handle_registry)
        event_bus.unsubscribe("file_event", self.handle_file)
        event_bus.unsubscribe("network_event", self.handle_network)
        event_bus.unsubscribe("service_event", self.handle_service)
        event_bus.unsubscribe("usb_event", self.handle_usb)
        event_bus.unsubscribe("process_event", self.handle_process)
        event_bus.unsubscribe("process_start_event", self.handle_process_start)
        event_bus.unsubscribe("response_candidate", automatic_response_engine.handle_candidate)

    # --- Event Handlers ---

    def handle_registry(self, data):
        if self._enabled("behavior_detection_enabled"):
            self.rule_engine.evaluate_registry_event(data)

    def handle_file(self, data):
        if self._enabled("behavior_detection_enabled"):
            self.rule_engine.evaluate_file_event(data)
        if self._enabled("correlation_enabled"):
            self.correlation_engine.process_file_event(data)

    def handle_network(self, data):
        if self._enabled("behavior_detection_enabled"):
            self.rule_engine.evaluate_network_event(data)

    def handle_service(self, data):
        if self._enabled("behavior_detection_enabled"):
            self.rule_engine.evaluate_service_event(data)

    def handle_usb(self, data):
        if self._enabled("correlation_enabled"):
            self.correlation_engine.process_usb_event(data)

    def handle_process(self, data):
        # Snapshots feed storage and ML; transitions arrive on a separate
        # channel so correlation fields cannot violate the database schema.
        return

    def handle_process_start(self, data):
        if self._enabled("correlation_enabled"):
            self.correlation_engine.process_process_event(data)

    def monitor(self):
        """Periodic cleanup task for stateful correlation engine."""
        self.correlation_engine.cleanup()
