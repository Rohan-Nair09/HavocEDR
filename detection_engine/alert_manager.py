import logging
import json
import time
from datetime import datetime, timezone
from monitoring.events import event_bus

logger = logging.getLogger(__name__)

class AlertManager:
    """
    Manages generation, deduplication, and suppression of alerts.
    """
    def __init__(self):
        # Cache of recently generated alerts to suppress duplicates
        # Key: alert signature (e.g., hash of title + main entities)
        # Value: timestamp
        self._alert_cache = {}
        self.SUPPRESSION_WINDOW = 300 # Suppress identical alerts for 5 minutes

    def _generate_signature(self, title: str, source_modules: str) -> str:
        """Create a basic signature to identify duplicate alerts."""
        return f"{title}::{source_modules}"

    def emit_alert(self, title: str, description: str, severity: str, 
                   source_modules: list, related_event_ids: list, threat_type: str):
        """
        Deduplicates and emits an alert through the EventBus.
        """
        now = time.time()
        mod_str = ",".join(sorted(source_modules))
        signature = self._generate_signature(title, mod_str)
        
        # Check suppression
        if signature in self._alert_cache:
            last_seen = self._alert_cache[signature]
            if now - last_seen < self.SUPPRESSION_WINDOW:
                logger.debug(f"AlertManager: Suppressed duplicate alert '{title}'")
                return # Suppress
                
        self._alert_cache[signature] = now

        alert_data = {
            "title": title,
            "description": description,
            "severity": severity,
            "source_modules": mod_str,
            "related_event_ids": json.dumps(related_event_ids),
            "threat_type": threat_type,
            "status": "Open",
            "timestamp": datetime.now(timezone.utc)
        }
        
        logger.warning(f"🚨 ALERT GENERATED [{severity}]: {title} ({threat_type})")
        event_bus.publish("alert_event", alert_data)

# Global instance for the detection engine
alert_manager = AlertManager()
