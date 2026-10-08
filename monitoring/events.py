import logging
import threading
from typing import Callable, Dict, List, Any

logger = logging.getLogger(__name__)

class EventBus:
    """
    A simple thread-safe Event Bus implementing the Observer pattern.
    Allows decoupling of the monitoring engine from the GUI and Database.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(EventBus, cls).__new__(cls)
                cls._instance._subscribers = {}
                cls._instance._sub_lock = threading.Lock()
        return cls._instance

    def subscribe(self, event_type: str, callback: Callable[[Any], None]) -> None:
        """Subscribe a callback to a specific event type."""
        with self._sub_lock:
            if event_type not in self._subscribers:
                self._subscribers[event_type] = []
            if callback not in self._subscribers[event_type]:
                self._subscribers[event_type].append(callback)
                logger.debug(f"Subscribed {callback.__name__} to event: {event_type}")

    def unsubscribe(self, event_type: str, callback: Callable[[Any], None]) -> None:
        """Unsubscribe a callback from a specific event type."""
        with self._sub_lock:
            if event_type in self._subscribers:
                if callback in self._subscribers[event_type]:
                    self._subscribers[event_type].remove(callback)
                    logger.debug(f"Unsubscribed {callback.__name__} from event: {event_type}")

    def publish(self, event_type: str, data: Any) -> None:
        """Publish an event to all subscribers synchronously (but subscribers can dispatch async if needed)."""
        with self._sub_lock:
            callbacks = self._subscribers.get(event_type, []).copy()
        
        for callback in callbacks:
            try:
                callback(data)
            except Exception as e:
                logger.error(f"Error in subscriber {callback.__name__} for event {event_type}: {e}")

# Global instance
event_bus = EventBus()
