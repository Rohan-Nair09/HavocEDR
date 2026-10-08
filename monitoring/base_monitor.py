import threading
import time
import logging
from abc import ABC, abstractmethod
from typing import Any

from .events import event_bus

logger = logging.getLogger(__name__)

class BaseMonitor(ABC):
    """
    Abstract Base Class for all monitoring modules (Process, Service, Network, etc.)
    Provides common functionality for background threading, graceful shutdown,
    and event publishing.
    """
    def __init__(self, name: str, interval: float = 2.0):
        self.name = name
        self.interval = interval
        self._stop_event = threading.Event()
        self._thread = None
        self.event_bus = event_bus

    def start(self):
        """Starts the monitoring thread."""
        if self._thread is not None and self._thread.is_alive():
            logger.warning(f"{self.name} is already running.")
            return

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, name=f"{self.name}Thread", daemon=True)
        self._thread.start()
        logger.info(f"{self.name} started with interval {self.interval}s.")

    def stop(self):
        """Signals the monitoring thread to stop and waits for it."""
        if self._thread is not None and self._thread.is_alive():
            logger.info(f"Stopping {self.name}...")
            self._stop_event.set()
            self._thread.join(timeout=self.interval + 2.0)
            logger.info(f"{self.name} stopped.")

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def publish_event(self, event_type: str, data: Any):
        """Helper method to publish events."""
        self.event_bus.publish(event_type, data)

    def _run_loop(self):
        """The main loop for the thread."""
        self.on_start()
        while not self._stop_event.is_set():
            try:
                self.monitor()
            except Exception as e:
                logger.exception(f"Exception in {self.name} loop: {e}")
            
            # Wait for the interval, but allow quick exit if stop_event is set
            self._stop_event.wait(self.interval)
        
        self.on_stop()

    def on_start(self):
        """Hook called before the loop begins. Override in subclasses if needed."""
        pass

    def on_stop(self):
        """Hook called after the loop ends. Override in subclasses if needed."""
        pass

    @abstractmethod
    def monitor(self):
        """
        The core monitoring logic to be implemented by subclasses.
        Called repeatedly every `interval` seconds.
        """
        pass
