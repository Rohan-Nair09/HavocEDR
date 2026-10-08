import logging
import threading
import queue
import time
from typing import Dict, Any, Type
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

from database.connection import SessionLocal
from database.models import ProcessEvent, ServiceEvent, NetworkConnection, RegistryEvent, FileEvent, USBEvent, SysmonEvent, Alert
from .events import event_bus

logger = logging.getLogger(__name__)

class DatabaseWriter:
    """
    Centralized persistence layer for the monitoring engine.
    Uses an internal queue and background thread to write events asynchronously,
    ensuring monitoring threads are never blocked.
    """
    def __init__(self, batch_size: int = 50, batch_timeout: float = 1.0):
        self.batch_size = batch_size
        self.batch_timeout = batch_timeout
        self.queue = queue.Queue(maxsize=10000)
        self._stop_event = threading.Event()
        self._thread = None
        
        # Map event types to SQLAlchemy models
        self.event_model_map: Dict[str, Type] = {
            "process_event": ProcessEvent,
            "service_event": ServiceEvent,
            "network_event": NetworkConnection,
            "registry_event": RegistryEvent,
            "file_event": FileEvent,
            "usb_event": USBEvent,
            "sysmon_event": SysmonEvent,
            "alert_event": Alert,
        }
        self._handlers = {}

    def start(self):
        """Starts the background DB writer thread and subscribes to events."""
        if self._thread is not None and self._thread.is_alive():
            logger.warning("DatabaseWriter is already running.")
            return

        self._stop_event.clear()
        
        # Subscribe to all known events
        for event_type in self.event_model_map.keys():
            handler = self._create_handler(event_type)
            self._handlers[event_type] = handler
            event_bus.subscribe(event_type, handler)

        self._thread = threading.Thread(target=self._run_loop, name="DatabaseWriterThread", daemon=True)
        self._thread.start()
        logger.info("DatabaseWriter started.")

    def stop(self):
        """Stops the background thread gracefully."""
        if self._thread is not None and self._thread.is_alive():
            logger.info("Stopping DatabaseWriter...")
            
            # Unsubscribe from events
            for event_type, handler in self._handlers.items():
                event_bus.unsubscribe(event_type, handler)
            self._handlers.clear()
                
            self._stop_event.set()
            self._thread.join(timeout=self.batch_timeout + 2.0)
            logger.info("DatabaseWriter stopped.")

    def _create_handler(self, event_type: str):
        """Creates an event handler for a specific event type."""
        def handler(data: Dict[str, Any]):
            try:
                # Put in queue, drop if queue is full to prevent memory explosion
                self.queue.put_nowait((event_type, data))
            except queue.Full:
                logger.warning("DatabaseWriter queue is full. Dropping event.")
        return handler

    def _run_loop(self):
        """Main loop that retrieves items from the queue and writes them in batches."""
        batch = []
        db: Session = None
        
        while not self._stop_event.is_set() or not self.queue.empty():
            try:
                # Wait for an item, but allow timeout to process partial batches
                item = self.queue.get(timeout=self.batch_timeout)
                batch.append(item)
            except queue.Empty:
                pass # Timeout reached, process the batch if any
                
            if len(batch) >= self.batch_size or (not batch == [] and (self.queue.empty() or self._stop_event.is_set())):
                try:
                    db = SessionLocal()
                    objects_to_add = []
                    
                    for event_type, data in batch:
                        model_class = self.event_model_map.get(event_type)
                        if model_class:
                            objects_to_add.append(model_class(**data))
                    
                    if objects_to_add:
                        # Batch insert using bulk_save_objects for efficiency
                        db.bulk_save_objects(objects_to_add)
                        db.commit()
                        logger.debug(f"Successfully inserted {len(objects_to_add)} events into database.")
                        
                except SQLAlchemyError as e:
                    logger.error(f"Database error while saving batch: {e}")
                    if db:
                        db.rollback()
                except Exception as e:
                    logger.error(f"Unexpected error in DatabaseWriter: {e}")
                    if db:
                        db.rollback()
                finally:
                    if db:
                        db.close()
                
                # Clear batch
                for _ in range(len(batch)):
                    self.queue.task_done()
                batch.clear()
