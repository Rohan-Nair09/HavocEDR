"""Background process scoring and alerting with a per-endpoint Isolation Forest."""

import logging
import queue
import threading
import time

from database.connection import SessionLocal
from database.models import ProcessEvent
from monitoring.base_monitor import BaseMonitor
from monitoring.events import event_bus
from ai.isolation_forest import ProcessIsolationForest
from .alert_manager import alert_manager

logger = logging.getLogger(__name__)


class MLAnomalyMonitor(BaseMonitor):
    def __init__(self):
        super().__init__("MLAnomalyMonitor", 1.0)
        self.detector = ProcessIsolationForest()
        self._events = queue.Queue(maxsize=5000)
        self._trainer = None
        self._last_training_attempt = 0.0

    def on_start(self):
        event_bus.subscribe("process_event", self._on_process)
        self._trainer = threading.Thread(target=self._train_from_history, name="ProcessModelTrainer", daemon=True)
        self._trainer.start()

    def on_stop(self):
        event_bus.unsubscribe("process_event", self._on_process)
        if self._trainer and self._trainer.is_alive():
            self._trainer.join(timeout=2.0)

    def _on_process(self, data):
        try:
            self._events.put_nowait(dict(data))
        except queue.Full:
            logger.warning("ML process event queue is full; dropping an event")

    def _train_from_history(self):
        while not self._stop_event.is_set():
            db = SessionLocal()
            try:
                rows = db.query(ProcessEvent).filter(ProcessEvent.is_suspicious.is_(False)).order_by(ProcessEvent.timestamp.desc()).limit(5000).all()
                data = [{column.name: getattr(row, column.name) for column in ProcessEvent.__table__.columns} for row in rows]
            except Exception:
                logger.exception("Could not load process history for model training")
                data = []
            finally:
                db.close()
            self._last_training_attempt = time.monotonic()
            if self.detector.train(data):
                return
            # On a new installation, gather a wider event history before retrying.
            self._stop_event.wait(60.0)

    def _maybe_train(self):
        status = self.detector.status()
        if status["state"] == "trained" or time.monotonic() - self._last_training_attempt < 60:
            return
        if self._trainer is None or not self._trainer.is_alive():
            self._trainer = threading.Thread(target=self._train_from_history, name="ProcessModelTrainer", daemon=True)
            self._trainer.start()

    def _score_event(self, data):
        if data.get("is_suspicious"):
            return
        result = self.detector.score(data)
        if result is None:
            return
        process_name = str(data.get("name") or "unknown process")
        score = result["decision_score"]
        alert_manager.emit_alert(
            title=f"Unusual process behavior: {process_name}",
            description=(
                "The endpoint's Isolation Forest model found this process profile outside its learned baseline. "
                "An anomaly is not proof of malicious activity; verify the process and its context.\n"
                f"Process: {process_name}\nPID: {data.get('pid', 'unknown')}\nPath: {data.get('path') or 'unavailable'}\n"
                f"Parent: {data.get('parent_name') or 'unknown'}\nCPU: {data.get('cpu_percent', 0)}%\n"
                f"Memory: {data.get('ram_usage_mb', 0)} MB\nIsolation Forest decision score: {score:.4f} (negative indicates an outlier)\n"
                f"Baseline profiles: {result['training_profiles']}"
            ),
            severity="Low",
            source_modules=["Isolation Forest"],
            related_event_ids=[],
            threat_type="Behavioral Anomaly",
        )

    def monitor(self):
        self._maybe_train()
        for _ in range(250):
            try:
                data = self._events.get_nowait()
            except queue.Empty:
                break
            try:
                self._score_event(data)
            except Exception:
                logger.exception("ML anomaly scoring failed for a process observation")
            finally:
                self._events.task_done()


process_ml_monitor = MLAnomalyMonitor()
