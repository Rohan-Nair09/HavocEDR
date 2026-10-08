import sys
import logging
import threading
from PySide6.QtCore import QObject, QTimer, Signal
from PySide6.QtWidgets import QApplication, QMessageBox

from database.init_db import init_db
from dashboard.main_window import MainWindow
from dashboard.event_bridge import ui_event_bridge
from config.settings import SettingsManager

logger = logging.getLogger(__name__)


def start_backend():
    """Initialize storage and start event processing before telemetry collection."""
    if not init_db():
        raise RuntimeError("Database initialization failed; HavocGuard cannot start safely.")

    # These imports include heavier endpoint and ML dependencies. Load them in
    # the backend startup worker so the Qt window can appear first.
    from monitoring.db_writer import DatabaseWriter
    from detection_engine.threat_engine import ThreatEngine
    from monitoring.process_monitor import ProcessMonitor
    from monitoring.service_monitor import ServiceMonitor
    from monitoring.network_monitor import NetworkMonitor
    from monitoring.registry_monitor import RegistryMonitor
    from monitoring.fim_monitor import FIMMonitor
    from monitoring.usb_monitor import USBMonitor
    from monitoring.sysmon_collector import SysmonCollector

    def load_ml_monitor():
        from detection_engine.ml_monitor import process_ml_monitor
        return process_ml_monitor

    writer = DatabaseWriter()
    writer.start()
    ui_event_bridge.start_listening()

    monitors = [ThreatEngine()]
    configured_monitors = (
        ("process_monitor_enabled", ProcessMonitor),
        ("service_monitor_enabled", ServiceMonitor),
        ("network_monitor_enabled", NetworkMonitor),
        ("registry_monitor_enabled", RegistryMonitor),
        ("fim_monitor_enabled", FIMMonitor),
        ("usb_monitor_enabled", USBMonitor),
        ("sysmon_monitor_enabled", SysmonCollector),
        ("ml_detection_enabled", load_ml_monitor),
    )
    for setting, monitor_type in configured_monitors:
        if (SettingsManager.get(setting) or "true").casefold() == "true":
            monitors.append(monitor_type())
    for monitor in monitors:
        try:
            monitor.start()
        except Exception:
            logger.exception("Could not start %s", monitor.name)
    return writer, monitors


def stop_backend(writer, monitors):
    for monitor in reversed(monitors):
        try:
            monitor.stop()
        except Exception:
            logger.exception("Could not stop %s cleanly", monitor.name)
    ui_event_bridge.stop_listening()
    writer.stop()

class _BackendSignals(QObject):
    ready = Signal(object, object)
    failed = Signal(str)


def main():
    app = QApplication(sys.argv)
    logging.basicConfig(level=logging.INFO)

    # Show the dashboard before loading collectors, WMI support, or ML
    # dependencies. Startup happens in a worker so it cannot hold the UI open.
    window = MainWindow(ui_event_bridge=ui_event_bridge)
    window.show()
    signals = _BackendSignals()
    backend_state = {"writer": None, "monitors": []}

    def on_backend_ready(writer, monitors):
        backend_state["writer"] = writer
        backend_state["monitors"] = monitors
        page = window.pages.currentWidget()
        refresh = getattr(page, "_refresh_data", None)
        if callable(refresh):
            refresh()
        logger.info("Backend startup completed.")

    def on_backend_failed(message):
        logger.error("Backend startup failed: %s", message)
        QMessageBox.critical(window, "HavocEDR startup failed", message)

    def start_backend_worker():
        try:
            writer, monitors = start_backend()
        except Exception as exc:
            signals.failed.emit(str(exc))
        else:
            signals.ready.emit(writer, monitors)

    signals.ready.connect(on_backend_ready)
    signals.failed.connect(on_backend_failed)
    backend_thread = threading.Thread(
        target=start_backend_worker, name="HavocEDRBackendStartup", daemon=True
    )
    QTimer.singleShot(100, backend_thread.start)

    def shutdown_backend():
        if backend_thread.is_alive():
            backend_thread.join(timeout=2.0)
        writer = backend_state["writer"]
        if writer is not None:
            stop_backend(writer, backend_state["monitors"])

    app.aboutToQuit.connect(shutdown_backend)
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
