"""Headless integration check for the current HavocGuard desktop dashboard."""
import os
import sys
import traceback

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def run():
    failures = []

    def check(label, action):
        try:
            result = action()
            print(f"PASS  {label}" + (f": {result}" if result is not None else ""))
        except Exception as exc:
            failures.append(label)
            print(f"FAIL  {label}: {exc}")
            traceback.print_exc()

    def initialize_database():
        from database.init_db import init_db
        if not init_db():
            raise RuntimeError("Database initialization reported failure")
        return "schema and migrations ready"

    check("database initialization", initialize_database)

    from PySide6.QtWidgets import QApplication, QTableWidget
    from dashboard.data_provider import DataProvider
    from dashboard.event_bridge import ui_event_bridge
    from dashboard.main_window import MainWindow

    app = QApplication.instance() or QApplication(sys.argv)
    window = None

    def construct_window():
        nonlocal window
        window = MainWindow(ui_event_bridge=ui_event_bridge)
        app.processEvents()
        return f"{window.pages.count()} pages registered"

    check("main window construction", construct_window)

    if window is not None:
        def navigation():
            for page_id, button in window.sidebar.buttons.items():
                button.click()
                app.processEvents()
                if window.pages.currentWidget() is not window.page_instances[page_id]:
                    raise AssertionError(f"Navigation did not open {page_id}")
            expected = {
                "dashboard", "processes", "services", "network", "file_integrity",
                "registry", "usb_devices", "threats_and_alerts", "ai_security_analyst",
                "reports_and_analytics", "settings",
            }
            if not expected.issubset(window.page_instances):
                raise AssertionError("One or more required dashboard pages are missing")
            return f"{len(window.sidebar.buttons)} sidebar destinations opened"

        check("sidebar navigation", navigation)

        def analytics_refresh():
            page = window.page_instances["reports_and_analytics"]
            page.refresh_charts()
            if page.tabs.count() != 6:
                raise AssertionError("Reports & Analytics tabs are incomplete")
            return "six report views refreshed"

        check("analytics refresh", analytics_refresh)

        def settings_page():
            page = window.page_instances["settings"]
            page.load_values()
            if page.tabs.count() != 8:
                raise AssertionError("Settings tabs are incomplete")
            return "eight settings sections loaded"

        check("settings load", settings_page)

        def model_view_architecture():
            legacy = window.findChildren(QTableWidget)
            if legacy:
                raise AssertionError(f"Found {len(legacy)} QTableWidget instances")
            return "model-based tables in use"

        check("table architecture", model_view_architecture)

        def event_bridge():
            page = window.page_instances["processes"]
            before = page.model.rowCount()
            ui_event_bridge.process_received.emit({
                "pid": 987654, "name": "validator-event.exe", "path": "C:/validator-event.exe",
                "command_line": "validator-event.exe", "user": "validator", "cpu_percent": 0.1,
                "ram_usage_mb": 1.0, "digital_signature": "Unknown", "is_suspicious": False,
                "timestamp": "2026-10-04T00:00:00",
            })
            app.processEvents()
            if page.model.rowCount() != before + 1:
                raise AssertionError("Process table did not receive the bridge event")
            return "synthetic process reached the live table model"

        check("UI event bridge", event_bridge)

    def data_provider_queries():
        counts = {}
        for table in ("alerts", "processes", "services", "network", "file", "registry", "usb", "sysmon"):
            rows, total = DataProvider.fetch_data(table, limit=5)
            counts[table] = f"{len(rows)}/{total}"
        return ", ".join(f"{key} {value}" for key, value in counts.items())

    check("data provider queries", data_provider_queries)
    app.processEvents()
    app.quit()
    print("\nVALIDATION " + ("PASSED" if not failures else f"FAILED ({', '.join(failures)})"))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(run())
