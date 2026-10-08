from dashboard.table_utils import configure_full_width_table
import csv
from collections import Counter
from datetime import datetime, timedelta

from PySide6.QtCore import Qt, QTimer, QAbstractTableModel, QModelIndex
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QFrame,
    QTabWidget, QComboBox, QPushButton, QTableView, QHeaderView, QLineEdit,
    QFileDialog, QMessageBox,
)
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg
from matplotlib.figure import Figure

from dashboard.data_provider import DataProvider
from dashboard.theme import Theme
from config.settings import SettingsManager


def _chart_palette():
    colors = Theme.palette()
    return colors["panel"], colors["muted"], colors["border"], colors["text"]


class _RowsModel(QAbstractTableModel):
    def __init__(self, headers, rows=(), parent=None):
        super().__init__(parent)
        self.headers = headers
        self.rows = list(rows)

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.headers)

    def data(self, index, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and index.isValid():
            return str(self.rows[index.row()][index.column()])
        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.headers[section]
        return None

    def set_rows(self, rows):
        self.beginResetModel()
        self.rows = list(rows)
        self.endResetModel()


class _MetricCard(QFrame):
    def __init__(self, title, color):
        super().__init__()
        self.setProperty("class", "Card")
        layout = QVBoxLayout(self)
        self.caption = QLabel(title)
        self.caption.setStyleSheet(f"color:{Theme.palette()['muted']};font-size:12px")
        self.value = QLabel("—")
        self.value.setStyleSheet(f"color:{color};font-size:25px;font-weight:600")
        layout.addWidget(self.caption)
        layout.addWidget(self.value)


class _ChartPanel(QFrame):
    def __init__(self, title, parent=None):
        super().__init__(parent)
        self.setProperty("class", "Card")
        layout = QVBoxLayout(self)
        label = QLabel(title)
        label.setStyleSheet(f"font-size:14px;font-weight:600;color:{Theme.palette()['text']}")
        layout.addWidget(label)
        panel, muted, border, _ = _chart_palette()
        self.figure = Figure(facecolor=panel, tight_layout=True)
        self.canvas = FigureCanvasQTAgg(self.figure)
        self.axes = self.figure.add_subplot(111)
        self.axes.set_facecolor(panel)
        self.axes.tick_params(colors=muted, labelsize=8)
        for side in ("top", "right"):
            self.axes.spines[side].set_visible(False)
        for side in ("left", "bottom"):
            self.axes.spines[side].set_color(border)
        layout.addWidget(self.canvas)


class AnalyticsPage(QWidget):
    """Database-backed reporting and security analytics workspace."""
    def __init__(self, bridge=None, parent=None):
        super().__init__(parent)
        self.bridge = bridge
        self._rows = []
        self._export_rows = []
        self._all_export_rows = []
        self.setObjectName("AnalyticsPage")
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 18, 24, 18)
        root.setSpacing(12)

        heading = QHBoxLayout()
        title_box = QVBoxLayout()
        title = QLabel("Reports & Analytics")
        title.setStyleSheet(f"font-size:24px;font-weight:700;color:{Theme.palette()['text']}")
        subtitle = QLabel("Generate insights, analyze trends, and export security reports.")
        subtitle.setStyleSheet(f"color:{Theme.palette()['muted']}")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        heading.addLayout(title_box)
        heading.addStretch()
        self.period = QComboBox()
        self.period.addItems(["Last 7 days", "Last 30 days", "All time"])
        self.period.currentIndexChanged.connect(self.refresh_charts)
        heading.addWidget(self.period)
        self.btn_refresh = QPushButton("Refresh")
        self.btn_refresh.clicked.connect(self.refresh_charts)
        heading.addWidget(self.btn_refresh)
        self.btn_export = QPushButton("Export All Data")
        self.btn_export.clicked.connect(self.export_csv)
        heading.addWidget(self.btn_export)
        root.addLayout(heading)

        self.tabs = QTabWidget()
        for name in ("Overview", "Security Reports", "System Reports", "Compliance", "Custom Reports", "Scheduled Reports"):
            self.tabs.addTab(QWidget(), name)
        self.tabs.currentChanged.connect(self._tab_changed)
        root.addWidget(self.tabs)
        self.compliance_note = QLabel("Operational summary only; this is not a standards compliance attestation.")
        self.compliance_note.hide()
        root.addWidget(self.compliance_note)

        self.metrics = {}
        metric_layout = QGridLayout()
        for index, (key, title_text, color) in enumerate((
            ("events", "Total Events", "#2196F3"),
            ("threats", "Threats Detected", "#FF4D4D"),
            ("blocked", "Reports Generated", "#9C4DFF"),
            ("critical", "Critical Alerts", "#FF9800"),
            ("resolved", "Resolved Alerts", "#00E676"),
            ("logs", "Logs Generated", "#00E5D4"),
        )):
            card = _MetricCard(title_text, color)
            metric_layout.addWidget(card, 0, index)
            self.metrics[key] = card.value
        root.addLayout(metric_layout)

        self.charts = {}
        chart_layout = QGridLayout()
        for pos, (key, title_text) in enumerate((
            ("trend", "Events Over Time"), ("severity", "Threats by Severity"),
            ("types", "Top Threat Types"), ("categories", "Events by Category"),
            ("hosts", "Top Affected Hosts"), ("status", "Events by Status"),
        )):
            chart = _ChartPanel(title_text)
            self.charts[key] = chart
            chart_layout.addWidget(chart, pos // 3, pos % 3)
        root.addLayout(chart_layout, 1)

        self.table = QTableView()

        configure_full_width_table(self.table)
        self.table.setMaximumHeight(150)
        self.table.setAlternatingRowColors(True)
        self.table_model = _RowsModel(("Time", "Category", "Severity / State", "Event / Report", "Details"), parent=self)
        self.table.setModel(self.table_model)
        root.addWidget(self.table)
        self.btn_generate = QPushButton("Generate Security Report")
        self.btn_generate.clicked.connect(self.generate_report)
        root.addWidget(self.btn_generate, alignment=Qt.AlignRight)

        self.schedule_panel = QFrame()
        self.schedule_panel.setProperty("class", "Card")
        schedule_layout = QHBoxLayout(self.schedule_panel)
        self.schedule_frequency = QComboBox()
        self.schedule_frequency.addItems(["Disabled", "Daily", "Weekly"])
        self.schedule_directory = QLineEdit()
        self.schedule_directory.setPlaceholderText("Folder for scheduled CSV reports")
        self.btn_schedule = QPushButton("Save Schedule")
        self.btn_schedule.clicked.connect(self.save_schedule)
        self.schedule_status = QLabel("Scheduled exports run while HavocGuard is open.")
        schedule_layout.addWidget(QLabel("Frequency"))
        schedule_layout.addWidget(self.schedule_frequency)
        schedule_layout.addWidget(self.schedule_directory, 1)
        schedule_layout.addWidget(self.btn_schedule)
        schedule_layout.addWidget(self.schedule_status)
        root.addWidget(self.schedule_panel)
        self.schedule_panel.hide()
        self.schedule_timer = QTimer(self)
        self.schedule_timer.timeout.connect(self.generate_scheduled_report)
        self.schedule_frequency.setCurrentText(SettingsManager.get("report_schedule") or "Disabled")
        self.schedule_directory.setText(SettingsManager.get("report_directory") or "")
        self._start_saved_schedule()

        if bridge is not None:
            bridge.alert_received.connect(self.refresh_charts)
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.refresh_charts)
        self.refresh_timer.start(30000)
        self.refresh_charts()

    def _tab_changed(self, index):
        labels = {
            0: "Generate Overview Report", 1: "Generate Security Report",
            2: "Generate System Report", 3: "Export Compliance Summary",
            4: "Generate Custom Report", 5: "Generate Scheduled Report Now",
        }
        self.btn_generate.setText(labels.get(index, "Generate Report"))
        self.schedule_panel.setVisible(index == 5)
        self.compliance_note.setVisible(index == 3)
        self.refresh_charts()

    def _get_data(self):
        alerts, _ = DataProvider.fetch_data("alerts", limit=500, sort_col="timestamp", sort_desc=True)
        tables = ("processes", "services", "network", "file", "registry", "usb", "sysmon")
        events = {}
        for table in tables:
            rows, _ = DataProvider.fetch_data(table, limit=500, sort_col="timestamp", sort_desc=True)
            events[table] = rows
        horizon = {0: 7, 1: 30}.get(self.period.currentIndex())
        if horizon:
            cutoff = datetime.now() - timedelta(days=horizon)
            alerts = [row for row in alerts if self._as_datetime(row.get("timestamp")) >= cutoff]
            for name, rows in events.items():
                events[name] = [row for row in rows if self._as_datetime(row.get("timestamp")) >= cutoff]
        return alerts, events

    @staticmethod
    def _as_datetime(value):
        if isinstance(value, datetime):
            return value.replace(tzinfo=None)
        if value:
            try:
                return datetime.fromisoformat(str(value).replace("Z", "+00:00")).replace(tzinfo=None)
            except ValueError:
                pass
        return datetime.min

    def _get_data_for_export(self):
        """Fetch all stored rows so Export All Data is not limited by tab or period."""
        alerts, _ = DataProvider.fetch_data("alerts", limit=100000, sort_col="timestamp", sort_desc=True)
        events = {}
        for table in ("processes", "services", "network", "file", "registry", "usb", "sysmon"):
            events[table], _ = DataProvider.fetch_data(table, limit=100000, sort_col="timestamp", sort_desc=True)
        return alerts, events

    def refresh_charts(self, *_):
        alerts, event_groups = self._get_data()
        mode = self.tabs.currentIndex()
        if mode == 1:  # Security Reports
            event_groups = {}
        elif mode == 2:  # System Reports
            alerts = []
        elif mode in (3, 5):
            alerts, event_groups = [], {}
        kpis = DataProvider.get_kpis()
        self._rows = alerts
        all_events = [(key, row) for key, rows in event_groups.items() for row in rows]
        self._export_rows = self._rows_for_events(event_groups, alerts)
        self.metrics["events"].setText(f"{kpis.get('total_events', len(all_events)):,}")
        self.metrics["threats"].setText(f"{kpis.get('total_alerts', len(alerts)):,}")
        self.metrics["blocked"].setText(f"{kpis.get('reports', 0):,}")
        self.metrics["critical"].setText(f"{kpis.get('critical_alerts', 0):,}")
        self.metrics["resolved"].setText(f"{kpis.get('resolved_alerts', 0):,}")
        self.metrics["logs"].setText(f"{kpis.get('total_events', len(all_events)) + kpis.get('total_alerts', len(alerts)):,}")

        days = Counter()
        for _, row in all_events:
            stamp = self._as_datetime(row.get("timestamp"))
            if stamp != datetime.min:
                days[stamp.date()] += 1
        ax = self._clear("trend")
        if days:
            ordered = sorted(days.items())
            ax.plot([str(day) for day, _ in ordered], [count for _, count in ordered], color="#2196F3", marker="o")
            ax.tick_params(axis="x", rotation=25)
        else:
            self._empty(ax)
        self.charts["trend"].canvas.draw_idle()

        severity = Counter(str(row.get("severity") or "Unknown").title() for row in alerts)
        self._draw_donut("severity", severity, ["#FF4D4D", "#FF9800", "#FFC107", "#2196F3", "#6B7280"])
        types = Counter(str(row.get("threat_type") or row.get("title") or "Other") for row in alerts)
        self._draw_bars("types", types)
        categories = Counter(name.title() for name, rows in event_groups.items() for _ in rows)
        self._draw_donut("categories", categories, ["#2196F3", "#00E676", "#9C4DFF", "#FF9800", "#00E5D4", "#FF4D4D", "#6B7280"])
        host = Counter(str(row.get("computer") or row.get("hostname") or "This device") for _, row in all_events)
        self._draw_bars("hosts", host)
        status = Counter(str(row.get("status") or "Recorded").title() for _, row in all_events)
        self._draw_donut("status", status, ["#00E676", "#FF4D4D", "#FF9800", "#9C4DFF", "#2196F3"])
        if mode == 3:
            self._export_rows = self._compliance_summary(kpis)
            self.table_model.set_rows(self._table_rows(self._export_rows))
        elif mode == 5:
            reports, _ = DataProvider.fetch_data("reports", limit=100, sort_col="timestamp", sort_desc=True)
            self._export_rows = [
                {"timestamp": row.get("timestamp"), "category": row.get("report_type"),
                 "state": row.get("format"), "name": row.get("file_path"), "details": "Generated"}
                for row in reports
            ]
            self.table_model.set_rows(self._table_rows(self._export_rows))
        else:
            self.table_model.set_rows(self._table_rows(self._export_rows)[:100])

    @staticmethod
    def _rows_for_events(event_groups, alerts):
        rows = [dict(row, category=category, record_type="event")
                for category, items in event_groups.items() for row in items]
        rows.extend(dict(row, category="alert", record_type="alert") for row in alerts)
        return rows

    @staticmethod
    def _table_rows(rows):
        result = []
        for row in rows:
            if row.get("record_type") == "alert":
                name = row.get("title", "")
                details = row.get("threat_type", "")
                state = row.get("status", "")
                severity = row.get("severity", "")
            elif "details" in row and "state" in row:
                name = row.get("name", "")
                details = row.get("details", "")
                state = row.get("state", "")
                severity = state
            else:
                name = next((row.get(key) for key in (
                    "file_path", "name", "process_name", "remote_ip", "device_name", "key_path", "event_name"
                ) if row.get(key)), "")
                details = row.get("suspicion_reasons") or row.get("action") or row.get("status") or ""
                state = "Suspicious" if row.get("is_suspicious") else "Recorded"
                severity = "Review" if row.get("is_suspicious") else "Info"
            result.append((str(row.get("timestamp", ""))[:19], row.get("category", ""), severity, name, details or state))
        return result

    @staticmethod
    def _compliance_summary(kpis):
        now = datetime.now().isoformat(timespec="seconds")
        return [
            {"timestamp": now, "category": "Operational Summary", "state": "Available",
             "name": "Local database", "details": "SQLite schema initialized"},
            {"timestamp": now, "category": "Operational Summary", "state": str(kpis.get("total_events", 0)),
             "name": "Stored telemetry events", "details": "Local event records"},
            {"timestamp": now, "category": "Operational Summary", "state": str(kpis.get("open_alerts", 0)),
             "name": "Open alerts", "details": "Requires analyst review"},
            {"timestamp": now, "category": "Operational Summary", "state": str(kpis.get("resolved_alerts", 0)),
             "name": "Resolved alerts", "details": "Status stored locally"},
        ]

    def save_schedule(self):
        frequency = self.schedule_frequency.currentText()
        directory = self.schedule_directory.text().strip()
        if frequency != "Disabled" and not directory:
            self.schedule_status.setText("Choose a report folder before enabling the schedule.")
            return
        if not SettingsManager.set("report_schedule", frequency) or not SettingsManager.set("report_directory", directory):
            self.schedule_status.setText("Schedule could not be saved.")
            return
        self._start_saved_schedule()
        self.schedule_status.setText("Scheduled exports run while HavocGuard is open." if frequency != "Disabled" else "Scheduled exports disabled.")

    def _start_saved_schedule(self):
        self.schedule_timer.stop()
        frequency = (SettingsManager.get("report_schedule") or "Disabled").casefold()
        interval = {"daily": 24 * 60 * 60 * 1000, "weekly": 7 * 24 * 60 * 60 * 1000}.get(frequency)
        if interval:
            self.schedule_timer.start(interval)

    def generate_scheduled_report(self):
        directory = self.schedule_directory.text().strip() or SettingsManager.get("report_directory")
        if not directory:
            self.schedule_status.setText("Choose a report folder to generate scheduled reports.")
            return
        try:
            import os
            os.makedirs(directory, exist_ok=True)
            alerts, groups = self._get_data()
            rows = self._rows_for_events(groups, alerts)
            path = os.path.join(directory, f"havocguard_scheduled_{datetime.now():%Y%m%d_%H%M%S}.csv")
            if self._write_csv(path, rows, notify=False):
                DataProvider.record_report(path, "Scheduled security report", "CSV")
                self.schedule_status.setText(f"Latest report: {path}")
        except OSError as exc:
            self.schedule_status.setText(f"Scheduled report failed: {exc}")

    def _clear(self, key):
        chart = self.charts[key]
        chart.figure.clear()
        ax = chart.figure.add_subplot(111)
        panel, muted, border, _ = _chart_palette()
        chart.figure.set_facecolor(panel)
        ax.set_facecolor(panel)
        ax.tick_params(colors=muted, labelsize=8)
        for side in ("top", "right"):
            ax.spines[side].set_visible(False)
        for side in ("left", "bottom"):
            ax.spines[side].set_color(border)
        return ax

    @staticmethod
    def _empty(ax):
        ax.text(.5, .5, "No events in the selected period", color=_chart_palette()[1], ha="center", va="center", transform=ax.transAxes)
        ax.set_axis_off()

    def _draw_donut(self, key, counts, colors):
        ax = self._clear(key)
        if counts:
            labels, values = zip(*counts.most_common(7))
            ax.pie(values, labels=labels, colors=colors[:len(values)], startangle=90,
                   wedgeprops={"width": .38, "edgecolor": "#111827"},
                   textprops={"color": _chart_palette()[3], "fontsize": 8})
        else:
            self._empty(ax)
        self.charts[key].canvas.draw_idle()

    def _draw_bars(self, key, counts):
        ax = self._clear(key)
        if counts:
            pairs = counts.most_common(7)
            labels, values = zip(*pairs)
            ax.barh(list(labels)[::-1], list(values)[::-1], color="#00E5D4")
            ax.tick_params(axis="y", labelsize=8)
        else:
            self._empty(ax)
        self.charts[key].canvas.draw_idle()

    def generate_report(self):
        mode = self.tabs.currentIndex()
        if mode == 5:
            self.generate_scheduled_report()
            return
        default = f"havocguard_{datetime.now():%Y%m%d_%H%M%S}.csv"
        report_types = {0: "Overview", 1: "Security", 2: "System", 3: "Compliance", 4: "Custom"}
        report_type = report_types.get(mode, "Security")
        path, _ = QFileDialog.getSaveFileName(self, f"Save {report_type} Report", default, "CSV Files (*.csv)")
        if path and self._write_csv(path, self._export_rows):
            DataProvider.record_report(path, report_type, "CSV")

    def export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export Security Data", "havocguard_export.csv", "CSV Files (*.csv)")
        if not path:
            return
        all_alerts, all_event_groups = self._get_data_for_export()
        self._all_export_rows = self._rows_for_events(all_event_groups, all_alerts)
        if self._write_csv(path, self._all_export_rows):
            DataProvider.record_report(path, "Full data export", "CSV")

    def _write_csv(self, path, rows, notify=True):
        try:
            columns = list(dict.fromkeys(key for row in rows for key in row)) if rows else ["message"]
            with open(path, "w", newline="", encoding="utf-8") as output:
                writer = csv.DictWriter(output, fieldnames=columns)
                writer.writeheader()
                writer.writerows(rows)
            if notify:
                QMessageBox.information(self, "Report Saved", f"Exported {len(rows)} records.")
            return True
        except OSError as exc:
            if notify:
                QMessageBox.critical(self, "Export Failed", str(exc))
            return False
