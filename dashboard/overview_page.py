from dashboard.table_utils import configure_full_width_table
from collections import Counter
from datetime import datetime, timedelta
import os

import psutil
from PySide6.QtCore import Qt, QTimer, QAbstractTableModel, QModelIndex
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QFrame,
    QPushButton, QTableView, QHeaderView, QProgressBar,
)
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg
from matplotlib.figure import Figure

from dashboard.data_provider import DataProvider
from dashboard.theme import Theme


class _DashboardTableModel(QAbstractTableModel):
    HEADERS = ("Time", "Severity", "Alert", "Type", "Status")
    FIELDS = ("timestamp", "severity", "title", "threat_type", "status")

    def __init__(self, parent=None):
        super().__init__(parent)
        self.rows = []

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.HEADERS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.HEADERS[section]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        row = self.rows[index.row()]
        field = self.FIELDS[index.column()]
        if role == Qt.DisplayRole:
            value = row.get(field, "")
            return str(value)[:19] if field == "timestamp" else str(value or "")
        if role == Qt.ForegroundRole and field == "severity":
            return Theme.get_severity_color(row.get("severity", ""))
        return None

    def set_rows(self, rows):
        self.beginResetModel()
        self.rows = list(rows)
        self.endResetModel()


class _Metric(QFrame):
    def __init__(self, title, accent, icon):
        super().__init__()
        self.setProperty("class", "Card")
        self.setMinimumHeight(100)
        layout = QVBoxLayout(self)
        label = QLabel(icon + "  " + title)
        label.setStyleSheet(f"color:{accent};font-size:12px;font-weight:600")
        self.value = QLabel("—")
        self.value.setStyleSheet("font-size:27px;font-weight:600;color:#fff")
        self.detail = QLabel("")
        self.detail.setStyleSheet(f"color:{accent};font-size:11px")
        layout.addWidget(label)
        layout.addWidget(self.value)
        layout.addWidget(self.detail)


class OverviewPage(QWidget):
    """Live security dashboard populated from the local telemetry database."""
    def __init__(self, ui_event_bridge=None, parent=None):
        super().__init__(parent)
        self.ui_event_bridge = ui_event_bridge
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(12)

        top = QHBoxLayout()
        title_box = QVBoxLayout()
        title = QLabel("Dashboard")
        title.setStyleSheet("font-size:24px;font-weight:700;color:#fff")
        subtitle = QLabel("Real-time overview of your endpoint security")
        subtitle.setStyleSheet("color:#9ca3af")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        top.addLayout(title_box)
        top.addStretch()
        self.updated = QLabel("")
        self.updated.setStyleSheet("color:#9ca3af")
        top.addWidget(self.updated)
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self._refresh_data)
        top.addWidget(refresh)
        root.addLayout(top)

        self.cards = {}
        card_row = QHBoxLayout()
        for key, label, accent, icon in (
            ("risk", "Threat Score", "#FF4D4D", "◈"),
            ("active", "Active Threats", "#FF4D4D", "✹"),
            ("resolved", "Resolved Alerts", "#00E676", "✓"),
            ("endpoints", "Monitored Endpoints", "#2196F3", "▣"),
            ("health", "System Health", "#9C4DFF", "⌁"),
        ):
            card = _Metric(label, accent, icon)
            self.cards[key] = card
            card_row.addWidget(card)
        root.addLayout(card_row)

        middle = QHBoxLayout()
        self.activity = self._chart("Threat Activity (Live)")
        self.distribution = self._chart("Threat Distribution")
        alerts_panel = QFrame()
        alerts_panel.setProperty("class", "Card")
        alerts_layout = QVBoxLayout(alerts_panel)
        alerts_head = QHBoxLayout()
        alerts_head.addWidget(QLabel("Recent Alerts"))
        alerts_head.addStretch()
        self.btn_view_alerts = QPushButton("View All")
        self.btn_view_alerts.setFlat(True)
        alerts_head.addWidget(self.btn_view_alerts)
        alerts_layout.addLayout(alerts_head)
        self.alert_model = _DashboardTableModel(self)
        self.alert_table = QTableView()
        configure_full_width_table(self.alert_table)
        self.alert_table.setModel(self.alert_model)
        self.alert_table.setSelectionBehavior(QTableView.SelectRows)
        self.alert_table.setEditTriggers(QTableView.NoEditTriggers)
        self.alert_table.verticalHeader().setVisible(False)
        alerts_layout.addWidget(self.alert_table)
        middle.addWidget(self.activity.panel, 5)
        middle.addWidget(self.distribution.panel, 4)
        middle.addWidget(alerts_panel, 5)
        root.addLayout(middle, 2)

        bottom = QHBoxLayout()
        process_panel = QFrame()
        process_panel.setProperty("class", "Card")
        proc_layout = QVBoxLayout(process_panel)
        proc_layout.addWidget(QLabel("Top Resource Consuming Processes"))
        self.process_model = _DashboardTableModel(self)
        self.process_model.HEADERS = ("Process", "CPU", "Memory", "PID", "Risk")
        self.process_model.FIELDS = ("name", "cpu_percent", "ram_usage_mb", "pid", "is_suspicious")
        self.process_table = QTableView()
        configure_full_width_table(self.process_table)
        self.process_table.setModel(self.process_model)
        self.process_table.setEditTriggers(QTableView.NoEditTriggers)
        self.process_table.verticalHeader().setVisible(False)
        proc_layout.addWidget(self.process_table)
        bottom.addWidget(process_panel, 3)

        health_panel = QFrame()
        health_panel.setProperty("class", "Card")
        health_layout = QVBoxLayout(health_panel)
        health_layout.addWidget(QLabel("System Overview"))
        self.health_bars = {}
        for key, caption, color in (("cpu", "CPU Usage", "#00E5D4"), ("memory", "Memory Usage", "#9C4DFF"), ("disk", "Disk Usage", "#00E676")):
            row = QHBoxLayout()
            row.addWidget(QLabel(caption))
            bar = QProgressBar()
            bar.setRange(0, 100)
            bar.setTextVisible(True)
            bar.setStyleSheet(f"QProgressBar{{border:0;background:#1f2937;height:12px;text-align:center}} QProgressBar::chunk{{background:{color};border-radius:4px}}")
            row.addWidget(bar)
            health_layout.addLayout(row)
            self.health_bars[key] = bar
        self.health_note = QLabel("Telemetry is stored locally in the HavocGuard database.")
        self.health_note.setStyleSheet("color:#9ca3af")
        health_layout.addWidget(self.health_note)
        bottom.addWidget(health_panel, 2)
        root.addLayout(bottom, 1)

        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self._refresh_data)
        # The overview redraws two Matplotlib charts and queries telemetry from
        # a growing local database. Keep updates responsive without doing that
        # relatively expensive work every few seconds.
        self.refresh_timer.start(30000)
        if self.ui_event_bridge is not None:
            self.ui_event_bridge.alert_received.connect(self._on_new_alert)
        # Let Qt paint the main window first; the first database/chart refresh
        # can be noticeable on endpoints with a large telemetry history.
        QTimer.singleShot(200, self._refresh_data)

    class _Plot:
        def __init__(self, title, parent):
            self.panel = QFrame()
            self.panel.setProperty("class", "Card")
            layout = QVBoxLayout(self.panel)
            title_label = QLabel(title)
            title_label.setStyleSheet("font-size:14px;font-weight:600;color:#fff")
            layout.addWidget(title_label)
            self.figure = Figure(facecolor="#111827", tight_layout=True)
            self.canvas = FigureCanvasQTAgg(self.figure)
            self.axes = self.figure.add_subplot(111)
            self.canvas.setParent(parent)
            layout.addWidget(self.canvas)

    def _chart(self, title):
        return self._Plot(title, self)

    def _refresh_data(self):
        alerts, _ = DataProvider.fetch_data(
            "alerts", limit=500, sort_col="id", sort_desc=True, include_total=False
        )
        processes, _ = DataProvider.fetch_data(
            "processes", limit=100, sort_col="id", sort_desc=True, include_total=False
        )
        # Read the latest process samples by indexed primary key, then rank
        # this small in-memory window. Sorting the entire history by CPU was
        # forcing SQLite to scan and sort the multi-hundred-megabyte table.
        processes.sort(key=lambda row: float(row.get("cpu_percent") or 0), reverse=True)
        active = [row for row in alerts if str(row.get("status", "Open")).casefold() not in ("resolved", "false positive")]
        critical = [row for row in active if str(row.get("severity", "")).casefold() == "critical"]
        score = min(100, len(critical) * 20 + len(active) * 4)
        self.cards["risk"].value.setText(str(score))
        self.cards["risk"].detail.setText("HIGH RISK" if score >= 60 else "ELEVATED" if score >= 30 else "LOW RISK")
        self.cards["active"].value.setText(str(len(active)))
        self.cards["active"].detail.setText(f"{len(critical)} critical")
        self.cards["resolved"].value.setText(str(sum(str(row.get("status", "")).casefold() == "resolved" for row in alerts)))
        self.cards["resolved"].detail.setText("Resolved alerts")
        self.cards["endpoints"].value.setText("1")
        self.cards["endpoints"].detail.setText("This device")
        try:
            cpu = psutil.cpu_percent()
            memory = psutil.virtual_memory().percent
            disk = psutil.disk_usage(os.path.abspath(os.sep)).percent
            for key, value in (("cpu", cpu), ("memory", memory), ("disk", disk)):
                self.health_bars[key].setValue(round(value))
                self.health_bars[key].setFormat(f"{value:.0f}%")
            self.cards["health"].value.setText("Good" if score < 60 else "Review")
            self.cards["health"].detail.setText("All systems normal" if score < 60 else "Alerts need attention")
        except (OSError, RuntimeError):
            self.cards["health"].value.setText("Unknown")
        self.alert_model.set_rows(alerts[:6])
        self.process_model.set_rows(processes[:6])
        self._draw_activity(alerts)
        self._draw_distribution(alerts)
        self.updated.setText("Updated " + datetime.now().strftime("%H:%M:%S"))

    def _draw_activity(self, alerts):
        ax = self.activity.axes
        ax.clear()
        ax.set_facecolor("#111827")
        recent = []
        for row in alerts:
            stamp = row.get("timestamp")
            if isinstance(stamp, datetime) and stamp >= datetime.now() - timedelta(hours=24):
                recent.append(stamp.replace(minute=stamp.minute // 2 * 2, second=0, microsecond=0))
        counts = Counter(recent)
        if counts:
            points = sorted(counts.items())
            ax.plot([x.strftime("%H:%M") for x, _ in points], [n for _, n in points], color="#FF4D4D", marker="o", linewidth=1.5)
            ax.fill_between(range(len(points)), [n for _, n in points], color="#FF4D4D", alpha=.12)
        else:
            ax.text(.5, .5, "No recent alerts", color="#9ca3af", ha="center", va="center", transform=ax.transAxes)
        self._style_axes(ax)
        ax.tick_params(axis="x", rotation=20, labelsize=8)
        self.activity.canvas.draw_idle()

    def _draw_distribution(self, alerts):
        ax = self.distribution.axes
        ax.clear()
        ax.set_facecolor("#111827")
        counts = Counter(str(row.get("severity") or "Unknown").title() for row in alerts)
        if counts:
            labels, values = zip(*counts.most_common())
            colors = [Theme.SEV_CRITICAL, Theme.SEV_HIGH, Theme.SEV_MEDIUM, Theme.SEV_LOW, "#6B7280"][:len(values)]
            ax.pie(values, labels=labels, colors=colors, startangle=90,
                   wedgeprops={"width": .38, "edgecolor": "#111827"},
                   textprops={"color": "#e0e6ed", "fontsize": 8})
            ax.text(0, 0, f"{len(alerts)}\nTotal", color="white", ha="center", va="center")
        else:
            ax.text(.5, .5, "No alerts recorded", color="#9ca3af", ha="center", va="center", transform=ax.transAxes)
        ax.set_aspect("equal")
        self.distribution.canvas.draw_idle()

    @staticmethod
    def _style_axes(ax):
        ax.tick_params(colors="#9ca3af", labelsize=8)
        ax.grid(axis="y", color="#374151", alpha=.5)
        for side in ("top", "right"):
            ax.spines[side].set_visible(False)
        for side in ("left", "bottom"):
            ax.spines[side].set_color("#374151")

    def _on_new_alert(self, _data):
        self._refresh_data()
