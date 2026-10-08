import platform
from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTabWidget, QPushButton,
    QFrame, QScrollArea, QFormLayout, QComboBox, QCheckBox, QSpinBox,
    QDoubleSpinBox, QMessageBox,
)
import qtawesome as qta

from config.settings import SettingsManager
from dashboard.theme import Theme


class ToggleSwitch(QCheckBox):
    """Accessible checkbox styled as a compact on/off switch."""
    def __init__(self, checked=False, parent=None):
        super().__init__(parent)
        self.setChecked(checked)
        self.setText("")
        self.setFixedWidth(44)
        self.setStyleSheet("QCheckBox::indicator{width:36px;height:18px;border-radius:9px;background:#374151;} QCheckBox::indicator:checked{background:#00b8aa;} QCheckBox::indicator:unchecked{background:#374151;}")


class SettingsPage(QWidget):
    """Persistent preferences and monitoring configuration."""
    TABS = ("General", "Monitoring", "Detection", "Response", "Notifications", "Integrations", "Advanced", "About")

    def __init__(self, bridge=None, parent=None):
        super().__init__(parent)
        self.bridge = bridge
        self.controls = {}
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 20, 28, 20)
        root.setSpacing(14)

        header = QHBoxLayout()
        title_box = QVBoxLayout()
        title = QLabel("Settings")
        title.setStyleSheet("font-size:24px;font-weight:700;color:#fff")
        subtitle = QLabel("Configure application preferences, security policies, and system behavior.")
        subtitle.setStyleSheet("color:#9ca3af")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        header.addLayout(title_box)
        header.addStretch()
        root.addLayout(header)

        body = QHBoxLayout()
        self.tabs = QTabWidget()
        factories = (
            self._general_tab, self._monitoring_tab, self._detection_tab, self._response_tab,
            self._notifications_tab, self._integrations_tab, self._advanced_tab, self._about_tab,
        )
        icons = ("cog", "desktop", "shield-alt", "bolt", "bell", "plug", "sliders-h", "info-circle")
        for name, icon, factory in zip(self.TABS, icons, factories):
            self.tabs.addTab(factory(), qta.icon(f"fa5s.{icon}", color="#00E5D4"), name)
        body.addWidget(self.tabs, 3)
        body.addWidget(self._status_panel(), 1)
        root.addLayout(body, 1)

        footer = QHBoxLayout()
        reset = QPushButton("Reset to Defaults")
        reset.clicked.connect(self.reset_defaults)
        footer.addWidget(reset)
        footer.addStretch()
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.load_values)
        footer.addWidget(cancel)
        self.btn_save = QPushButton("Save Changes")
        self.btn_save.setProperty("class", "PrimaryAction")
        self.btn_save.clicked.connect(self.save_changes)
        footer.addWidget(self.btn_save)
        root.addLayout(footer)
        self.load_values()

    def _setting(self, key, control):
        self.controls[key] = control
        return control

    def _toggle(self, key, default=True):
        return self._setting(key, ToggleSwitch(SettingsManager.get(key) == "true" if SettingsManager.get(key) else default))

    def _float(self, key, default, low=0.2, high=300.0):
        control = QDoubleSpinBox()
        control.setRange(low, high)
        control.setDecimals(1)
        control.setSuffix(" sec")
        try:
            control.setValue(float(SettingsManager.get(key) or default))
        except (ValueError, TypeError):
            control.setValue(default)
        return self._setting(key, control)

    def _int(self, key, default, low=1, high=365):
        control = QSpinBox()
        control.setRange(low, high)
        control.setSuffix(" days")
        try:
            control.setValue(int(SettingsManager.get(key) or default))
        except (ValueError, TypeError):
            control.setValue(default)
        return self._setting(key, control)

    def _combo(self, key, options, default):
        control = QComboBox()
        control.addItems(options)
        control.setCurrentText(SettingsManager.get(key) or default)
        return self._setting(key, control)

    def _page(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(18)
        scroll.setWidget(content)
        return scroll, layout

    def _section(self, layout, title, rows):
        card = QFrame()
        card.setProperty("class", "Card")
        inner = QVBoxLayout(card)
        heading = QLabel(title)
        heading.setStyleSheet(f"font-size:15px;font-weight:600;color:{Theme.palette()['text']}")
        inner.addWidget(heading)
        form = QFormLayout()
        form.setVerticalSpacing(12)
        form.setHorizontalSpacing(20)
        for label, control in rows:
            form.addRow(QLabel(label), control)
        inner.addLayout(form)
        layout.addWidget(card)

    def _general_tab(self):
        page, layout = self._page()
        self._section(layout, "Application", [
            ("Launch with Windows", self._toggle("launch_with_windows", False)),
            ("Self protection", self._toggle("self_protection", False)),
            ("Automatic updates", self._toggle("automatic_updates", False)),
            ("Language", self._combo("language", ["English (United States)", "Spanish", "French"], "English (United States)")),
            ("Theme", self._combo("theme", ["Dark", "Light", "System"], "Dark")),
        ])
        self._section(layout, "Data and Storage", [
            ("Retention period", self._int("retention_days", 30)),
            ("Anonymous usage telemetry", self._toggle("telemetry_enabled", False)),
            ("Share threat intelligence", self._toggle("share_threat_intelligence", False)),
        ])
        layout.addStretch()
        return page

    def _monitoring_tab(self):
        page, layout = self._page()
        for label, key, interval, default_interval in (
            ("Process monitoring", "process_monitor_enabled", "process_monitor_interval", 5.0),
            ("Service monitoring", "service_monitor_enabled", "service_monitor_interval", 10.0),
            ("Network monitoring", "network_monitor_enabled", "network_monitor_interval", 5.0),
            ("Registry monitoring", "registry_monitor_enabled", "registry_monitor_interval", 5.0),
            ("File integrity monitoring", "fim_monitor_enabled", "fim_monitor_interval", 5.0),
            ("USB monitoring", "usb_monitor_enabled", "usb_monitor_interval", 5.0),
            ("Windows event log / Sysmon", "sysmon_monitor_enabled", "sysmon_monitor_interval", 15.0),
        ):
            self._section(layout, label, [("Enabled", self._toggle(key, True)), ("Refresh interval", self._float(interval, default_interval))])
        layout.addStretch()
        return page

    def _detection_tab(self):
        page, layout = self._page()
        self._section(layout, "Detection Engine", [
            ("Behavior rules", self._toggle("behavior_detection_enabled", True)),
            ("Cross-event correlation", self._toggle("correlation_enabled", True)),
            ("Suppress duplicate alerts", self._toggle("alert_deduplication_enabled", True)),
            ("Train local Isolation Forest from process history", self._toggle("ml_detection_enabled", True)),
            ("Minimum alert severity", self._combo("minimum_alert_severity", ["Informational", "Low", "Medium", "High", "Critical"], "Low")),
        ])
        layout.addStretch()
        return page

    def _response_tab(self):
        page, layout = self._page()
        quarantine = self._toggle("response_quarantine_file", False)
        network_isolation = self._toggle("response_block_network", False)
        auto_usb_termination = self._toggle("response_auto_usb_termination", False)
        self._section(layout, "Automated Response", [
            ("Response mode", self._combo("response_mode", ["Ask Before Responding", "Monitor Only", "Automated"], "Monitor Only")),
            ("Allow process termination", self._toggle("response_terminate_process", False)),
            ("Automatically stop executables launched from USB", auto_usb_termination),
            ("Allow file quarantine", quarantine),
            ("Allow per-process network isolation", network_isolation),
        ])
        note = QLabel("Quarantine requires stopping the selected process first and stores a hash-verified copy in your user profile for later restore. Network isolation applies Windows Firewall block rules to the selected executable only; it does not disconnect the whole computer. Both require their setting to be enabled, administrator rights, and confirmation. Automated USB response remains separately opt-in.")
        note.setWordWrap(True)
        note.setStyleSheet("color:#9ca3af")
        layout.addWidget(note)
        layout.addStretch()
        return page

    def _notifications_tab(self):
        page, layout = self._page()
        self._section(layout, "Notifications", [
            ("Show desktop notifications", self._toggle("desktop_notifications", True)),
            ("Critical alerts", self._toggle("notify_critical", True)),
            ("High severity alerts", self._toggle("notify_high", True)),
            ("Medium severity alerts", self._toggle("notify_medium", True)),
            ("Low severity alerts", self._toggle("notify_low", False)),
        ])
        layout.addStretch()
        return page

    def _integrations_tab(self):
        page, layout = self._page()
        self._section(layout, "Telemetry Sources", [
            ("Collect Windows Sysmon events when available", self._toggle("integration_sysmon", True)),
            ("Collect Windows service events", self._toggle("integration_services", True)),
            ("Collect removable device events", self._toggle("integration_usb", True)),
        ])
        layout.addWidget(QLabel("Sysmon is optional. HavocGuard continues to run when it is not installed."))
        layout.addStretch()
        return page

    def _advanced_tab(self):
        page, layout = self._page()
        self._section(layout, "Advanced", [
            ("Maximum stored events per page", self._int("page_size", 500, 50, 5000)),
            ("Log level", self._combo("log_level", ["DEBUG", "INFO", "WARNING", "ERROR"], "INFO")),
            ("Start minimized", self._toggle("start_minimized", False)),
        ])
        layout.addStretch()
        return page

    def _about_tab(self):
        page, layout = self._page()
        self._section(layout, "HavocGuard EDR", [
            ("Application version", QLabel("1.0.0")),
            ("Python", QLabel(platform.python_version())),
            ("Platform", QLabel(platform.platform())),
            ("Configuration saved", QLabel(datetime.now().strftime("%Y-%m-%d %H:%M"))),
        ])
        layout.addStretch()
        return page

    def _status_panel(self):
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        for title, rows in (
            ("System Information", [("Application", "HavocGuard EDR"), ("Platform", platform.system()), ("Version", "1.0.0")]),
            ("Protection Settings", [("Process monitoring", "Enabled"), ("Threat detection", "Enabled"), ("Sysmon", "Optional source")]),
        ):
            card = QFrame()
            card.setProperty("class", "Card")
            box = QVBoxLayout(card)
            label = QLabel(title)
            label.setStyleSheet("font-weight:600;color:#fff")
            box.addWidget(label)
            for name, value in rows:
                row = QHBoxLayout()
                row.addWidget(QLabel(name))
                row.addStretch()
                val = QLabel(value)
                val.setStyleSheet("color:#00E676")
                row.addWidget(val)
                box.addLayout(row)
            layout.addWidget(card)
        layout.addStretch()
        return panel

    def load_values(self):
        for key, control in self.controls.items():
            value = SettingsManager.get(key)
            if isinstance(control, QCheckBox):
                control.setChecked(value.casefold() == "true" if value else control.isChecked())
            elif isinstance(control, QComboBox) and value:
                control.setCurrentText(value)
            elif isinstance(control, (QSpinBox, QDoubleSpinBox)) and value:
                try:
                    control.setValue(float(value) if isinstance(control, QDoubleSpinBox) else int(value))
                except ValueError:
                    pass

    def save_changes(self):
        failed = []
        for key, control in self.controls.items():
            if isinstance(control, QCheckBox):
                value = "true" if control.isChecked() else "false"
            elif isinstance(control, QComboBox):
                value = control.currentText()
            else:
                value = control.value()
            if not SettingsManager.set(key, value):
                failed.append(key)
        if failed:
            QMessageBox.critical(self, "Settings Not Saved", "Could not save: " + ", ".join(failed))
        else:
            Theme.apply_stylesheet(QApplication.instance(), SettingsManager.get("theme") or "Dark")
            QMessageBox.information(self, "Settings Saved", "Your settings have been saved.")

    def reset_defaults(self):
        for key, control in self.controls.items():
            if isinstance(control, QCheckBox):
                control.setChecked(key.endswith("_enabled") or key.startswith("notify_") or key.startswith("integration_"))
            elif isinstance(control, QComboBox):
                control.setCurrentIndex(0)
            elif isinstance(control, QDoubleSpinBox):
                control.setValue(2.0)
            elif isinstance(control, QSpinBox):
                control.setValue(30 if key == "retention_days" else 500 if key == "page_size" else 1)
