from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QCheckBox, QSpinBox,
    QPushButton, QLabel, QMessageBox
)

class SettingsPage(QWidget):
    """Placeholder Settings page.

    Provides a minimal UI that the validator can import and interact with.
    In the final product this will read/write the real SettingsManager.
    """
    def __init__(self, bridge, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)

        # Example monitor toggle
        self.chk_process = QCheckBox("Enable Process Monitor")
        self.chk_process.setChecked(True)
        layout.addWidget(self.chk_process)

        # Example interval control
        layout.addWidget(QLabel("Process monitor interval (seconds)"))
        self.spin_process_interval = QSpinBox()
        self.spin_process_interval.setRange(1, 60)
        self.spin_process_interval.setValue(5)
        layout.addWidget(self.spin_process_interval)

        # Save button – used by the validator
        self.btn_save = QPushButton("Save Settings")
        layout.addWidget(self.btn_save)
        self.btn_save.clicked.connect(self._save)

    def _save(self):
        """Persist settings (stub)."""
        QMessageBox.information(self, "Settings", "Settings saved (placeholder).")
