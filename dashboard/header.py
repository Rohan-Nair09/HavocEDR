from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QHBoxLayout, QPushButton, 
    QComboBox, QSpacerItem, QSizePolicy
)
from PySide6.QtCore import Qt
import qtawesome as qta

class HeaderBar(QWidget):
    """Top header matching the spec exactly."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("HeaderBar")
        self.setFixedHeight(56)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(24, 0, 24, 0)
        layout.setSpacing(16)

        layout.addItem(QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum))

        # Right side - Response Mode
        resp_layout = QHBoxLayout()
        resp_layout.setSpacing(8)
        resp_lbl = QLabel("Response Mode")
        resp_lbl.setStyleSheet("color: #9ca3af; font-size: 12px;")
        
        self.response_mode = QComboBox()
        self.response_mode.addItems(["Ask Before Responding", "Monitor Only", "Automated"])
        self.response_mode.setFixedWidth(180)
        # Style specific for the header dropdown
        self.response_mode.setStyleSheet("""
            QComboBox {
                border: 1px solid #FF9800;
                color: #FF9800;
                background-color: transparent;
                border-radius: 4px;
                padding: 4px 8px;
            }
            QComboBox::drop-down { border: none; }
        """)
        
        mode_container = QVBoxLayout()
        mode_container.setContentsMargins(0, 8, 0, 8)
        mode_container.setSpacing(2)
        mode_container.addWidget(resp_lbl)
        mode_container.addWidget(self.response_mode)
        layout.addLayout(mode_container)

        # Separator or spacing
        layout.addSpacing(16)

        # Icons
        self.btn_notifications = QPushButton(qta.icon('fa5s.bell', color='#e0e6ed'), "")
        self.btn_notifications.setToolTip("Notifications (3 Unread)")
        self.btn_notifications.setFixedSize(32, 32)
        layout.addWidget(self.btn_notifications)

        self.btn_theme = QPushButton(qta.icon('fa5s.moon', color='#e0e6ed'), "")
        self.btn_theme.setToolTip("Toggle Theme")
        self.btn_theme.setFixedSize(32, 32)
        layout.addWidget(self.btn_theme)

        self.btn_help = QPushButton(qta.icon('fa5s.question-circle', color='#e0e6ed'), "")
        self.btn_help.setToolTip("Help")
        self.btn_help.setFixedSize(32, 32)
        layout.addWidget(self.btn_help)

        self.btn_settings = QPushButton(qta.icon('fa5s.cog', color='#e0e6ed'), "")
        self.btn_settings.setToolTip("Settings")
        self.btn_settings.setFixedSize(32, 32)
        layout.addWidget(self.btn_settings)

        layout.addSpacing(16)

        # Window controls
        self.btn_min = QPushButton(qta.icon('fa5s.window-minimize', color='#9ca3af'), "")
        self.btn_min.setFixedSize(32, 32)
        layout.addWidget(self.btn_min)
        
        self.btn_max = QPushButton(qta.icon('fa5s.window-maximize', color='#9ca3af'), "")
        self.btn_max.setFixedSize(32, 32)
        layout.addWidget(self.btn_max)
        
        self.btn_close = QPushButton(qta.icon('fa5s.times', color='#9ca3af'), "")
        self.btn_close.setFixedSize(32, 32)
        self.btn_close.clicked.connect(self._close_requested)
        layout.addWidget(self.btn_close)

    def _close_requested(self):
        if self.parent():
            self.parent().close()
