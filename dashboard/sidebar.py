import os
import time
from datetime import timedelta
import psutil
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from database.connection import engine
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QPushButton, QSpacerItem,
    QSizePolicy, QFrame, QHBoxLayout, QProgressBar, QScrollArea
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QPixmap
import qtawesome as qta

class Sidebar(QWidget):
    """Left navigation panel matching exact screenshot spec."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("Sidebar")
        self.setFixedWidth(260)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        # ---- Logo area --------------------------------------------
        logo_frame = QFrame()
        logo_layout = QHBoxLayout(logo_frame)
        logo_layout.setContentsMargins(20, 24, 20, 20)
        logo_lbl = QLabel()
        logo_lbl.setText("<span style='color:#00E5D4; font-size: 20px; font-weight:bold;'>🛡️ HavocGuard EDR</span><br><span style='font-size:10px; color:#9ca3af;'>Intelligent. Adaptive. Secure.</span>")
        logo_layout.addWidget(logo_lbl)
        layout.addWidget(logo_frame)

        # ---- Navigation Menu --------------------------------------
        self.buttons = {}
        nav_items = [
            ("Dashboard", "fa5s.th-large"),
            ("Processes", "fa5s.microchip"),
            ("Services", "fa5s.cogs"),
            ("Network", "fa5s.network-wired"),
            ("File Integrity", "fa5s.file-alt"),
            ("Registry", "fa5s.cubes"),
            ("USB Devices", "fa5b.usb"),
            ("Threats & Alerts", "fa5s.exclamation-triangle"),
            ("AI Security Analyst", "fa5s.brain"),
            ("Reports & Analytics", "fa5s.chart-bar"),
            ("Settings", "fa5s.cog")
        ]

        nav_container = QWidget()
        nav_layout = QVBoxLayout(nav_container)
        nav_layout.setContentsMargins(12, 0, 12, 0)
        nav_layout.setSpacing(4)

        for name, icon_name in nav_items:
            # For exact ID mapping we strip spaces and ampersands
            btn_id = name.lower().replace(' & ', '_and_').replace(' ', '_')
            btn = QPushButton(f"  {name}")
            btn.setIcon(qta.icon(icon_name, color='#9ca3af'))
            btn.setObjectName(f"btn_{btn_id}")
            btn.setCheckable(True)
            btn.setAutoExclusive(True)
            nav_layout.addWidget(btn)
            self.buttons[btn_id] = btn

        # Keep all navigation reachable on shorter screens. Without a scroll
        # area, the two status cards can push the last navigation items below
        # the visible window area.
        nav_scroll = QScrollArea()
        nav_scroll.setWidgetResizable(True)
        nav_scroll.setFrameShape(QFrame.NoFrame)
        nav_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        nav_scroll.setWidget(nav_container)
        layout.addWidget(nav_scroll, 1)
        layout.addItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))

        # ---- Bottom Status Cards ----------------------------------
        bottom_layout = QVBoxLayout()
        bottom_layout.setContentsMargins(16, 16, 16, 16)
        bottom_layout.setSpacing(12)

        self.agent_card = self._make_agent_card()
        bottom_layout.addWidget(self.agent_card)

        self.protected_card = self._make_protected_card()
        bottom_layout.addWidget(self.protected_card)

        layout.addLayout(bottom_layout)
        self._agent_process = psutil.Process(os.getpid())
        self._agent_process.cpu_percent()
        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self._refresh_agent_card)
        self._refresh_timer.start(5000)
        self._refresh_agent_card()

    def _make_agent_card(self) -> QFrame:
        card = QFrame()
        card.setProperty("class", "Card")
        # Override border for this specific card
        card.setStyleSheet("QFrame.Card { background-color: #111827; border: 1px solid #1f2937; border-radius: 12px; }")
        
        layout = QVBoxLayout(card)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)
        
        # Header: Icon + Title
        header = QHBoxLayout()
        header.setContentsMargins(0, 0, 0, 0)
        icon_lbl = QLabel()
        icon_lbl.setPixmap(qta.icon('fa5s.shield-alt', color='#00E676').pixmap(16, 16))
        title = QLabel("<b style='color:#00E676; font-size:12px;'>HavocGuard UI</b><br><span style='color:#00E676; font-size:11px;'>Running</span>")
        header.addWidget(icon_lbl)
        header.addWidget(title)
        header.addStretch()
        layout.addLayout(header)
        
        # Stats
        self.agent_stats = QLabel("<span style='color:#9ca3af; font-size:11px;'>Version: 1.0.0<br>Uptime: —<br>Telemetry: <span style='color:#00E5D4;'>Live</span></span>")
        layout.addWidget(self.agent_stats)
        
        # Spacer
        layout.addSpacing(4)
        
        # CPU
        self.cpu_lbl = QLabel("<span style='color:#9ca3af; font-size:11px;'>CPU Usage</span> <span style='color:#00E676; font-size:11px;'>—</span>")
        layout.addWidget(self.cpu_lbl)
        self.cpu_bar = self._usage_bar()
        layout.addWidget(self.cpu_bar)
        
        # Spacer
        layout.addSpacing(4)
        
        # RAM
        self.ram_lbl = QLabel("<span style='color:#9ca3af; font-size:11px;'>RAM Usage</span> <span style='color:#00E676; font-size:11px;'>—</span>")
        layout.addWidget(self.ram_lbl)
        self.ram_bar = self._usage_bar()
        layout.addWidget(self.ram_bar)

        # Spacer
        layout.addSpacing(8)

        # DB / Sync
        db_lbl = QHBoxLayout()
        db_lbl.setContentsMargins(0,0,0,0)
        db_lbl.addWidget(QLabel("<span style='color:#9ca3af; font-size:11px;'>DB Status</span>"))
        self.db_val = QLabel("<span style='color:#9ca3af; font-size:11px;'>Checking</span>")
        self.db_val.setAlignment(Qt.AlignRight)
        db_lbl.addWidget(self.db_val)
        layout.addLayout(db_lbl)
        
        sync_lbl = QHBoxLayout()
        sync_lbl.setContentsMargins(0,0,0,0)
        sync_lbl.addWidget(QLabel("<span style='color:#9ca3af; font-size:11px;'>Last Check</span>"))
        self.sync_val = QLabel("<span style='color:#e0e6ed; font-size:11px;'>—</span>")
        self.sync_val.setAlignment(Qt.AlignRight)
        sync_lbl.addWidget(self.sync_val)
        layout.addLayout(sync_lbl)

        return card

    def _usage_bar(self):
        bar = QProgressBar()
        bar.setFixedHeight(4)
        bar.setTextVisible(False)
        bar.setRange(0, 100)
        bar.setStyleSheet("QProgressBar { border: none; background: #1f2937; border-radius: 2px; } QProgressBar::chunk { background: #00E676; border-radius: 2px; }")
        return bar

    def _refresh_agent_card(self):
        try:
            with self._agent_process.oneshot():
                cpu = self._agent_process.cpu_percent()
                memory = self._agent_process.memory_info().rss / (1024 * 1024)
                started = self._agent_process.create_time()
            elapsed = max(0, int(time.time() - started))
            uptime = str(timedelta(seconds=elapsed))
            self.agent_stats.setText(f"<span style='color:#9ca3af;font-size:11px;'>Version: 1.0.0<br>Uptime: {uptime}<br>Telemetry: <span style='color:#00E5D4;'>Live</span></span>")
            self.cpu_lbl.setText(f"<span style='color:#9ca3af;font-size:11px;'>CPU Usage</span> <span style='color:#00E676;font-size:11px;'>{cpu:.1f}%</span>")
            self.ram_lbl.setText(f"<span style='color:#9ca3af;font-size:11px;'>RAM Usage</span> <span style='color:#00E676;font-size:11px;'>{memory:.0f} MB</span>")
            self.cpu_bar.setValue(min(100, round(cpu)))
            self.ram_bar.setValue(min(100, round(memory / max(psutil.virtual_memory().total / (1024 * 1024), 1) * 100)))
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            self.db_val.setText("<span style='color:#00E676;font-size:11px;'>Connected</span>")
            self.sync_val.setText(f"<span style='color:#e0e6ed;font-size:11px;'>{time.strftime('%H:%M:%S')}</span>")
        except (psutil.Error, OSError, RuntimeError, SQLAlchemyError):
            self.db_val.setText("<span style='color:#FF4D4D;font-size:11px;'>Unavailable</span>")

    def _make_protected_card(self) -> QFrame:
        card = QFrame()
        card.setProperty("class", "Card")
        # Glow effect border
        card.setStyleSheet("QFrame.Card { background-color: rgba(0, 230, 118, 0.05); border: 1px solid rgba(0, 230, 118, 0.2); border-radius: 12px; }")
        layout = QHBoxLayout(card)
        layout.setContentsMargins(12, 12, 12, 12)
        
        icon_lbl = QLabel()
        icon_lbl.setPixmap(qta.icon('fa5s.shield-alt', color='#00E676').pixmap(24, 24))
        
        text = QLabel("<b style='color:#00E676; font-size:12px;'>Endpoint Monitored</b><br><span style='color:#9ca3af; font-size:10px;'>Telemetry is collected<br>while the agent is running</span>")
        
        layout.addWidget(icon_lbl)
        layout.addWidget(text)
        return card
