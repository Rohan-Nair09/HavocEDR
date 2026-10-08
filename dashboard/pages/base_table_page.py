from dashboard.table_utils import configure_full_width_table
import os
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableView,
    QPushButton, QLineEdit, QHeaderView, QAbstractItemView,
    QComboBox
)
from PySide6.QtCore import Qt, QSortFilterProxyModel
import qtawesome as qta

class BaseTablePage(QWidget):
    """Base class for all telemetry pages (Processes, Network, etc.)
    using QTableView + QAbstractTableModel as requested.
    """
    def __init__(self, title, subtitle, bridge=None, parent=None):
        super().__init__(parent)
        self.bridge = bridge
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(32, 24, 32, 24)
        self.layout.setSpacing(16)

        # ---- Header -----------------------------------------------
        header_layout = QHBoxLayout()
        title_layout = QVBoxLayout()
        title_layout.setSpacing(4)
        title_lbl = QLabel(title)
        title_lbl.setStyleSheet("font-size: 24px; font-weight: bold; color: #ffffff;")
        subtitle_lbl = QLabel(subtitle)
        subtitle_lbl.setStyleSheet("color: #9ca3af; font-size: 14px;")
        title_layout.addWidget(title_lbl)
        title_layout.addWidget(subtitle_lbl)
        header_layout.addLayout(title_layout)
        
        # ---- Toolbar ----------------------------------------------
        header_layout.addStretch()
        
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search...")
        self.search_box.setFixedWidth(240)
        self.search_box.textChanged.connect(self.on_search)
        header_layout.addWidget(self.search_box)
        
        self.btn_filter = QPushButton(qta.icon('fa5s.filter', color='#9ca3af'), " Filters")
        self.btn_filter.setStyleSheet("background-color: transparent; border: 1px solid #374151; padding: 6px 16px; border-radius: 4px; color: #e0e6ed; font-weight: bold;")
        header_layout.addWidget(self.btn_filter)
        
        self.btn_refresh = QPushButton(qta.icon('fa5s.sync-alt', color='#9ca3af'), "")
        self.btn_refresh.setToolTip("Refresh")
        self.btn_refresh.setStyleSheet("background-color: transparent; border: 1px solid #374151; padding: 6px 12px; border-radius: 4px;")
        header_layout.addWidget(self.btn_refresh)
        
        self.btn_export = QPushButton(qta.icon('fa5s.file-export', color='#9ca3af'), " Export CSV")
        self.btn_export.setStyleSheet("background-color: transparent; border: 1px solid #374151; padding: 6px 16px; border-radius: 4px; color: #e0e6ed; font-weight: bold;")
        header_layout.addWidget(self.btn_export)
        
        self.layout.addLayout(header_layout)

        # ---- Top KPIs (Optional placeholder, subclasses can insert here)
        self.kpi_layout = QHBoxLayout()
        self.layout.addLayout(self.kpi_layout)

        # ---- Table Setup ------------------------------------------
        self.table = QTableView()
        configure_full_width_table(self.table)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setStretchLastSection(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table.verticalHeader().setVisible(False)
        self.table.setSortingEnabled(True)
        self.table.setShowGrid(False) # Matches modern web-like tables
        self.layout.addWidget(self.table)

        # ---- Pagination -------------------------------------------
        page_layout = QHBoxLayout()
        self.page_lbl = QLabel("Showing 0 to 0 of 0 entries")
        self.page_lbl.setStyleSheet("color: #9ca3af;")
        page_layout.addWidget(self.page_lbl)
        page_layout.addStretch()
        
        prev_btn = QPushButton(qta.icon('fa5s.chevron-left', color='#9ca3af'), "")
        prev_btn.setFixedSize(28, 28)
        prev_btn.setStyleSheet("background-color: #1f2937; border: none; border-radius: 4px;")
        
        page1 = QPushButton("1")
        page1.setFixedSize(28, 28)
        page1.setStyleSheet("background-color: #00E5D4; color: black; border-radius: 4px; font-weight: bold;")
        
        next_btn = QPushButton(qta.icon('fa5s.chevron-right', color='#9ca3af'), "")
        next_btn.setFixedSize(28, 28)
        next_btn.setStyleSheet("background-color: #1f2937; border: none; border-radius: 4px;")
        
        page_layout.addWidget(prev_btn)
        page_layout.addWidget(page1)
        page_layout.addWidget(next_btn)
        
        self.layout.addLayout(page_layout)

        # Model setup
        self.model = None
        self.proxy_model = QSortFilterProxyModel()
        self.proxy_model.setFilterCaseSensitivity(Qt.CaseInsensitive)
        self.proxy_model.setFilterKeyColumn(-1)

    def set_model(self, model):
        self.model = model
        self.proxy_model.setSourceModel(self.model)
        self.table.setModel(self.proxy_model)
        self.update_pagination_label()
        
        # Connect to model changes to update counts
        self.model.layoutChanged.connect(self.update_pagination_label)

    def on_search(self, text):
        self.proxy_model.setFilterWildcard(f"*{text}*")
        self.update_pagination_label()

    def update_pagination_label(self):
        if self.model:
            total = self.proxy_model.rowCount()
            self.page_lbl.setText(f"Showing 1 to {min(10, total)} of {total} entries")
