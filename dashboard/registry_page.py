from dashboard.table_utils import configure_full_width_table
import csv
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableView, 
    QHeaderView, QPushButton, QLineEdit, QFileDialog, QMessageBox
)
from dashboard.theme import Theme
from dashboard.data_provider import DataProvider
from dashboard.models.registry_model import RegistryModel

class RegistryPage(QWidget):
    def __init__(self, ui_event_bridge):
        super().__init__()
        self.ui_event_bridge = ui_event_bridge
        self.layout = QVBoxLayout(self)
        
        # Header
        header_layout = QHBoxLayout()
        title = QLabel("Registry Monitor")
        title.setFont(Theme.get_font(18, bold=True))
        header_layout.addWidget(title)
        
        self.btn_refresh = QPushButton("Refresh")
        self.btn_refresh.clicked.connect(self.load_data)
        
        self.btn_export = QPushButton("Export CSV")
        self.btn_export.clicked.connect(self.export_csv)
        
        header_layout.addStretch()
        header_layout.addWidget(self.btn_refresh)
        header_layout.addWidget(self.btn_export)
        
        self.layout.addLayout(header_layout)
        
        # Controls
        controls_layout = QHBoxLayout()
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Search Key Path or Value (press Enter)")
        self.search_bar.returnPressed.connect(self.load_data)
        
        controls_layout.addWidget(QLabel("Search:"))
        controls_layout.addWidget(self.search_bar)
        controls_layout.addStretch()
        self.layout.addLayout(controls_layout)
        
        # Table
        self.table = QTableView()
        configure_full_width_table(self.table)
        self.model = RegistryModel()
        self.table.setModel(self.model)
        
        # Table Styling
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setEditTriggers(QTableView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.setSortingEnabled(True) 
        
        self.layout.addWidget(self.table)
        
        # Real-time updates bridge
        self.ui_event_bridge.registry_received.connect(self._on_registry_event)
        
        self.load_data()

    def load_data(self):
        search_term = self.search_bar.text().strip().lower()
        data, count = DataProvider.fetch_data("registry", limit=500, sort_col="id", sort_desc=True)
        
        if search_term:
            filtered_data = []
            for d in data:
                if search_term in str(d.get("key_path", "")).lower() or search_term in str(d.get("value_name", "")).lower():
                    filtered_data.append(d)
            data = filtered_data

        self.model.set_data(data)

    def _on_registry_event(self, data: dict):
        search_term = self.search_bar.text().strip().lower()
        if search_term:
            if search_term not in str(data.get("key_path", "")).lower() and search_term not in str(data.get("value_name", "")).lower():
                return
        self.model.append_row(data)

    def export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export Registry", "registry_export.csv", "CSV Files (*.csv)")
        if not path:
            return
            
        data = self.model.get_raw_data()
        try:
            with open(path, 'w', newline='', encoding='utf-8') as f:
                if not data:
                    return
                writer = csv.DictWriter(f, fieldnames=data[0].keys())
                writer.writeheader()
                writer.writerows(data)
            QMessageBox.information(self, "Export Successful", f"Exported {len(data)} registry events to {path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", f"Failed to export CSV: {e}")
