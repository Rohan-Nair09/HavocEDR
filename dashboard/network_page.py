from dashboard.table_utils import configure_full_width_table
import csv
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableView, 
    QHeaderView, QPushButton, QLineEdit, QFileDialog, QMessageBox
)
from dashboard.theme import Theme
from dashboard.data_provider import DataProvider
from dashboard.models.network_model import NetworkModel

class NetworkPage(QWidget):
    def __init__(self, ui_event_bridge):
        super().__init__()
        self.ui_event_bridge = ui_event_bridge
        self.layout = QVBoxLayout(self)
        
        # Header
        header_layout = QHBoxLayout()
        title = QLabel("Network Monitor")
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
        self.search_bar.setPlaceholderText("Search IP, Port, or Process (press Enter)")
        self.search_bar.returnPressed.connect(self.load_data)
        
        controls_layout.addWidget(QLabel("Search:"))
        controls_layout.addWidget(self.search_bar)
        controls_layout.addStretch()
        self.layout.addLayout(controls_layout)
        
        # Table
        self.table = QTableView()
        configure_full_width_table(self.table)
        self.model = NetworkModel()
        self.table.setModel(self.model)
        
        # Table Styling
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents) # PID
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setEditTriggers(QTableView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.setSortingEnabled(True) 
        
        self.layout.addWidget(self.table)
        
        # Real-time updates bridge
        self.ui_event_bridge.network_received.connect(self._on_network_event)
        
        self.load_data()

    def load_data(self):
        search_term = self.search_bar.text().strip().lower()
        data, count = DataProvider.fetch_data("network", limit=500, sort_col="id", sort_desc=True)
        
        if search_term:
            filtered_data = []
            for d in data:
                ip_match = search_term in str(d.get("remote_ip", "")).lower() or search_term in str(d.get("local_ip", "")).lower()
                port_match = search_term == str(d.get("remote_port", "")) or search_term == str(d.get("local_port", ""))
                proc_match = search_term in str(d.get("process_name", "")).lower() or search_term == str(d.get("pid", ""))
                
                if ip_match or port_match or proc_match:
                    filtered_data.append(d)
            data = filtered_data

        self.model.set_data(data)

    def _on_network_event(self, data: dict):
        # Filter check
        search_term = self.search_bar.text().strip().lower()
        if search_term:
            ip_match = search_term in str(data.get("remote_ip", "")).lower() or search_term in str(data.get("local_ip", "")).lower()
            port_match = search_term == str(data.get("remote_port", "")) or search_term == str(data.get("local_port", ""))
            proc_match = search_term in str(data.get("process_name", "")).lower() or search_term == str(data.get("pid", ""))
            if not (ip_match or port_match or proc_match):
                return
                
        self.model.append_row(data)

    def export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export Network", "network_export.csv", "CSV Files (*.csv)")
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
            QMessageBox.information(self, "Export Successful", f"Exported {len(data)} network events to {path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", f"Failed to export CSV: {e}")
