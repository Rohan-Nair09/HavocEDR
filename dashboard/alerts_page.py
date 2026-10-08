from dashboard.table_utils import configure_full_width_table
import csv
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableView, 
    QHeaderView, QPushButton, QComboBox, QFileDialog, QMessageBox
)
from PySide6.QtCore import Qt, QAbstractTableModel, QModelIndex
from dashboard.theme import Theme
from dashboard.data_provider import DataProvider

class AlertsTableModel(QAbstractTableModel):
    def __init__(self, data=None):
        super().__init__()
        self._data = data or []
        self._headers = ["ID", "Timestamp", "Severity", "Threat Type", "Status", "Title", "Source Modules"]

    def data(self, index, role):
        if not index.isValid():
            return None
            
        row = index.row()
        col = index.column()
        item = self._data[row]
        
        if role == Qt.DisplayRole:
            if col == 0: return str(item.get("id", ""))
            if col == 1: return str(item.get("timestamp", ""))[:19]
            if col == 2: return item.get("severity", "")
            if col == 3: return item.get("threat_type", "")
            if col == 4: return item.get("status", "")
            if col == 5: return item.get("title", "")
            if col == 6: return item.get("source_modules", "")
            
        if role == Qt.ForegroundRole and col == 2:
            # Color-code severity
            return Theme.get_severity_color(item.get("severity", ""))
            
        return None

    def rowCount(self, index=QModelIndex()):
        return len(self._data)

    def columnCount(self, index=QModelIndex()):
        return len(self._headers)

    def headerData(self, section, orientation, role):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self._headers[section]
        return None

    def sort(self, column, order=Qt.AscendingOrder):
        fields = ("id", "timestamp", "severity", "threat_type", "status", "title", "source_modules")
        if column < 0 or column >= len(fields) or not self._data:
            return
        field = fields[column]
        self.layoutAboutToBeChanged.emit()
        self._data.sort(key=lambda row: (row.get(field) is None, row.get(field) or ""), reverse=order == Qt.DescendingOrder)
        self.layoutChanged.emit()
        
    def set_data(self, new_data):
        self.beginResetModel()
        self._data = new_data
        self.endResetModel()

    def get_raw_data(self):
        return self._data

class AlertsPage(QWidget):
    def __init__(self, ui_event_bridge):
        super().__init__()
        self.ui_event_bridge = ui_event_bridge
        self.layout = QVBoxLayout(self)
        
        # Header
        header_layout = QHBoxLayout()
        title = QLabel("Threats & Alerts")
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
        self.status_filter = QComboBox()
        self.status_filter.addItems(["All", "Open", "Investigating", "Resolved", "False Positive"])
        self.status_filter.currentTextChanged.connect(self.load_data)
        
        controls_layout.addWidget(QLabel("Filter Status:"))
        controls_layout.addWidget(self.status_filter)
        controls_layout.addStretch()
        self.layout.addLayout(controls_layout)
        
        # Table
        self.table = QTableView()
        configure_full_width_table(self.table)
        self.model = AlertsTableModel()
        self.table.setModel(self.model)
        
        # Table Styling
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents) # ID
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents) # Timestamp
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents) # Severity
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setEditTriggers(QTableView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        
        self.layout.addWidget(self.table)
        
        # Real-time updates
        self.ui_event_bridge.alert_received.connect(self._on_new_alert)
        
        self.load_data()

    def load_data(self):
        status = self.status_filter.currentText()
        filters = {}
        if status != "All":
            filters["status"] = status
            
        data, count = DataProvider.fetch_data("alerts", limit=500, sort_col="id", sort_desc=True, filters=filters)
        self.model.set_data(data)

    def _on_new_alert(self, data: dict):
        # Simply reload data to get the new alert
        self.load_data()

    def export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export Alerts", "alerts_export.csv", "CSV Files (*.csv)")
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
            QMessageBox.information(self, "Export Successful", f"Exported {len(data)} alerts to {path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", f"Failed to export CSV: {e}")
