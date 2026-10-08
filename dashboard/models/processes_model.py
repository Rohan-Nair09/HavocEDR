from PySide6.QtCore import Qt, QModelIndex
from dashboard.theme import Theme
from .base_table_model import BaseTableModel

class ProcessesModel(BaseTableModel):
    def __init__(self, data=None):
        headers = ["PID", "Process Name", "Path", "Signature", "Suspicious", "CPU %", "Memory MB", "Username", "Start Time"]
        super().__init__(headers, data)

    def data(self, index, role):
        if not index.isValid():
            return None
            
        row = index.row()
        col = index.column()
        item = self._data[row]
        
        if role == Qt.DisplayRole:
            if col == 0: return str(item.get("pid", ""))
            if col == 1: return item.get("name", "")
            if col == 2: return item.get("path", item.get("executable_path", ""))
            if col == 3: return item.get("digital_signature", item.get("is_signed", ""))
            if col == 4: return str(item.get("is_suspicious", ""))
            if col == 5: return f"{item.get('cpu_percent', item.get('cpu_usage', 0.0)):.1f}"
            if col == 6: return f"{item.get('ram_usage_mb', item.get('memory_usage', 0.0)):.1f}"
            if col == 7: return item.get("user", item.get("username", ""))
            if col == 8: return str(item.get("timestamp", ""))[:19]
            
        if role == Qt.ForegroundRole:
            # Highlight suspicious rows
            if item.get("is_suspicious"):
                return Theme.get_severity_color("high")
            
        return None
