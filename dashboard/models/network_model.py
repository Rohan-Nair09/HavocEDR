from PySide6.QtCore import Qt, QModelIndex
from dashboard.theme import Theme
from .base_table_model import BaseTableModel

class NetworkModel(BaseTableModel):
    def __init__(self, data=None):
        headers = ["Process", "PID", "Local IP", "Local Port", "Remote IP", "Remote Port", "Protocol", "State", "Username", "Suspicious", "Timestamp"]
        super().__init__(headers, data)

    def data(self, index, role):
        if not index.isValid():
            return None
            
        row = index.row()
        col = index.column()
        item = self._data[row]
        
        if role == Qt.DisplayRole:
            if col == 0: return item.get("process_name", "")
            if col == 1: return str(item.get("pid", ""))
            if col == 2: return item.get("local_ip", "")
            if col == 3: return str(item.get("local_port", ""))
            if col == 4: return item.get("remote_ip", "")
            if col == 5: return str(item.get("remote_port", ""))
            if col == 6: return item.get("protocol", "")
            if col == 7: return item.get("status", "")
            if col == 8: return item.get("username", "")
            if col == 9: return str(item.get("is_suspicious", ""))
            if col == 10: return str(item.get("timestamp", ""))[:19]
            
        if role == Qt.ForegroundRole:
            if item.get("is_suspicious"):
                return Theme.get_severity_color("high")
            if "CLOSED" in str(item.get("status", "")):
                return Theme.get_severity_color("info")
            
        return None
