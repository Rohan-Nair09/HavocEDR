from PySide6.QtCore import Qt, QModelIndex
from dashboard.theme import Theme
from .base_table_model import BaseTableModel

class SysmonModel(BaseTableModel):
    def __init__(self, data=None):
        headers = ["Event ID", "Event Name", "Process GUID", "PID", "Image", "User", "Suspicious", "Timestamp"]
        super().__init__(headers, data)

    def data(self, index, role):
        if not index.isValid():
            return None
            
        row = index.row()
        col = index.column()
        item = self._data[row]
        
        if role == Qt.DisplayRole:
            if col == 0: return str(item.get("event_id", ""))
            if col == 1: return item.get("event_name", "")
            if col == 2: return item.get("process_guid", "")
            if col == 3: return str(item.get("process_id", ""))
            if col == 4: return item.get("image", "")
            if col == 5: return item.get("user", "")
            if col == 6: return str(item.get("is_suspicious", ""))
            if col == 7: return str(item.get("timestamp", ""))[:19]
            
        if role == Qt.ForegroundRole:
            if item.get("is_suspicious"):
                return Theme.get_severity_color("high")
            
        return None
