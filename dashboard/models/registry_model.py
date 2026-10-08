from PySide6.QtCore import Qt, QModelIndex
from dashboard.theme import Theme
from .base_table_model import BaseTableModel

class RegistryModel(BaseTableModel):
    def __init__(self, data=None):
        headers = ["Hive", "Key Path", "Value Name", "Change Type", "Signed", "Suspicious", "Timestamp"]
        super().__init__(headers, data)

    def data(self, index, role):
        if not index.isValid():
            return None
            
        row = index.row()
        col = index.column()
        item = self._data[row]
        
        if role == Qt.DisplayRole:
            if col == 0: return item.get("hive", "")
            if col == 1: return item.get("key_path", "")
            if col == 2: return item.get("value_name", "")
            if col == 3: return item.get("change_type", "").upper()
            if col == 4: return str(item.get("is_signed", ""))
            if col == 5: return str(item.get("is_suspicious", ""))
            if col == 6: return str(item.get("timestamp", ""))[:19]
            
        if role == Qt.ForegroundRole:
            if item.get("is_suspicious"):
                return Theme.get_severity_color("high")
            if item.get("change_type") == "deleted":
                return Theme.get_severity_color("critical")
            
        return None
