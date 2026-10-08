from PySide6.QtCore import Qt, QModelIndex
from dashboard.theme import Theme
from .base_table_model import BaseTableModel

class FIMModel(BaseTableModel):
    def __init__(self, data=None):
        headers = ["File Path", "Action", "Old SHA256", "New SHA256", "Hash Changed", "Previous Path", "Suspicious", "Timestamp"]
        super().__init__(headers, data)

    def data(self, index, role):
        if not index.isValid():
            return None
            
        row = index.row()
        col = index.column()
        item = self._data[row]
        
        old_hash = item.get("old_sha256", "")
        new_hash = item.get("sha256", "")
        hash_changed = (old_hash != new_hash) and bool(old_hash and new_hash)
        
        if role == Qt.DisplayRole:
            if col == 0: return item.get("file_path", "")
            if col == 1: return item.get("action", "").upper()
            if col == 2: return old_hash[:16] + "..." if old_hash else "N/A"
            if col == 3: return new_hash[:16] + "..." if new_hash else "N/A"
            if col == 4: return "YES" if hash_changed else "NO"
            if col == 5: return item.get("previous_file_path", "")
            if col == 6: return str(item.get("is_suspicious", ""))
            if col == 7: return str(item.get("timestamp", ""))[:19]
            
        if role == Qt.ForegroundRole:
            if item.get("is_suspicious") or hash_changed:
                return Theme.get_severity_color("high")
            if item.get("action") == "deleted":
                return Theme.get_severity_color("info")
            
        return None
