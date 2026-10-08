from PySide6.QtCore import Qt, QModelIndex
from dashboard.theme import Theme
from .base_table_model import BaseTableModel

class USBModel(BaseTableModel):
    def __init__(self, data=None):
        headers = ["Drive Letter", "Action", "Vendor ID", "Product ID", "Serial Number", "Previously Seen", "Suspicious", "Timestamp"]
        super().__init__(headers, data)

    def data(self, index, role):
        if not index.isValid():
            return None
            
        row = index.row()
        col = index.column()
        item = self._data[row]
        
        if role == Qt.DisplayRole:
            if col == 0: return item.get("drive_letter", "")
            if col == 1: return item.get("action", "").upper()
            if col == 2: return item.get("vendor_id", "")
            if col == 3: return item.get("product_id", "")
            if col == 4: return item.get("serial_number", "")
            if col == 5: return str(item.get("previously_seen", ""))
            if col == 6: return str(item.get("is_suspicious", ""))
            if col == 7: return str(item.get("timestamp", ""))[:19]
            
        if role == Qt.ForegroundRole:
            if item.get("is_suspicious") or not item.get("previously_seen"):
                return Theme.get_severity_color("high")
            if item.get("action") == "removed":
                return Theme.get_severity_color("info")
            
        return None
