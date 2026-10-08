from PySide6.QtCore import Qt, QAbstractTableModel, QModelIndex
from dashboard.theme import Theme

class BaseTableModel(QAbstractTableModel):
    """
    Base class for all Telemetry table models.
    Handles data storage, dynamic row appending, and generic formatting.
    """
    def __init__(self, headers=None, data=None):
        super().__init__()
        self._headers = headers or []
        self._data = data or []

    def rowCount(self, index=QModelIndex()):
        return len(self._data)

    def columnCount(self, index=QModelIndex()):
        return len(self._headers)

    def headerData(self, section, orientation, role):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self._headers[section]
        return None

    def sort(self, column, order=Qt.AscendingOrder):
        """Sort the backing rows by the values currently displayed in a column."""
        if column < 0 or column >= self.columnCount() or not self._data:
            return
        decorated = []
        for position, row in enumerate(self._data):
            value = self.data(self.index(position, column), Qt.DisplayRole)
            decorated.append((value, position, row))
        values = [str(value or "").strip() for value, _, _ in decorated]
        numeric = True
        numeric_values = []
        for value in values:
            try:
                numeric_values.append(float(value.replace(",", "")))
            except ValueError:
                numeric = False
                break
        key = (lambda item: numeric_values[item[1]]) if numeric else (lambda item: str(item[0] or "").casefold())
        self.layoutAboutToBeChanged.emit()
        decorated.sort(key=key, reverse=order == Qt.DescendingOrder)
        self._data = [item[2] for item in decorated]
        self.layoutChanged.emit()

    def set_data(self, new_data):
        """Perform a complete data reload."""
        self.beginResetModel()
        self._data = new_data
        self.endResetModel()

    def append_row(self, row_dict):
        """
        Dynamically append a single row to the UI model without a full database reload.
        This provides real-time updates efficiently.
        """
        # Insert at the top (index 0) since we usually sort descending by timestamp/ID
        self.beginInsertRows(QModelIndex(), 0, 0)
        self._data.insert(0, row_dict)
        
        # If the table grows too large, pop from the bottom to prevent memory bloat in UI
        if len(self._data) > 1000:
            self.endInsertRows()
            self.beginRemoveRows(QModelIndex(), 1000, len(self._data) - 1)
            self._data = self._data[:1000]
            self.endRemoveRows()
        else:
            self.endInsertRows()

    def get_raw_data(self):
        return self._data
