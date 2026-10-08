from dashboard.table_utils import configure_full_width_table
import csv

from PySide6.QtCore import Qt, QAbstractTableModel, QModelIndex
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableView, QHeaderView,
    QPushButton, QLineEdit, QFileDialog, QMessageBox,
)

from dashboard.data_provider import DataProvider


class ServicesModel(QAbstractTableModel):
    HEADERS = ("Service", "Display Name", "Status", "Image Path", "Signed", "Suspicious", "Last Seen")
    FIELDS = ("name", "display_name", "status", "binpath", "is_signed", "is_suspicious", "timestamp")

    def __init__(self, parent=None):
        super().__init__(parent)
        self.rows = []

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.HEADERS)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or role != Qt.DisplayRole:
            return None
        value = self.rows[index.row()].get(self.FIELDS[index.column()], "")
        if index.column() == 6:
            return str(value)[:19]
        if isinstance(value, bool):
            return "Yes" if value else "No"
        return "" if value is None else str(value)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.HEADERS[section]
        return None

    def sort(self, column, order=Qt.AscendingOrder):
        if column < 0 or column >= len(self.FIELDS) or not self.rows:
            return
        field = self.FIELDS[column]
        def key(row):
            value = row.get(field)
            if isinstance(value, (int, float)):
                return (0, value)
            if value is None:
                return (1, "")
            return (0, str(value).casefold())
        self.layoutAboutToBeChanged.emit()
        self.rows.sort(key=key, reverse=order == Qt.DescendingOrder)
        self.layoutChanged.emit()

    def set_rows(self, rows):
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()


class ServicesPage(QWidget):
    def __init__(self, bridge=None, parent=None):
        super().__init__(parent)
        self.rows = []
        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 24, 32, 24)
        layout.setSpacing(16)

        header = QHBoxLayout()
        titles = QVBoxLayout()
        title = QLabel("Services")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #ffffff;")
        subtitle = QLabel("Review Windows services and identify suspicious service configurations.")
        subtitle.setStyleSheet("color: #9ca3af; font-size: 14px;")
        titles.addWidget(title)
        titles.addWidget(subtitle)
        header.addLayout(titles)
        header.addStretch()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search services...")
        self.search.textChanged.connect(self.load_data)
        header.addWidget(self.search)
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.load_data)
        header.addWidget(refresh)
        export = QPushButton("Export CSV")
        export.clicked.connect(self.export_csv)
        header.addWidget(export)
        layout.addLayout(header)

        self.model = ServicesModel(self)
        self.table = QTableView()
        configure_full_width_table(self.table)
        self.table.setModel(self.model)
        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setEditTriggers(QTableView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        layout.addWidget(self.table)

        if bridge is not None:
            bridge.service_received.connect(self._on_service)
        self.load_data()

    def load_data(self, *_):
        rows, _ = DataProvider.fetch_data("services", limit=1000, sort_col="id", sort_desc=True)
        query = self.search.text().strip().casefold()
        self.rows = [row for row in rows if not query or query in " ".join(str(v) for v in row.values()).casefold()]
        self.model.set_rows(self.rows)

    def _on_service(self, _event):
        self.load_data()

    def export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export Services", "services_export.csv", "CSV Files (*.csv)")
        if not path or not self.rows:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as output:
                writer = csv.DictWriter(output, fieldnames=self.rows[0].keys())
                writer.writeheader()
                writer.writerows(self.rows)
            QMessageBox.information(self, "Export Successful", f"Exported {len(self.rows)} services.")
        except OSError as exc:
            QMessageBox.critical(self, "Export Failed", str(exc))
