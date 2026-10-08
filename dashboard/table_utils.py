from PySide6.QtCore import Qt
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QTableView


def configure_full_width_table(table: QTableView) -> None:
    """Keep columns readable and let the user scroll to the full cell contents."""
    table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
    table.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
    table.setTextElideMode(Qt.ElideRight)
    header = table.horizontalHeader()
    header.setStretchLastSection(False)
    header.setSectionResizeMode(QHeaderView.Interactive)
    header.setDefaultSectionSize(180)
    header.setMinimumSectionSize(100)
