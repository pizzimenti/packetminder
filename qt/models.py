"""Table model that bridges Rust netwatch-core data to Qt's model/view system."""

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, Qt, QSortFilterProxyModel
from PyQt6.QtGui import QColor

COLUMNS = ["REMOTE_IP", "ISP", "DOWN", "UP", "SENT", "RECV", "CONNECTED"]

# Map color names from Rust to QColors
ROW_COLORS = {
    "blue": QColor(100, 149, 237),   # cornflower blue
    "red": QColor(255, 80, 80),
    "yellow": QColor(255, 220, 80),
    "white": QColor(210, 210, 210),
}


class ConnectionTableModel(QAbstractTableModel):
    """Flat table model backed by a list of Connection objects from Rust."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._connections = []

    def update_connections(self, connections):
        """Replace all data with a fresh snapshot from netwatch-core."""
        self.beginResetModel()
        self._connections = list(connections)
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return len(self._connections)

    def columnCount(self, parent=QModelIndex()):
        return len(COLUMNS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return COLUMNS[section]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None

        conn = self._connections[index.row()]
        col = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            if col == 0:
                return conn.remote
            elif col == 1:
                return conn.isp
            elif col == 2:
                return conn.speed_down_fmt
            elif col == 3:
                return conn.speed_up_fmt
            elif col == 4:
                return conn.bytes_sent_fmt
            elif col == 5:
                return conn.bytes_recv_fmt
            elif col == 6:
                return conn.first_seen_str

        elif role == Qt.ItemDataRole.ForegroundRole:
            color_name = conn.color
            return ROW_COLORS.get(color_name, ROW_COLORS["white"])

        # Raw numeric values for sorting
        elif role == Qt.ItemDataRole.UserRole:
            if col == 0:
                return conn.remote
            elif col == 1:
                return conn.isp.lower()
            elif col == 2:
                return conn.speed_down
            elif col == 3:
                return conn.speed_up
            elif col == 4:
                return conn.bytes_sent
            elif col == 5:
                return conn.bytes_recv
            elif col == 6:
                return conn.first_seen_str

        return None


class SortableConnectionModel(QSortFilterProxyModel):
    """Proxy model that sorts using raw numeric values from UserRole."""

    def lessThan(self, left, right):
        left_data = self.sourceModel().data(left, Qt.ItemDataRole.UserRole)
        right_data = self.sourceModel().data(right, Qt.ItemDataRole.UserRole)
        if left_data is None or right_data is None:
            return False
        return left_data < right_data
