#!/usr/bin/env python3
"""Netwatch Qt GUI — a beautiful desktop frontend for netwatch-core."""

import sys

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QFont, QPalette
from PyQt6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMainWindow,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from models import ConnectionTableModel, SortableConnectionModel
from netwatch_core import NetwatchCore

POLL_MS = 1000


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NETWATCH")
        self.resize(1000, 600)
        self.setMinimumSize(700, 300)

        self.core = NetwatchCore()
        self._setup_ui()
        self._setup_timer()

    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # -- Header --
        header = QFrame()
        header.setFixedHeight(36)
        header.setStyleSheet("background-color: #1a1a2e;")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(12, 0, 12, 0)

        title = QLabel("NETWATCH")
        title.setFont(QFont("monospace", 14, QFont.Weight.Bold))
        title.setStyleSheet("color: #00d4ff;")
        header_layout.addWidget(title)

        self.count_label = QLabel("0 connections")
        self.count_label.setFont(QFont("monospace", 11))
        self.count_label.setStyleSheet("color: #ffd700;")
        header_layout.addStretch()
        header_layout.addWidget(self.count_label)

        layout.addWidget(header)

        # -- Table --
        self.source_model = ConnectionTableModel()
        self.proxy_model = SortableConnectionModel()
        self.proxy_model.setSourceModel(self.source_model)

        self.table = QTableView()
        self.table.setModel(self.proxy_model)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(5, Qt.SortOrder.DescendingOrder)  # RECV desc
        self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setFont(QFont("monospace", 10))

        # Column sizing
        hdr = self.table.horizontalHeader()
        hdr.setStretchLastSection(False)
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)    # REMOTE_IP
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)    # ISP
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)      # DOWN
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)      # UP
        hdr.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)      # SENT
        hdr.setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)      # RECV
        hdr.setSectionResizeMode(6, QHeaderView.ResizeMode.Fixed)      # CONNECTED
        self.table.setColumnWidth(2, 100)
        self.table.setColumnWidth(3, 100)
        self.table.setColumnWidth(4, 70)
        self.table.setColumnWidth(5, 70)
        self.table.setColumnWidth(6, 90)

        self.table.setStyleSheet("""
            QTableView {
                background-color: #0d0d1a;
                alternate-background-color: #141428;
                color: #d0d0d0;
                border: none;
                gridline-color: transparent;
            }
            QTableView::item:selected {
                background-color: #2a2a4a;
            }
            QHeaderView::section {
                background-color: #1a1a2e;
                color: #ffffff;
                font-weight: bold;
                border: none;
                padding: 4px 8px;
            }
        """)

        layout.addWidget(self.table)

        # -- Footer --
        footer = QFrame()
        footer.setFixedHeight(28)
        footer.setStyleSheet("background-color: #00d4ff;")
        footer_layout = QHBoxLayout(footer)
        footer_layout.setContentsMargins(12, 0, 12, 0)
        footer_label = QLabel("Click column headers to sort")
        footer_label.setFont(QFont("monospace", 10, QFont.Weight.Bold))
        footer_label.setStyleSheet("color: #000000;")
        footer_layout.addWidget(footer_label)
        layout.addWidget(footer)

    def _setup_timer(self):
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._poll)
        self.timer.start(POLL_MS)
        self._poll()  # immediate first poll

    def _poll(self):
        connections = self.core.poll()
        self.source_model.update_connections(connections)
        self.count_label.setText(f"{len(connections)} connections")


def apply_dark_palette(app):
    """Apply a dark color palette to the application."""
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(13, 13, 26))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(210, 210, 210))
    palette.setColor(QPalette.ColorRole.Base, QColor(13, 13, 26))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(20, 20, 40))
    palette.setColor(QPalette.ColorRole.Text, QColor(210, 210, 210))
    palette.setColor(QPalette.ColorRole.Button, QColor(26, 26, 46))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(210, 210, 210))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 42, 74))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(255, 255, 255))
    app.setPalette(palette)


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    apply_dark_palette(app)

    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
