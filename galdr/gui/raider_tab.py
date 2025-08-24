from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget, QTableWidgetItem,
    QSplitter, QTabWidget, QTextEdit, QGroupBox, QLabel, QHeaderView
)
from PyQt6.QtCore import Qt, pyqtSlot
from PyQt6.QtGui import QFont

from galdr.raider.raider_core import RaiderManager

class RaiderTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.raider_manager = None
        self.init_ui()
        self.connect_signals()

    def init_ui(self):
        main_layout = QHBoxLayout(self)

        # --- Left side: Configuration ---
        config_widget = QWidget()
        config_layout = QVBoxLayout(config_widget)

        # Request Editor
        request_group = QGroupBox("Request Template")
        request_layout = QVBoxLayout(request_group)
        self.request_editor = QTextEdit()
        self.request_editor.setPlaceholderText("Paste raw HTTP request here...")
        self.request_editor.setFont(QFont("Courier", 9))
        request_layout.addWidget(self.request_editor)

        # Injection Point Controls
        ip_layout = QHBoxLayout()
        self.add_marker_btn = QPushButton("Add § Injection Marker")
        ip_layout.addWidget(self.add_marker_btn)
        ip_layout.addStretch()
        request_layout.addLayout(ip_layout)
        config_layout.addWidget(request_group)

        # Payloads
        payloads_group = QGroupBox("Payloads")
        payloads_layout = QVBoxLayout(payloads_group)
        self.payload_tabs = QTabWidget()

        # Simple List Tab
        simple_list_widget = QWidget()
        simple_list_layout = QVBoxLayout(simple_list_widget)
        self.payload_list_editor = QTextEdit()
        self.payload_list_editor.setPlaceholderText("Paste one payload per line...")
        simple_list_layout.addWidget(self.payload_list_editor)
        self.payload_tabs.addTab(simple_list_widget, "Simple List")

        payloads_layout.addWidget(self.payload_tabs)
        config_layout.addWidget(payloads_group)

        # --- Right side: Attack Control and Results ---
        results_widget = QWidget()
        results_layout = QVBoxLayout(results_widget)

        # Attack Controls
        attack_controls_group = QGroupBox("Attack Controls")
        attack_controls_layout = QHBoxLayout(attack_controls_group)
        self.start_btn = QPushButton("Start Attack")
        self.stop_btn = QPushButton("Stop Attack")
        self.stop_btn.setEnabled(False)
        attack_controls_layout.addWidget(self.start_btn)
        attack_controls_layout.addWidget(self.stop_btn)
        results_layout.addWidget(attack_controls_group)

        # Results Table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels(["Position", "Payload", "Status", "Length", "Time (s)"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        results_layout.addWidget(self.results_table)

        main_layout.addWidget(config_widget, 1)
        main_layout.addWidget(results_widget, 2)

    def connect_signals(self):
        self.add_marker_btn.clicked.connect(self.add_injection_marker)
        self.start_btn.clicked.connect(self.start_attack)
        self.stop_btn.clicked.connect(self.stop_attack)

    def add_injection_marker(self):
        cursor = self.request_editor.textCursor()
        if cursor.hasSelection():
            # A more robust implementation would use a single, unique marker
            # and store the start/end positions. For now, this is simpler.
            selection = cursor.selectedText()
            cursor.insertText(f"§{selection}§")

    def start_attack(self):
        template = self.request_editor.toPlainText()
        if "§" not in template:
            # Simple validation
            return

        # A more robust implementation would parse all injection points.
        # We'll find the first one for this example.
        import re
        match = re.search(r"§(.*?)§", template)
        if not match:
            return

        injection_point = match.group(0)

        payloads = self.payload_list_editor.toPlainText().splitlines()
        if not payloads:
            return

        self.results_table.setRowCount(0)
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

        # The core logic assumes the template *is* the URL for now.
        # This is a major simplification for the UI design phase.
        simplified_template = template.replace(injection_point, injection_point)

        self.raider_manager = RaiderManager(simplified_template, [injection_point], payloads)
        self.raider_manager.request_completed.connect(self.add_result_to_table)
        self.raider_manager.fuzzing_finished.connect(self.fuzzing_finished)
        self.raider_manager.start()

    def stop_attack(self):
        if self.raider_manager:
            self.raider_manager.stop()
        self.stop_btn.setEnabled(False)

    @pyqtSlot(dict)
    def add_result_to_table(self, result):
        row_pos = self.results_table.rowCount()
        self.results_table.insertRow(row_pos)
        self.results_table.setItem(row_pos, 0, QTableWidgetItem(str(result["position"])))
        self.results_table.setItem(row_pos, 1, QTableWidgetItem(result["payload"]))
        self.results_table.setItem(row_pos, 2, QTableWidgetItem(str(result["status"])))
        self.results_table.setItem(row_pos, 3, QTableWidgetItem(str(result["length"])))
        self.results_table.setItem(row_pos, 4, QTableWidgetItem(f"{result['time_sec']:.2f}"))

    @pyqtSlot()
    def fuzzing_finished(self):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.raider_manager = None

    def load_request(self, request_data):
        # This method will be called by other tabs (Proxy, Repeater)
        # For now, we just format the request as a raw string.
        # A full implementation would need to handle headers, body, etc.
        raw_request = f"{request_data['method']} {request_data['url']} HTTP/1.1\n"
        for key, value in request_data['headers'].items():
            raw_request += f"{key}: {value}\n"
        raw_request += "\n"
        if request_data['body']:
            raw_request += request_data['body']

        self.request_editor.setPlainText(raw_request)
