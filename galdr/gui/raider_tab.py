import asyncio
import re
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget, QTableWidgetItem,
    QSplitter, QTabWidget, QTextEdit, QGroupBox, QLabel, QHeaderView, QListWidget,
    QComboBox, QSpinBox
)
from PyQt6.QtCore import Qt, pyqtSlot, QThread, pyqtSignal
from PyQt6.QtGui import QFont

from galdr.raider.raider_core import RaiderManager
from galdr.payloads.manager import PayloadManager

class AIPayloadGeneratorThread(QThread):
    payloads_ready = pyqtSignal(list)

    def __init__(self, ai_analyzer, context, vuln_type, count):
        super().__init__()
        self.ai_analyzer = ai_analyzer
        self.context = context
        self.vuln_type = vuln_type
        self.count = count

    def run(self):
        payloads = asyncio.run(
            self.ai_analyzer.generate_smart_payloads(self.context, self.vuln_type, self.count)
        )
        self.payloads_ready.emit(payloads)

class RaiderTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.raider_manager = None
        self.payload_manager = PayloadManager()
        self.ai_payload_thread = None
        self.marker_positions = 0
        self.payload_data = {}
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
        self.add_marker_btn = QPushButton("Add § Marker")
        self.clear_markers_btn = QPushButton("Clear Markers")
        ip_layout.addWidget(self.add_marker_btn)
        ip_layout.addWidget(self.clear_markers_btn)
        ip_layout.addStretch()
        request_layout.addLayout(ip_layout)
        config_layout.addWidget(request_group)

        # Payloads Configuration
        payloads_group = QGroupBox("Payload Sets")
        payloads_layout = QVBoxLayout(payloads_group)
        self.payload_sets_table = QTableWidget()
        self.payload_sets_table.setColumnCount(4)
        self.payload_sets_table.setHorizontalHeaderLabels(["Position", "Type", "Options", "Count"])
        self.payload_sets_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.payload_sets_table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.MinimumExpanding)
        payloads_layout.addWidget(self.payload_sets_table)
        config_layout.addWidget(payloads_group)

        # --- Right side: Attack Control and Results ---
        results_widget = QWidget()
        results_layout = QVBoxLayout(results_widget)

        # Attack Controls
        attack_controls_group = QGroupBox("Attack Controls")
        attack_controls_layout = QHBoxLayout(attack_controls_group)

        attack_controls_layout.addWidget(QLabel("Attack Type:"))
        self.attack_type_combo = QComboBox()
        self.attack_type_combo.addItems(["Sniper", "Battering Ram", "Pitchfork", "Cluster Bomb"])
        attack_controls_layout.addWidget(self.attack_type_combo)

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
        self.clear_markers_btn.clicked.connect(self.clear_markers)
        self.start_btn.clicked.connect(self.start_attack)
        self.stop_btn.clicked.connect(self.stop_attack)
        self.ai_generate_btn.clicked.connect(self.generate_ai_payloads)

    def generate_ai_payloads(self):
        if not self.main_window or not self.main_window.ai_analyzer:
            return

        context = self.request_editor.toPlainText()
        vuln_type = self.ai_vuln_type_combo.currentText()
        count = self.ai_payload_count_spin.value()

        self.ai_generate_btn.setText("Generating...")
        self.ai_generate_btn.setEnabled(False)

        self.ai_payload_thread = AIPayloadGeneratorThread(
            self.main_window.ai_analyzer, context, vuln_type, count
        )
        self.ai_payload_thread.payloads_ready.connect(self.on_ai_payloads_ready)
        self.ai_payload_thread.start()

    @pyqtSlot(list)
    def on_ai_payloads_ready(self, payloads):
        self.ai_payloads_editor.setPlainText("\n".join(payloads))
        self.ai_generate_btn.setText("Generate")
        self.ai_generate_btn.setEnabled(True)

    def add_injection_marker(self):
        # This simplified logic assumes markers are added in order.
        # A full implementation would need to parse the text to find the next available number.
        self.marker_positions += 1
        position = self.marker_positions

        cursor = self.request_editor.textCursor()
        # Use a non-enclosing marker for easier parsing
        cursor.insertText(f"§{position}§")

        self.add_payload_set_row(position)

    def clear_markers(self):
        text = self.request_editor.toPlainText()
        cleared_text = re.sub(r"§\d+§", "", text)
        self.request_editor.setPlainText(cleared_text)
        self.marker_positions = 0
        self.payload_sets_table.setRowCount(0)
        self.payload_data = {}

    def add_payload_set_row(self, position):
        row_position = self.payload_sets_table.rowCount()
        self.payload_sets_table.insertRow(row_position)

        # Position Number (static)
        pos_item = QTableWidgetItem(str(position))
        pos_item.setFlags(pos_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        self.payload_sets_table.setItem(row_position, 0, pos_item)

        # Type ComboBox
        type_combo = QComboBox()
        type_combo.addItems(["Simple List", "Built-in List"]) # AI later
        self.payload_sets_table.setCellWidget(row_position, 1, type_combo)

        # Options Button (placeholder)
        options_btn = QPushButton("Configure")
        self.payload_sets_table.setCellWidget(row_position, 2, options_btn)

        # Count Label (static)
        count_item = QTableWidgetItem("0")
        count_item.setFlags(count_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        self.payload_sets_table.setItem(row_position, 3, count_item)

        # Connect signals for this new row
        type_combo.currentIndexChanged.connect(
            lambda index, r=row_position, p=position: self.on_payload_type_changed(index, r, p)
        )
        # options_btn.clicked.connect(...) # To be implemented later

    def on_payload_type_changed(self, combo_index, table_row, position):
        # A simplified logic for now
        payload_type = self.payload_sets_table.cellWidget(table_row, 1).currentText()

        if payload_type == "Simple List":
            # In a full UI, a dialog would ask for the list. Here, we use a default.
            payloads = ["simple_payload_1", "simple_payload_2"]
            self.payload_data[str(position)] = payloads
        elif payload_type == "Built-in List":
            # Use the first available list as a default
            available_lists = self.payload_manager.get_available_lists()
            if available_lists:
                payloads = self.payload_manager.load_payload_list(available_lists[0])
                self.payload_data[str(position)] = payloads
            else:
                payloads = []

        self.payload_sets_table.item(table_row, 3).setText(str(len(payloads)))

    def load_builtin_payload_lists(self):
        """Loads the list of available payload files into the UI."""
        self.builtin_payloads_list.clear()
        available_lists = self.payload_manager.get_available_lists()
        self.builtin_payloads_list.addItems(available_lists)

    def start_attack(self):
        template = self.request_editor.toPlainText()
        if not re.search(r"§\d+§", template):
            return

        if not self.payload_data:
            # Add a message to the user here in a real app
            return

        attack_type = self.attack_type_combo.currentText()

        self.results_table.setRowCount(0)
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

        self.raider_manager = RaiderManager(template, self.payload_data, attack_type)
        self.raider_manager.request_completed.connect(self.add_result_to_table)
        self.raider_manager.fuzzing_finished.connect(self.fuzzing_finished)
        self.raider_manager.log_message.connect(self.log_message) # Connect log
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
