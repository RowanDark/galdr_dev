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

        # Built-in Lists Tab
        builtin_list_widget = QWidget()
        builtin_list_layout = QVBoxLayout(builtin_list_widget)
        self.builtin_payloads_list = QListWidget()
        builtin_list_layout.addWidget(self.builtin_payloads_list)
        self.payload_tabs.addTab(builtin_list_widget, "Built-in Lists")

        # AI Generated Tab
        ai_widget = QWidget()
        ai_layout = QVBoxLayout(ai_widget)
        ai_controls_layout = QHBoxLayout()
        ai_controls_layout.addWidget(QLabel("Vuln Type:"))
        self.ai_vuln_type_combo = QComboBox()
        self.ai_vuln_type_combo.addItems(["SQL Injection", "XSS", "Command Injection"])
        ai_controls_layout.addWidget(self.ai_vuln_type_combo)
        ai_controls_layout.addWidget(QLabel("Count:"))
        self.ai_payload_count_spin = QSpinBox()
        self.ai_payload_count_spin.setRange(5, 50)
        self.ai_payload_count_spin.setValue(10)
        ai_controls_layout.addWidget(self.ai_payload_count_spin)
        self.ai_generate_btn = QPushButton("Generate")
        ai_controls_layout.addWidget(self.ai_generate_btn)
        ai_layout.addLayout(ai_controls_layout)
        self.ai_payloads_editor = QTextEdit()
        self.ai_payloads_editor.setReadOnly(True)
        ai_layout.addWidget(self.ai_payloads_editor)
        self.payload_tabs.addTab(ai_widget, "AI Generated")

        payloads_layout.addWidget(self.payload_tabs)
        config_layout.addWidget(payloads_group)

        self.load_builtin_payload_lists()

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
        self.marker_positions += 1
        cursor = self.request_editor.textCursor()
        if cursor.hasSelection():
            selection = cursor.selectedText()
            cursor.insertText(f"§{self.marker_positions}§{selection}§{self.marker_positions}§")
        else:
            cursor.insertText(f"§{self.marker_positions}§")

    def clear_markers(self):
        text = self.request_editor.toPlainText()
        # This regex removes the §...§ markers but keeps the content between them.
        cleared_text = re.sub(r"§\d+§(.*?)§\d+§", r"\1", text)
        # This regex removes empty markers like §1§
        cleared_text = re.sub(r"§\d+§", "", cleared_text)
        self.request_editor.setPlainText(cleared_text)
        self.marker_positions = 0

    def load_builtin_payload_lists(self):
        """Loads the list of available payload files into the UI."""
        self.builtin_payloads_list.clear()
        available_lists = self.payload_manager.get_available_lists()
        self.builtin_payloads_list.addItems(available_lists)

    def start_attack(self):
        template = self.request_editor.toPlainText()
        if not re.search(r"§\d+§", template):
            # No numbered markers found, do nothing.
            return

        # For now, we only support a single payload list, which will be used
        # for all injection point sets (e.g., for Sniper and Battering Ram).
        payloads = []
        current_tab_index = self.payload_tabs.currentIndex()
        if self.payload_tabs.tabText(current_tab_index) == "Simple List":
            payloads = self.payload_list_editor.toPlainText().splitlines()
        elif self.payload_tabs.tabText(current_tab_index) == "Built-in Lists":
            selected_item = self.builtin_payloads_list.currentItem()
            if selected_item:
                list_name = selected_item.text()
                payloads = self.payload_manager.load_payload_list(list_name)
        elif self.payload_tabs.tabText(current_tab_index) == "AI Generated":
            payloads = self.ai_payloads_editor.toPlainText().splitlines()

        if not payloads:
            return

        # The payload dictionary maps position number to payload list.
        # For now, we assign the single list to key "1" for Sniper/Battering Ram.
        # A full UI would manage multiple lists for Pitchfork/Cluster Bomb.
        payload_dict = {"1": payloads}
        attack_type = self.attack_type_combo.currentText()

        self.results_table.setRowCount(0)
        self.marker_positions = 0 # Reset for the next time
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

        self.raider_manager = RaiderManager(template, payload_dict, attack_type)
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
