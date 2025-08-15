from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, QLineEdit,
    QPushButton, QTableWidget, QTableWidgetItem, QHeaderView,
    QSplitter, QGroupBox, QTabWidget, QComboBox, QFileDialog, QMessageBox,
    QSpinBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
import requests
import time
from concurrent.futures import ThreadPoolExecutor

# --- Backend Logic ---

class RaiderAttack(QThread):
    result_received = pyqtSignal(dict)
    attack_finished = pyqtSignal()

    def __init__(self, request_template, payloads, thread_count=10):
        super().__init__()
        self.request_template = request_template
        self.payloads = payloads
        self.thread_count = thread_count
        self.running = True

    def run(self):
        with ThreadPoolExecutor(max_workers=self.thread_count) as executor:
            request_id_counter = 0
            for payload in self.payloads:
                if not self.running:
                    break
                request_id_counter += 1
                executor.submit(self._send_request, request_id_counter, payload)

        self.attack_finished.emit()

    def _send_request(self, request_id, payload):
        if not self.running:
            return

        # Replace insertion points (marked with §) with the payload
        url = self.request_template['url'].replace("§", payload)
        headers = {k: v.replace("§", payload) for k, v in self.request_template['headers'].items()}
        body = self.request_template['body'].replace("§", payload)
        method = self.request_template['method']

        try:
            start_time = time.time()
            response = requests.request(
                method, url, headers=headers, data=body.encode('utf-8'),
                timeout=10, verify=False
            )
            elapsed_time = int((time.time() - start_time) * 1000)

            result = {
                'id': request_id, 'payload': payload, 'status': response.status_code,
                'length': len(response.content), 'time': elapsed_time, 'error': ''
            }
        except requests.RequestException as e:
            result = {
                'id': request_id, 'payload': payload, 'status': 0,
                'length': 0, 'time': 0, 'error': str(e)
            }

        self.result_received.emit(result)

    def stop(self):
        self.running = False

# --- Frontend UI ---

class RaiderTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.attack_thread = None
        self.init_ui()

    def init_ui(self):
        main_layout = QHBoxLayout(self)
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left Pane
        left_pane = QWidget()
        left_layout = QVBoxLayout(left_pane)
        request_group = self.create_request_group()
        payload_group = self.create_payload_group()
        attack_controls_group = self.create_attack_controls_group()
        left_layout.addWidget(request_group)
        left_layout.addWidget(payload_group)
        left_layout.addWidget(attack_controls_group)
        left_layout.addStretch()

        # Right Pane
        right_pane = QWidget()
        right_layout = QVBoxLayout(right_pane)
        results_group = QGroupBox("📊 Attack Results")
        results_layout = QVBoxLayout(results_group)
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(7)
        self.results_table.setHorizontalHeaderLabels(["ID", "Payload", "Status", "Length", "Time (ms)", "Errors", "Info"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        results_layout.addWidget(self.results_table)
        right_layout.addWidget(results_group)

        splitter.addWidget(left_pane)
        splitter.addWidget(right_pane)
        splitter.setSizes([500, 700])
        main_layout.addWidget(splitter)
        self.setLayout(main_layout)

    def create_request_group(self):
        group = QGroupBox("🎯 Target Request")
        layout = QVBoxLayout(group)
        url_layout = QHBoxLayout()
        self.method_combo = QComboBox()
        self.method_combo.addItems(['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
        url_layout.addWidget(self.method_combo)
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com/search?q=§fuzz§")
        url_layout.addWidget(self.url_input)
        layout.addLayout(url_layout)
        layout.addWidget(QLabel("📋 Headers:"))
        self.headers_editor = QTextEdit()
        self.headers_editor.setPlaceholderText("User-Agent: Galdr Raider")
        self.headers_editor.setFixedHeight(100)
        layout.addWidget(self.headers_editor)
        layout.addWidget(QLabel("📝 Request Body:"))
        self.body_editor = QTextEdit()
        self.body_editor.setPlaceholderText("{\"key\": \"§value§\"}")
        self.body_editor.setFixedHeight(100)
        layout.addWidget(self.body_editor)
        info_label = QLabel("Use the '§' character to mark insertion points for payloads.")
        info_label.setStyleSheet("color: #aaa; font-size: 11px;")
        layout.addWidget(info_label)
        return group

    def create_payload_group(self):
        group = QGroupBox("💣 Payloads")
        layout = QVBoxLayout(group)
        self.payload_tabs = QTabWidget()

        # Simple List Tab
        simple_list_tab = QWidget()
        simple_list_layout = QVBoxLayout(simple_list_tab)
        self.simple_payload_list = QTextEdit()
        self.simple_payload_list.setPlaceholderText("payload1\npayload2\npayload3")
        simple_list_layout.addWidget(self.simple_payload_list)
        self.payload_tabs.addTab(simple_list_tab, "Simple List")

        # Wordlist Tab
        wordlist_tab = QWidget()
        wordlist_layout = QHBoxLayout(wordlist_tab)
        self.wordlist_path_label = QLabel("No file selected.")
        self.wordlist_select_btn = QPushButton("📂 Select File")
        self.wordlist_select_btn.clicked.connect(self.select_wordlist_file)
        wordlist_layout.addWidget(self.wordlist_path_label)
        wordlist_layout.addWidget(self.wordlist_select_btn)
        self.payload_tabs.addTab(wordlist_tab, "Wordlist")

        # AI Payloads Tab
        ai_tab = QWidget()
        ai_layout = QFormLayout(ai_tab)
        self.ai_payloads_enabled = QCheckBox("Enable AI-Generated Payloads")
        self.ai_payload_type = QComboBox()
        self.ai_payload_type.addItems(['SQLi', 'XSS', 'Command Injection', 'Generic Fuzz'])
        ai_layout.addRow(self.ai_payloads_enabled)
        ai_layout.addRow("Payload Type:", self.ai_payload_type)
        self.payload_tabs.addTab(ai_tab, "🤖 AI Payloads")

        layout.addWidget(self.payload_tabs)
        return group

    def create_attack_controls_group(self):
        group = QGroupBox("⚙️ Attack Controls")
        layout = QHBoxLayout(group)
        self.start_attack_btn = QPushButton("🚀 Start Attack")
        self.start_attack_btn.clicked.connect(self.start_attack)
        self.stop_attack_btn = QPushButton("⏹️ Stop Attack")
        self.stop_attack_btn.clicked.connect(self.stop_attack)
        self.stop_attack_btn.setEnabled(False)
        layout.addWidget(self.start_attack_btn)
        layout.addWidget(self.stop_attack_btn)
        return group

    def select_wordlist_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Wordlist", "", "Text Files (*.txt);;All Files (*)")
        if file_path:
            self.wordlist_path_label.setText(file_path)

    def start_attack(self):
        if self.attack_thread and self.attack_thread.isRunning():
            return

        # 1. Gather request template
        headers = {}
        for line in self.headers_editor.toPlainText().split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()

        request_template = {
            'method': self.method_combo.currentText(),
            'url': self.url_input.text(),
            'headers': headers,
            'body': self.body_editor.toPlainText()
        }

        # 2. Gather payloads
        payloads = self.get_payloads()
        if not payloads:
            QMessageBox.warning(self, "No Payloads", "Please provide a list of payloads.")
            return

        # 3. Clear results and start attack
        self.results_table.setRowCount(0)
        self.start_attack_btn.setEnabled(False)
        self.stop_attack_btn.setEnabled(True)

        self.attack_thread = RaiderAttack(request_template, payloads)
        self.attack_thread.result_received.connect(self.update_results_table)
        self.attack_thread.finished.connect(self.finish_attack)
        self.attack_thread.start()

    def get_payloads(self):
        current_tab_index = self.payload_tabs.currentIndex()
        if current_tab_index == 0: # Simple List
            return [p.strip() for p in self.simple_payload_list.toPlainText().split('\n') if p.strip()]
        elif current_tab_index == 1: # Wordlist
            file_path = self.wordlist_path_label.text()
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    return [line.strip() for line in f if line.strip()]
            else:
                return []
        # AI payload logic would go here
        return []

    def update_results_table(self, result):
        row_position = self.results_table.rowCount()
        self.results_table.insertRow(row_position)
        self.results_table.setItem(row_position, 0, QTableWidgetItem(str(result['id'])))
        self.results_table.setItem(row_position, 1, QTableWidgetItem(result['payload']))
        self.results_table.setItem(row_position, 2, QTableWidgetItem(str(result['status'])))
        self.results_table.setItem(row_position, 3, QTableWidgetItem(str(result['length'])))
        self.results_table.setItem(row_position, 4, QTableWidgetItem(str(result['time'])))
        self.results_table.setItem(row_position, 5, QTableWidgetItem(result['error']))
        self.results_table.scrollToBottom()

    def stop_attack(self):
        if self.attack_thread and self.attack_thread.isRunning():
            self.attack_thread.stop()
            self.stop_attack_btn.setText("Stopping...")
            self.stop_attack_btn.setEnabled(False)

    def finish_attack(self):
        self.start_attack_btn.setEnabled(True)
        self.stop_attack_btn.setEnabled(False)
        self.stop_attack_btn.setText("⏹️ Stop Attack")
        QMessageBox.information(self, "Attack Finished", "The Raider attack has completed.")
        self.attack_thread = None
