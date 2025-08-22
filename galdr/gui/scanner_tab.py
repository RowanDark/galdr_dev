from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QProgressBar, QTextEdit,
    QGroupBox, QLabel
)
from PyQt6.QtCore import QThread
from core.active_scanner import ActiveSecurityScanner

class ScannerThread(QThread):
    def __init__(self, scanner):
        super().__init__()
        self.scanner = scanner

    def run(self):
        self.scanner.run_scan()

    def stop(self):
        self.scanner.stop()

class ScannerTab(QWidget):
    def __init__(self, repeater_tab, main_window_ref):
        super().__init__()
        self.repeater_tab = repeater_tab
        self.main_window = main_window_ref
        self.scanner = None
        self.scanner_thread = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        # Control Panel
        control_group = QGroupBox("Active Scanner Controls")
        control_layout = QHBoxLayout()

        self.load_btn = QPushButton("Load from Repeater")
        self.load_btn.clicked.connect(self.load_request_from_repeater)
        control_layout.addWidget(self.load_btn)

        self.start_btn = QPushButton("Start Scan")
        self.start_btn.clicked.connect(self.start_scan)
        self.start_btn.setEnabled(False)
        control_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Stop Scan")
        self.stop_btn.clicked.connect(self.stop_scan)
        self.stop_btn.setEnabled(False)
        control_layout.addWidget(self.stop_btn)

        control_group.setLayout(control_layout)
        layout.addWidget(control_group)

        # Status
        status_group = QGroupBox("Scan Status")
        status_layout = QVBoxLayout()

        self.request_info_label = QLabel("No request loaded.")
        status_layout.addWidget(self.request_info_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        status_layout.addWidget(self.progress_bar)

        status_group.setLayout(status_layout)
        layout.addWidget(status_group)

        # Log Area
        log_group = QGroupBox("Scanner Log")
        log_layout = QVBoxLayout()
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        log_layout.addWidget(self.log_area)
        log_group.setLayout(log_layout)
        layout.addWidget(log_group)

        self.setLayout(layout)

    def load_request_from_repeater(self):
        # This is a simplified way to get the request.
        # A better implementation might use signals/slots or a shared model.

        url = self.repeater_tab.url_input.text()
        method = self.repeater_tab.method_combo.currentText()
        headers_text = self.repeater_tab.headers_editor.toPlainText()
        body = self.repeater_tab.body_editor.toPlainText()

        if not url:
            self.log_message("Repeater has no URL. Please load a request in the Repeater tab first.")
            return

        headers = {}
        for line in headers_text.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()

        request_data = {
            'url': url,
            'method': method,
            'headers': headers,
            'body': body
        }
        self.load_request(request_data, "Repeater")

    def load_request(self, request_data, source="Proxy"):
        self.base_request = request_data

        url = request_data['url']
        method = request_data['method']

        self.request_info_label.setText(f"Loaded: {method} {url}")
        self.log_message(f"Request loaded from {source}: {method} {url}")
        self.start_btn.setEnabled(True)

    def start_scan(self):
        if not hasattr(self, 'base_request'):
            self.log_message("No request loaded to scan.")
            return

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        self.log_area.clear()

        self.scanner = ActiveSecurityScanner(self.base_request)

        # Connect signals from the scanner to the UI
        self.scanner.finding_detected.connect(self.main_window.handle_security_finding)
        self.scanner.scan_progress.connect(self.update_progress)
        self.scanner.scan_finished.connect(self.scan_finished)
        self.scanner.log_message.connect(self.log_message)

        self.scanner_thread = ScannerThread(self.scanner)
        self.scanner_thread.start()

    def stop_scan(self):
        if self.scanner_thread and self.scanner_thread.isRunning():
            self.scanner_thread.stop()
            self.stop_btn.setText("Stopping...")
            self.stop_btn.setEnabled(False)

    def update_progress(self, value, total):
        if total > 0:
            self.progress_bar.setMaximum(total)
            self.progress_bar.setValue(value)

    def scan_finished(self):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setText("Stop Scan")
        self.log_message("Scan finished.")
        self.scanner_thread = None

    def log_message(self, message):
        self.log_area.append(message)
