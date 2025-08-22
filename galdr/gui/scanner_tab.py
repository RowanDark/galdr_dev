import json
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QTableWidget,
    QTableWidgetItem, QHeaderView, QGroupBox, QTextEdit, QMessageBox,
    QGridLayout, QCheckBox
)
from PyQt6.QtSql import QSqlQuery
from galdr.scanner.active_scanner import ActiveScanner
from galdr.scanner.checks.sqli_check import SqliCheck
from galdr.scanner.checks.xss_check import XssCheck
from galdr.scanner.checks.command_injection_check import CommandInjectionCheck
from galdr.scanner.checks.ssrf_check import SsrfCheck
from galdr.scanner.checks.idor_check import IdorCheck
from galdr.scanner.checks.username_enum_check import UsernameEnumCheck
from galdr.scanner.checks.xxe_check import XxeCheck
from galdr.scanner.checks.deserialization_check import DeserializationCheck

class ScannerTab(QWidget):
    def __init__(self, main_window, db, plugin_manager, parent=None):
        super().__init__(parent)
        self.main_window = main_window
        self.db = db
        self.plugin_manager = plugin_manager
        self.scanner_thread = None
        self.imported_requests = []
        self.check_class_map = {}
        self.init_ui()
        self.load_plugin_checks()

    def init_ui(self):
        """Initialize the UI for the Active Scanner tab."""
        layout = QVBoxLayout(self)

        # Controls
        controls_group = QGroupBox("Scan Controls")
        controls_layout = QHBoxLayout()

        self.import_targets_button = QPushButton("📥 Import from Crawler")
        self.import_targets_button.clicked.connect(self.import_targets)
        controls_layout.addWidget(self.import_targets_button)

        self.start_scan_button = QPushButton("🚀 Start Scan")
        self.start_scan_button.clicked.connect(self.start_scan)
        controls_layout.addWidget(self.start_scan_button)

        self.stop_scan_button = QPushButton("⏹️ Stop Scan")
        self.stop_scan_button.setEnabled(False)
        # self.stop_scan_button.clicked.connect(self.stop_scan)
        controls_layout.addWidget(self.stop_scan_button)

        controls_layout.addStretch()

        self.ai_smart_scan_check = QCheckBox("Enable AI Smart Payloads")
        controls_layout.addWidget(self.ai_smart_scan_check)

        controls_group.setLayout(controls_layout)
        layout.addWidget(controls_group)

        # Scan Configuration
        config_group = QGroupBox("Scan Configuration")
        config_layout = QGridLayout()

        # A mapping from checkbox to the check class
        self.check_boxes = {}

        # Built-in checks
        self.check_class_map = {
            "SQL Injection": SqliCheck,
            "Cross-Site Scripting (XSS)": XssCheck,
            "Command Injection": CommandInjectionCheck,
            "Server-Side Request Forgery (SSRF)": SsrfCheck,
            "XML External Entity (XXE)": XxeCheck,
            "Insecure Deserialization": DeserializationCheck,
            "Insecure Direct Object References (IDOR)": IdorCheck,
            "Username Enumeration": UsernameEnumCheck,
        }

        # Create checkboxes for built-in checks
        for name in self.check_class_map.keys():
            self.check_boxes[name] = QCheckBox(name)
            self.check_boxes[name].setChecked(True)

        # Add checkboxes to the layout
        self.config_layout = QGridLayout()
        row, col = 0, 0
        for checkbox in self.check_boxes.values():
            self.config_layout.addWidget(checkbox, row, col)
            col += 1
            if col > 2: # 3 columns
                col = 0
                row += 1

        config_group.setLayout(self.config_layout)
        layout.addWidget(config_group)

        # Targets Area
        targets_group = QGroupBox("Targets (one per line)")
        targets_layout = QVBoxLayout()
        self.targets_text = QTextEdit()
        self.targets_text.setPlaceholderText("http://example.com/page?id=1\nhttp://example.com/search?q=test")
        targets_layout.addWidget(self.targets_text)
        targets_group.setLayout(targets_layout)
        layout.addWidget(targets_group)

        # Results Table
        results_group = QGroupBox("Vulnerability Findings")
        results_layout = QVBoxLayout()
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(["URL", "Vulnerability Type", "Parameter", "Severity"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        results_layout.addWidget(self.results_table)
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)

        self.setLayout(layout)

    def import_targets(self):
        """Imports full requests from the crawler's results database."""
        if not self.db or not self.db.isOpen():
            QMessageBox.warning(self, "Database Error", "Database connection is not available.")
            return

        query = QSqlQuery(self.db)
        query_text = "SELECT url, method, request_headers, request_body FROM results WHERE url LIKE '%?%'"

        if not query.exec(query_text):
            QMessageBox.warning(self, "Query Error", f"Failed to query results: {query.lastError().text()}")
            return

        self.imported_requests = []
        urls_for_display = []
        while query.next():
            request_data = {
                "url": query.value(0),
                "method": query.value(1),
                "headers": json.loads(query.value(2) or '{}'),
                "body": query.value(3)
            }
            # Basic filter to exclude common static files
            if not any(request_data["url"].lower().endswith(ext) for ext in ['.css', '.js', '.png', '.jpg']):
                self.imported_requests.append(request_data)
                urls_for_display.append(request_data["url"])

        if not self.imported_requests:
            QMessageBox.information(self, "No Targets Found", "No scannable targets found in the crawler results.")
            return

        self.targets_text.setPlainText("\n".join(urls_for_display))
        QMessageBox.information(self, "Import Complete", f"Successfully imported {len(self.imported_requests)} requests as targets.")

    def start_scan(self):
        """Starts the active scanner thread with the imported requests."""
        if not self.imported_requests:
            QMessageBox.warning(self, "No Targets", "Please import targets from the crawler before starting a scan.")
            return

        self.results_table.setRowCount(0)
        self.start_scan_button.setEnabled(False)
        self.stop_scan_button.setEnabled(True)

        ai_mode = self.ai_smart_scan_check.isChecked()

        enabled_checks = [self.check_class_map[text] for text, cb in self.check_boxes.items() if cb.isChecked()]

        if not enabled_checks:
            QMessageBox.warning(self, "No Checks Selected", "Please select at least one vulnerability check to run.")
            self.start_scan_button.setEnabled(True)
            self.stop_scan_button.setEnabled(False)
            return

        self.scanner_thread = ActiveScanner(
            request_data_list=self.imported_requests,
            enabled_checks=enabled_checks,
            ai_mode=ai_mode,
            ai_analyzer=self.main_window.ai_analyzer
        )
        self.scanner_thread.vulnerability_found.connect(self.add_finding_to_table)
        self.scanner_thread.scan_finished.connect(self.scan_finished)
        self.scanner_thread.start()

    def scan_finished(self, count):
        """Called when the scan is finished."""
        print(f"GUI: Scan finished, {count} findings.")
        self.start_scan_button.setEnabled(True)
        self.stop_scan_button.setEnabled(False)

    def add_finding_to_table(self, finding):
        """Adds a new vulnerability finding to the results table."""
        row_position = self.results_table.rowCount()
        self.results_table.insertRow(row_position)

        self.results_table.setItem(row_position, 0, QTableWidgetItem(finding.url))
        self.results_table.setItem(row_position, 1, QTableWidgetItem(finding.check_name))
        self.results_table.setItem(row_position, 2, QTableWidgetItem(finding.parameter))
        self.results_table.setItem(row_position, 3, QTableWidgetItem(finding.severity))

    def load_plugin_checks(self):
        """Loads scanner checks from plugins and adds them to the UI."""
        plugin_checks = self.plugin_manager.get_scanner_checks()
        if not plugin_checks:
            return

        row, col = len(self.check_boxes) % 3, len(self.check_boxes) // 3

        for check_class in plugin_checks:
            # We need a name for the check. Let's assume the class has a 'name' attribute.
            check_name = getattr(check_class, 'name', check_class.__name__)

            if check_name in self.check_class_map:
                print(f"Warning: Scanner check '{check_name}' from plugin conflicts with an existing check. Skipping.")
                continue

            self.check_class_map[check_name] = check_class
            checkbox = QCheckBox(f"🔌 {check_name}")
            checkbox.setChecked(True)
            self.check_boxes[check_name] = checkbox

            self.config_layout.addWidget(checkbox, row, col)
            col += 1
            if col > 2:
                col = 0
                row += 1

    def add_target_request(self, request_data):
        """Adds a single request to the scanner queue from an external source like the crawler."""
        # Filter out static files and check for duplicates
        url = request_data.get("url", "")
        if not any(url.lower().endswith(ext) for ext in ['.css', '.js', '.png', '.jpg', '.gif']) and '?' in url:
            # Check if this exact URL is already in our list for display
            existing_urls = self.targets_text.toPlainText().split('\n')
            if url not in existing_urls:
                self.imported_requests.append(request_data)
                self.targets_text.append(url)
