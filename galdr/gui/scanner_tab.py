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

class ScannerTab(QWidget):
    def __init__(self, main_window, db, parent=None):
        super().__init__(parent)
        self.main_window = main_window # To access ai_analyzer
        self.db = db
        self.scanner_thread = None
        self.init_ui()

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
        self.check_boxes = {
            "SQL Injection": QCheckBox("SQL Injection"),
            "Cross-Site Scripting (XSS)": QCheckBox("Cross-Site Scripting (XSS)"),
            "Command Injection": QCheckBox("Command Injection"),
            "Server-Side Request Forgery (SSRF)": QCheckBox("Server-Side Request Forgery (SSRF)"),
            "Insecure Direct Object References (IDOR)": QCheckBox("Insecure Direct Object References (IDOR)"),
            "Username Enumeration": QCheckBox("Username Enumeration"),
        }

        # Add checkboxes to the layout
        row, col = 0, 0
        for text, checkbox in self.check_boxes.items():
            checkbox.setChecked(True) # Enable all by default
            config_layout.addWidget(checkbox, row, col)
            col += 1
            if col > 2: # 3 columns
                col = 0
                row += 1

        config_group.setLayout(config_layout)
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
        """Imports targets with query parameters from the crawler's results database."""
        if not self.db or not self.db.isOpen():
            QMessageBox.warning(self, "Database Error", "Database connection is not available.")
            return

        query = QSqlQuery(self.db)
        # Select unique URLs that contain a '?' indicating query parameters
        query_text = "SELECT DISTINCT url FROM results WHERE url LIKE '%?%'"

        if not query.exec(query_text):
            QMessageBox.warning(self, "Query Error", f"Failed to query results: {query.lastError().text()}")
            return

        urls = []
        static_extensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.ttf', '.eot']
        while query.next():
            url = query.value(0)
            # Basic filter to exclude common static files
            if not any(url.lower().endswith(ext) for ext in static_extensions):
                urls.append(url)

        if not urls:
            QMessageBox.information(self, "No Targets Found", "No URLs with query parameters found in the crawler results.")
            return

        self.targets_text.setPlainText("\n".join(urls))
        QMessageBox.information(self, "Import Complete", f"Successfully imported {len(urls)} targets from the crawler results.")

    def start_scan(self):
        """Starts the active scanner thread."""
        targets = self.targets_text.toPlainText().strip().split('\n')
        targets = [t.strip() for t in targets if t.strip()]

        if not targets:
            print("No targets to scan.")
            return

        self.results_table.setRowCount(0) # Clear previous results
        self.start_scan_button.setEnabled(False)
        self.stop_scan_button.setEnabled(True)

        ai_mode = self.ai_smart_scan_check.isChecked()

        # Build the list of enabled checks from the UI
        check_class_map = {
            "SQL Injection": SqliCheck,
            "Cross-Site Scripting (XSS)": XssCheck,
            "Command Injection": CommandInjectionCheck,
            "Server-Side Request Forgery (SSRF)": SsrfCheck,
            "Insecure Direct Object References (IDOR)": IdorCheck,
            "Username Enumeration": UsernameEnumCheck,
        }

        enabled_checks = []
        for text, checkbox in self.check_boxes.items():
            if checkbox.isChecked():
                enabled_checks.append(check_class_map[text])

        if not enabled_checks:
            QMessageBox.warning(self, "No Checks Selected", "Please select at least one vulnerability check to run.")
            self.start_scan_button.setEnabled(True)
            self.stop_scan_button.setEnabled(False)
            return

        self.scanner_thread = ActiveScanner(
            targets=targets,
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
