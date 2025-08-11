from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QTableWidget,
    QTableWidgetItem, QHeaderView, QGroupBox, QTextEdit
)
from galdr.scanner.active_scanner import ActiveScanner

class ScannerTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
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

        controls_group.setLayout(controls_layout)
        layout.addWidget(controls_group)

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
        """Placeholder for importing targets from the crawler."""
        # For now, just add a dummy target
        dummy_targets = [
            "http://testphp.vulnweb.com/listproducts.php?cat=1",
            "http://testphp.vulnweb.com/search.php?test=query"
        ]
        self.targets_text.setPlainText("\n".join(dummy_targets))

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

        self.scanner_thread = ActiveScanner(targets)
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
