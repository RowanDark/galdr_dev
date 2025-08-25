from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QSplitter, QTabWidget, QTextEdit, QPushButton, QGroupBox, QLabel
)
from PyQt6.QtCore import Qt

class RaiderTab(QWidget):
    """
    UI Tab for the Raider (Fuzzer) tool.
    Allows for configuring and running customized fuzzing attacks.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout(self)

        # Top controls
        controls_layout = QHBoxLayout()
        self.start_attack_btn = QPushButton("Start Attack")
        self.stop_attack_btn = QPushButton("Stop Attack")
        self.stop_attack_btn.setEnabled(False)

        controls_layout.addWidget(self.start_attack_btn)
        controls_layout.addWidget(self.stop_attack_btn)
        controls_layout.addStretch()
        main_layout.addLayout(controls_layout)

        # Main vertical splitter
        v_splitter = QSplitter(Qt.Orientation.Vertical)

        # Top part of the UI (Request and Config)
        top_widget = QWidget()
        top_layout = QHBoxLayout(top_widget)

        h_splitter = QSplitter(Qt.Orientation.Horizontal)

        # Request Editor
        request_group = QGroupBox("Request")
        request_layout = QVBoxLayout(request_group)
        self.request_editor = QTextEdit()
        self.request_editor.setPlaceholderText("Paste raw HTTP request here. Mark injection points with $$")
        request_layout.addWidget(self.request_editor)
        h_splitter.addWidget(request_group)

        # Config and Payloads
        config_tabs = QTabWidget()

        # Payloads Tab
        payloads_widget = QWidget()
        payloads_layout = QVBoxLayout(payloads_widget)
        payloads_layout.addWidget(QLabel("Enter one payload per line:"))
        self.payloads_editor = QTextEdit()
        payloads_layout.addWidget(self.payloads_editor)
        config_tabs.addTab(payloads_widget, "Payloads")

        h_splitter.addWidget(config_tabs)
        h_splitter.setSizes([700, 300])

        top_layout.addWidget(h_splitter)
        v_splitter.addWidget(top_widget)

        # Results Table
        results_group = QGroupBox("Results")
        results_layout = QVBoxLayout(results_group)
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(6)
        self.results_table.setHorizontalHeaderLabels(["ID", "Payload", "Status", "Length", "Time (ms)", "Error"])
        results_layout.addWidget(self.results_table)
        v_splitter.addWidget(results_group)

        v_splitter.setSizes([400, 300])
        main_layout.addWidget(v_splitter)

        # Connect signals to placeholder methods
        # self.start_attack_btn.clicked.connect(self.start_attack)
        # self.stop_attack_btn.clicked.connect(self.stop_attack)

    def add_result_to_table(self, result):
        """Adds a result from the fuzzer engine to the results table."""
        row_position = self.results_table.rowCount()
        self.results_table.insertRow(row_position)

        self.results_table.setItem(row_position, 0, QTableWidgetItem(str(result['id'])))
        self.results_table.setItem(row_position, 1, QTableWidgetItem(result['payload']))
        self.results_table.setItem(row_position, 2, QTableWidgetItem(str(result['status'])))
        self.results_table.setItem(row_position, 3, QTableWidgetItem(str(result['length'])))
        self.results_table.setItem(row_position, 4, QTableWidgetItem(str(result['time'])))
        self.results_table.setItem(row_position, 5, QTableWidgetItem(result.get('error', '')))
