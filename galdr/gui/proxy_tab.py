import shutil
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QTableWidget,
    QTableWidgetItem, QHeaderView, QTextEdit, QGroupBox, QFileDialog, QMessageBox
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from galdr.proxy.mitm_proxy import MitmProxy
from galdr.proxy import cert_utils

class ProxyTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.proxy_thread = None
        self.proxy_host = '127.0.0.1'
        self.proxy_port = 8080

        # Ensure CA certificate exists before UI is initialized
        cert_utils.get_ca_certificate()

        self.init_ui()

    def init_ui(self):
        """Initialize the UI for the Proxy tab."""
        layout = QVBoxLayout(self)

        # 1. Controls Group
        controls_group = QGroupBox("Proxy Controls")
        controls_layout = QHBoxLayout()

        self.proxy_button = QPushButton("🚀 Start Proxy")
        self.proxy_button.setCheckable(True)
        self.proxy_button.clicked.connect(self.toggle_proxy)
        controls_layout.addWidget(self.proxy_button)

        self.proxy_status_label = QLabel(f"Status: Inactive")
        self.proxy_status_label.setStyleSheet("padding: 5px; border-radius: 3px;")
        controls_layout.addWidget(self.proxy_status_label)

        controls_layout.addStretch()

        self.export_ca_button = QPushButton("📜 Export Galdr CA")
        self.export_ca_button.clicked.connect(self.export_ca_cert)
        controls_layout.addWidget(self.export_ca_button)

        controls_group.setLayout(controls_layout)
        layout.addWidget(controls_group)

        # 2. History Table
        history_group = QGroupBox("Intercepted Traffic")
        history_layout = QVBoxLayout()

        self.history_table = QTableWidget()
        self.history_table.setColumnCount(5)
        self.history_table.setHorizontalHeaderLabels(["ID", "Method", "URL", "Status", "Size (Bytes)"])
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.history_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        self.history_table.setColumnWidth(0, 50)
        self.history_table.setColumnWidth(1, 80)
        self.history_table.setColumnWidth(3, 80)
        self.history_table.setColumnWidth(4, 100)

        history_layout.addWidget(self.history_table)
        history_group.setLayout(history_layout)
        layout.addWidget(history_group)

        # 3. Instructions Group
        instructions_group = QGroupBox("How to Use")
        instructions_layout = QVBoxLayout()

        instructions_text = QTextEdit()
        instructions_text.setReadOnly(True)
        instructions_text.setFont(QFont("Courier", 9))
        instructions_text.setHtml(f"""
            <p><b>To intercept HTTPS traffic, you must first install the Galdr CA certificate in your browser.</b></p>
            <ol>
                <li>Click the <b>'Export Galdr CA'</b> button above and save the `galdr_ca.pem` file.</li>
                <li>Go to your browser's settings, find the certificate manager (usually under Security or Privacy), and import the `galdr_ca.pem` file into the "Authorities" or "Trusted Root Certification Authorities" tab.</li>
                <li>Click the <b>'Start Proxy'</b> button.</li>
                <li>Configure your browser to use an HTTP proxy at <strong>{self.proxy_host}</strong> on port <strong>{self.proxy_port}</strong>.</li>
                <li>All HTTP and HTTPS traffic from your browser will now appear in the table.</li>
            </ol>
        """)
        instructions_layout.addWidget(instructions_text)
        instructions_group.setLayout(instructions_layout)
        layout.addWidget(instructions_group, 1) # Give less stretch to this

        self.setLayout(layout)

    def export_ca_cert(self):
        """Handle exporting the CA certificate."""
        default_path = str(cert_utils.CA_CERT_PATH.home() / "galdr_ca.pem")
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Galdr CA Certificate", default_path,
            "PEM Files (*.pem);;All Files (*)"
        )
        if filename:
            try:
                shutil.copy(cert_utils.CA_CERT_PATH, filename)
                QMessageBox.information(self, "Export Successful",
                                      f"Galdr CA certificate successfully exported to:\n{filename}")
            except Exception as e:
                QMessageBox.critical(self, "Export Failed", f"Could not export certificate: {e}")

    def toggle_proxy(self, checked):
        """Starts or stops the proxy server."""
        if checked:
            try:
                self.history_table.setRowCount(0) # Clear table on start
                self.proxy_thread = MitmProxy(host=self.proxy_host, port=self.proxy_port)
                self.proxy_thread.logger.request_logged.connect(self.add_log_entry)
                self.proxy_thread.start()
                self.proxy_button.setText("⏹️ Stop Proxy")
                self.proxy_status_label.setText(f"Status: Running on {self.proxy_host}:{self.proxy_port}")
                self.proxy_status_label.setStyleSheet("background-color: #4CAF50; color: white; padding: 5px; border-radius: 3px;")
            except Exception as e:
                self.proxy_status_label.setText(f"Status: Error - {e}")
                self.proxy_status_label.setStyleSheet("background-color: #D32F2F; color: white; padding: 5px; border-radius: 3px;")
                self.proxy_button.setChecked(False)
        else:
            if self.proxy_thread and self.proxy_thread.is_alive():
                self.proxy_thread.stop()
                self.proxy_thread.join(timeout=2)
                self.proxy_thread = None

            self.proxy_button.setText("🚀 Start Proxy")
            self.proxy_status_label.setText("Status: Inactive")
            self.proxy_status_label.setStyleSheet("background-color: #f44336; color: white; padding: 5px; border-radius: 3px;")

    def add_log_entry(self, log_data):
        """Adds a new request to the history table from a signal."""
        row_position = self.history_table.rowCount()
        self.history_table.insertRow(row_position)

        # Create items from dictionary
        id_item = QTableWidgetItem(str(row_position + 1))
        method_item = QTableWidgetItem(log_data.get('method', ''))
        url_item = QTableWidgetItem(log_data.get('url', ''))
        status_item = QTableWidgetItem(str(log_data.get('status', '')))
        size_item = QTableWidgetItem(str(log_data.get('size', '')))

        # Set alignment
        id_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        method_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        size_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        # Add to table
        self.history_table.setItem(row_position, 0, id_item)
        self.history_table.setItem(row_position, 1, method_item)
        self.history_table.setItem(row_position, 2, url_item)
        self.history_table.setItem(row_position, 3, status_item)
        self.history_table.setItem(row_position, 4, size_item)

        self.history_table.scrollToBottom()
