import shutil
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QTableWidget,
    QTableWidgetItem, QHeaderView, QTextEdit, QGroupBox, QFileDialog, QMessageBox
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from galdr.proxy.mitm_proxy import MitmProxy
from galdr.proxy import cert_utils
from galdr.proxy.intercept_manager import InterceptManager

from PyQt6.QtWidgets import QMenu, QSplitter, QTabWidget
from PyQt6.QtGui import QAction

class ProxyTab(QWidget):
    def __init__(self, repeater_tab, main_window, parent=None):
        super().__init__(parent)
        self.repeater_tab = repeater_tab
        self.main_window = main_window
        self.proxy_thread = None
        self.proxy_host = '127.0.0.1'
        self.proxy_port = 8080
        self.full_requests = [] # To store detailed request data
        self.intercept_manager = InterceptManager()
        self.intercepted_request_data = None # To hold the current intercepted request

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

        # Create sub-tabs for Intercept and History
        self.sub_tab_widget = QTabWidget()

        # Create Intercept Tab
        self.init_intercept_tab()

        # Create History Tab
        self.init_history_tab()

        layout.addWidget(self.sub_tab_widget)

    def init_intercept_tab(self):
        """Initializes the Intercept sub-tab UI."""
        intercept_widget = QWidget()
        layout = QVBoxLayout(intercept_widget)

        # Controls for interception
        intercept_controls_layout = QHBoxLayout()
        self.intercept_button = QPushButton("Intercept is OFF")
        self.intercept_button.setCheckable(True)
        self.intercept_button.clicked.connect(self.toggle_intercept_mode)
        intercept_controls_layout.addWidget(self.intercept_button)

        self.forward_button = QPushButton("Forward")
        self.forward_button.setEnabled(False)
        self.forward_button.clicked.connect(self.forward_request)
        intercept_controls_layout.addWidget(self.forward_button)

        self.drop_button = QPushButton("Drop")
        self.drop_button.setEnabled(False)
        self.drop_button.clicked.connect(self.drop_request)
        intercept_controls_layout.addWidget(self.drop_button)
        intercept_controls_layout.addStretch()
        layout.addLayout(intercept_controls_layout)

        # Splitter for request/response (though we only have request for now)
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Request editor
        req_group = QGroupBox("Intercepted Request")
        req_layout = QVBoxLayout(req_group)
        self.intercept_headers_text = QTextEdit()
        self.intercept_headers_text.setPlaceholderText("Request Headers...")
        self.intercept_headers_text.setReadOnly(False)
        req_layout.addWidget(self.intercept_headers_text)

        self.intercept_body_text = QTextEdit()
        self.intercept_body_text.setPlaceholderText("Request Body...")
        self.intercept_body_text.setReadOnly(False)
        req_layout.addWidget(self.intercept_body_text)

        splitter.addWidget(req_group)
        layout.addWidget(splitter)

        self.sub_tab_widget.addTab(intercept_widget, "Intercept")

    def init_history_tab(self):
        """Initializes the History sub-tab UI."""
        history_widget = QWidget()
        history_layout = QVBoxLayout(history_widget)

        self.history_table = QTableWidget()
        self.history_table.setColumnCount(5)
        self.history_table.setHorizontalHeaderLabels(["ID", "Method", "URL", "Status", "Size (Bytes)"])
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.history_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        self.history_table.setColumnWidth(0, 50)
        self.history_table.setColumnWidth(1, 80)
        self.history_table.setColumnWidth(3, 80)
        self.history_table.setColumnWidth(4, 100)

        self.history_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.history_table.customContextMenuRequested.connect(self.show_context_menu)

        history_layout.addWidget(self.history_table)
        self.sub_tab_widget.addTab(history_widget, "History")

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

    def toggle_intercept_mode(self, checked):
        """Toggles the interception status."""
        self.intercept_manager.toggle_intercept(checked)
        if checked:
            self.intercept_button.setText("Intercept is ON")
            self.intercept_button.setStyleSheet("background-color: #4CAF50; color: white;")
        else:
            self.intercept_button.setText("Intercept is OFF")
            self.intercept_button.setStyleSheet("") # Reset to default

    def handle_intercepted_request(self, request_data):
        """Populates the Intercept tab with data from a paused request."""
        self.intercepted_request_data = request_data # Store original request
        self.sub_tab_widget.setCurrentWidget(self.sub_tab_widget.widget(0)) # Switch to Intercept tab

        headers = "\n".join(f"{k}: {v}" for k, v in request_data.get('headers', {}).items())
        self.intercept_headers_text.setPlainText(headers)
        self.intercept_body_text.setPlainText(request_data.get('body', ''))

        self.forward_button.setEnabled(True)
        self.drop_button.setEnabled(True)

    def reset_intercept_ui(self):
        """Clears the intercept UI and disables buttons."""
        self.intercept_headers_text.clear()
        self.intercept_body_text.clear()
        self.forward_button.setEnabled(False)
        self.drop_button.setEnabled(False)
        self.intercepted_request_data = None

    def forward_request(self):
        """Unblocks the proxy to forward the request with potentially modified data."""
        if not self.intercepted_request_data:
            return

        # Parse headers from text area
        modified_headers = {}
        for line in self.intercept_headers_text.toPlainText().split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                modified_headers[key.strip()] = value.strip()

        modified_body = self.intercept_body_text.toPlainText()

        data_to_send = {
            'action': 'forward',
            'method': self.intercepted_request_data['method'],
            'url': self.intercepted_request_data['url'],
            'headers': modified_headers,
            'body': modified_body
        }
        self.intercept_manager.send_response_to_proxy(data_to_send)
        self.reset_intercept_ui()

    def drop_request(self):
        """Unblocks the proxy to drop the request."""
        self.intercept_manager.send_response_to_proxy({'action': 'drop'})
        self.reset_intercept_ui()

    def show_context_menu(self, position):
        """Show context menu on right-click."""
        if self.history_table.selectionModel().hasSelection():
            menu = QMenu()
            send_to_repeater_action = QAction("🔄 Send to Repeater", self)
            send_to_repeater_action.triggered.connect(self.send_to_repeater)
            menu.addAction(send_to_repeater_action)
            menu.exec(self.history_table.mapToGlobal(position))

    def send_to_repeater(self):
        """Send the selected request to the Repeater tab."""
        selected_rows = self.history_table.selectionModel().selectedRows()
        if not selected_rows:
            return

        # Get the index of the first selected row
        row_index = selected_rows[0].row()

        if 0 <= row_index < len(self.full_requests):
            request_data = self.full_requests[row_index]

            # The body in RepeaterTab expects a string, not bytes.
            # We already decoded it as 'latin-1' which is safe.
            repeater_data = {
                'method': request_data.get('method'),
                'url': request_data.get('url'),
                'headers': request_data.get('headers'),
                'body': request_data.get('body')
            }

            self.repeater_tab.load_request(repeater_data)
            self.main_window.tab_widget.setCurrentWidget(self.repeater_tab)

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
                self.full_requests.clear() # Clear detailed requests
                self.proxy_thread = MitmProxy(
                    host=self.proxy_host,
                    port=self.proxy_port,
                    intercept_manager=self.intercept_manager
                )
                self.proxy_thread.logger.request_logged.connect(self.add_log_entry)
                self.proxy_thread.logger.request_intercepted.connect(self.handle_intercepted_request)
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
        self.full_requests.append(log_data)

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
