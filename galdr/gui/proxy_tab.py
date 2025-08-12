import shutil
import asyncio
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QTableWidget,
    QTableWidgetItem, QHeaderView, QTextEdit, QGroupBox, QFileDialog, QMessageBox,
    QSplitter, QTabWidget, QCheckBox, QMenu
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QAction
import subprocess
import os
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from urllib import request, error
import socket

# --- New CommandServer using http.server ---
class _HttpRequestHandler(BaseHTTPRequestHandler):
    """Handles incoming HTTP POST requests from the mitmproxy addon."""
    def do_POST(self):
        if self.path == '/event':
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                event = json.loads(post_data.decode('utf-8'))

                # Emit the signal via the server instance
                if hasattr(self.server, 'event_emitter'):
                    self.server.event_emitter.emit(event)

                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'OK')
            except Exception as e:
                print(f"Error processing POST request in CommandServer: {e}")
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b'Error')
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not Found')

    def log_message(self, format, *args):
        # Suppress logging to keep the console clean
        return

class CommandServer(QThread):
    """An HTTP server in a QThread to receive events from the mitmproxy addon."""
    event_received = pyqtSignal(dict)

    def __init__(self, host='127.0.0.1', port=8082, parent=None):
        super().__init__(parent)
        self.host = host
        self.port = port
        self.httpd = None

    def run(self):
        try:
            self.httpd = HTTPServer((self.host, self.port), _HttpRequestHandler)
            # Attach the signal emitter to the server instance so the handler can access it
            self.httpd.event_emitter = self.event_received
            print(f"Event server listening on http://{self.host}:{self.port}")
            self.httpd.serve_forever()
        except Exception as e:
            # It's possible the port is already in use.
            print(f"Could not start command server: {e}")

    def stop(self):
        if self.httpd:
            print("Stopping event server...")
            # shutdown must be called from a different thread
            # which is why running the server in a QThread is perfect.
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None
            print("Event server stopped.")


class ProxyTab(QWidget):
    def __init__(self, repeater_tab, main_window, parent=None):
        super().__init__(parent)
        self.repeater_tab = repeater_tab
        self.main_window = main_window
        self.proxy_process = None
        self.proxy_host = '127.0.0.1'
        self.proxy_port = 8080
        self.event_server_port = 8082  # Port for receiving events from addon
        self.addon_command_port = 8083 # Port for sending commands to addon

        self.full_requests = [] # To store detailed request data
        self.intercepted_flow_id = None # To hold the current intercepted flow ID
        self.intercepting_response = False # Flag to track if we are intercepting a response
        self.intercepted_request_data = None # Store request data during response intercept

        # --- New server-based communication ---
        self.event_server = CommandServer(port=self.event_server_port)
        self.event_server.event_received.connect(self._handle_event)
        # For sending non-blocking HTTP requests to the addon
        self.command_executor = ThreadPoolExecutor(max_workers=2)

        self.init_ui()

    def init_ui(self):
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

        self.sub_tab_widget = QTabWidget()
        self.init_intercept_tab()
        self.init_history_tab()
        layout.addWidget(self.sub_tab_widget)

        # Instructions Group
        instructions_group = QGroupBox("How to Use")
        instructions_layout = QVBoxLayout()
        instructions_text = QTextEdit()
        instructions_text.setReadOnly(True)
        instructions_text.setFont(QFont("Courier", 9))
        instructions_text.setHtml(f"""
            <p><b>To intercept HTTPS traffic, you must first install the Galdr CA certificate.</b></p>
            <ol>
                <li>Click <b>'Start Proxy'</b> once to generate the certificate file. Then stop it.</li>
                <li>Click <b>'Export Galdr CA'</b> and save the `galdr_ca.pem` file.</li>
                <li>Go to your browser's settings, find the certificate manager (usually under Security or Privacy), and import the `galdr_ca.pem` file into the "Authorities" or "Trusted Root Certification Authorities" tab.</li>
                <li>Click <b>'Start Proxy'</b> again.</li>
                <li>Configure your browser to use an HTTP proxy at <strong>{self.proxy_host}</strong> on port <strong>{self.proxy_port}</strong>.</li>
            </ol>
        """)
        instructions_layout.addWidget(instructions_text)
        instructions_group.setLayout(instructions_layout)
        layout.addWidget(instructions_group, 1)

        self.setLayout(layout)

    def init_intercept_tab(self):
        intercept_widget = QWidget()
        layout = QVBoxLayout(intercept_widget)

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

        self.analyze_ai_button = QPushButton("🤖 Analyze with AI")
        self.analyze_ai_button.setEnabled(False)
        self.analyze_ai_button.clicked.connect(self.analyze_with_ai)
        intercept_controls_layout.addWidget(self.analyze_ai_button)

        self.intercept_response_check = QCheckBox("Intercept Responses")
        self.intercept_response_check.clicked.connect(self.toggle_response_intercept_mode)
        intercept_controls_layout.addWidget(self.intercept_response_check)

        layout.addLayout(intercept_controls_layout)

        splitter = QSplitter(Qt.Orientation.Vertical)

        req_group = QGroupBox("Intercepted Request")
        req_layout = QVBoxLayout(req_group)
        self.intercept_headers_text = QTextEdit()
        self.intercept_headers_text.setPlaceholderText("Request Headers...")
        req_layout.addWidget(self.intercept_headers_text)
        self.intercept_body_text = QTextEdit()
        self.intercept_body_text.setPlaceholderText("Request Body...")
        req_layout.addWidget(self.intercept_body_text)
        splitter.addWidget(req_group)

        resp_group = QGroupBox("Intercepted Response")
        resp_layout = QVBoxLayout(resp_group)
        self.intercept_resp_headers_text = QTextEdit()
        self.intercept_resp_headers_text.setPlaceholderText("Response Headers...")
        resp_layout.addWidget(self.intercept_resp_headers_text)
        self.intercept_resp_body_text = QTextEdit()
        self.intercept_resp_body_text.setPlaceholderText("Response Body...")
        resp_layout.addWidget(self.intercept_resp_body_text)
        splitter.addWidget(resp_group)

        layout.addWidget(splitter)
        self.sub_tab_widget.addTab(intercept_widget, "Intercept")

    def init_history_tab(self):
        history_widget = QWidget()
        history_layout = QVBoxLayout(history_widget)

        self.history_table = QTableWidget()
        self.history_table.setColumnCount(5)
        self.history_table.setHorizontalHeaderLabels(["ID", "Method", "URL", "Status", "Size (Bytes)"])
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.history_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        self.history_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.history_table.customContextMenuRequested.connect(self.show_context_menu)

        history_layout.addWidget(self.history_table)
        self.sub_tab_widget.addTab(history_widget, "History")

    def _send_state_update_to_addon(self):
        """Sends the current interception state to the mitmproxy addon."""
        state = {
            'intercept_requests': self.intercept_button.isChecked(),
            'intercept_responses': self.intercept_response_check.isChecked()
        }
        command = {"action": "update_state", "data": state}
        self._send_command_to_addon(command)

    def toggle_intercept_mode(self, checked):
        """Toggles request interception and notifies the addon."""
        self._send_state_update_to_addon()
        if checked:
            self.intercept_button.setText("Intercept is ON")
            self.intercept_button.setStyleSheet("background-color: #4CAF50; color: white;")
        else:
            self.intercept_button.setText("Intercept is OFF")
            self.intercept_button.setStyleSheet("")

    def toggle_response_intercept_mode(self, checked):
        """Toggles response interception and notifies the addon."""
        self._send_state_update_to_addon()

    def _handle_event(self, event: dict):
        """Processes an event received from the CommandServer."""
        try:
            event_type = event.get("type")
            data = event.get("data")

            if event_type == "flow_log":
                self.add_log_entry(data)
            elif event_type == "request_intercepted":
                self.handle_intercepted_request(data)
            elif event_type == "response_intercepted":
                self.handle_intercepted_response(data)
        except Exception as e:
            print(f"Error handling event: {e}")

    def handle_intercepted_request(self, request_data):
        self.intercepted_flow_id = request_data.get('flow_id')
        self.intercepting_response = False
        self.sub_tab_widget.setCurrentWidget(self.sub_tab_widget.widget(0))

        headers = "\n".join(f"{k}: {v}" for k, v in request_data.get('headers', {}).items())
        self.intercept_headers_text.setPlainText(headers)
        self.intercept_body_text.setPlainText(request_data.get('body', ''))

        self.intercept_resp_headers_text.clear()
        self.intercept_resp_body_text.clear()

        self.forward_button.setEnabled(True)
        self.drop_button.setEnabled(True)
        self.analyze_ai_button.setEnabled(True)

    def handle_intercepted_response(self, response_data):
        self.intercepted_flow_id = response_data.get('flow_id')
        self.intercepting_response = True
        self.intercepted_request_data = response_data # Store for status code

        status_line = f"HTTP/1.1 {response_data.get('status_code', 200)} OK"
        headers = status_line + "\n" + "\n".join(f"{k}: {v}" for k, v in response_data.get('headers', {}).items())
        self.intercept_resp_headers_text.setPlainText(headers)
        self.intercept_resp_body_text.setPlainText(response_data.get('body', ''))

        self.forward_button.setEnabled(True)
        self.drop_button.setEnabled(True)
        self.analyze_ai_button.setEnabled(True)

    def reset_intercept_ui(self):
        self.intercept_headers_text.clear()
        self.intercept_body_text.clear()
        self.intercept_resp_headers_text.clear()
        self.intercept_resp_body_text.clear()
        self.forward_button.setEnabled(False)
        self.drop_button.setEnabled(False)
        self.analyze_ai_button.setEnabled(False)
        self.intercepted_flow_id = None
        self.intercepting_response = False
        self.intercepted_request_data = None

    def _send_command_to_addon(self, command: dict):
        """Sends a command to the mitmproxy addon via an HTTP POST request in a background thread."""
        def task():
            try:
                url = f"http://{self.proxy_host}:{self.addon_command_port}/command"
                data = json.dumps(command).encode('utf-8')
                req = request.Request(url, data=data, headers={'Content-Type': 'application/json'})
                with request.urlopen(req, timeout=2):
                    pass # Don't need response
            except (error.URLError, socket.timeout):
                # This is expected if the proxy isn't running or is starting up.
                pass
            except Exception as e:
                print(f"Error sending command to addon: {e}")

        self.command_executor.submit(task)

    def forward_request(self):
        if not self.intercepted_flow_id:
            return

        command = {"flow_id": self.intercepted_flow_id, "action": "forward"}

        if self.intercepting_response:
            modified_headers = {}
            header_lines = self.intercept_resp_headers_text.toPlainText().split('\n')
            # First line is status, handle it separately
            status_line = header_lines[0] if header_lines else ''
            try:
                status_code = int(status_line.split(' ')[1])
            except (IndexError, ValueError):
                status_code = self.intercepted_request_data.get('status_code', 200)

            for line in header_lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    modified_headers[key.strip()] = value.strip()

            command['data'] = {
                'response': {
                    'headers': modified_headers,
                    'body': self.intercept_resp_body_text.toPlainText(),
                    'status_code': status_code
                }
            }
        else: # Forwarding a request
            modified_headers = {}
            for line in self.intercept_headers_text.toPlainText().split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    modified_headers[key.strip()] = value.strip()

            command['data'] = {
                'request': {
                    'headers': modified_headers,
                    'body': self.intercept_body_text.toPlainText()
                }
            }

        self._send_command_to_addon(command)
        self.reset_intercept_ui()

    def drop_request(self):
        if self.intercepted_flow_id:
            command = {"flow_id": self.intercepted_flow_id, "action": "drop"}
            self._send_command_to_addon(command)
        self.reset_intercept_ui()

    def analyze_with_ai(self):
        if not self.intercepted_flow_id:
            QMessageBox.warning(self, "No Data", "There is no intercepted data to analyze.")
            return

        request_headers = self.intercept_headers_text.toPlainText()
        request_body = self.intercept_body_text.toPlainText()
        response_headers = self.intercept_resp_headers_text.toPlainText()
        response_body = self.intercept_resp_body_text.toPlainText()

        finding = {
            'id': 'intercept-manual', 'title': 'Manual Interception Analysis', 'severity': 'info',
            'description': 'Analyze the following intercepted HTTP transaction.',
            'evidence': f"--- REQUEST ---\n{request_headers}\n\n{request_body}\n\n--- RESPONSE ---\n{response_headers}\n\n{response_body}"
        }
        self.analyze_ai_button.setText("🤖 Analyzing...")
        self.analyze_ai_button.setEnabled(False)
        asyncio.create_task(self.run_ai_analysis_task([finding]))

    async def run_ai_analysis_task(self, findings):
        try:
            results = await self.main_window.ai_analyzer.analyze_findings(findings)
            if results and 'error' not in results[0]:
                analysis = results[0]
                formatted_result = (
                    f"<b>AI Security Analysis:</b><br><br>"
                    f"<b>Severity Assessment:</b> {analysis.get('severity_assessment', 'N/A')}<br>"
                    f"<b>Remediation Priority:</b> {analysis.get('remediation_priority', 'N/A')}<br><br>"
                    f"<b>AI Reasoning:</b><br>{analysis.get('ai_reasoning', 'No reasoning provided.')}"
                )
                QMessageBox.information(self, "AI Analysis Complete", formatted_result)
            else:
                error_msg = results[0].get('error', 'Unknown error') if results else 'Unknown error'
                QMessageBox.critical(self, "AI Analysis Failed", f"The AI analysis failed: {error_msg}")
        except Exception as e:
            QMessageBox.critical(self, "AI Analysis Error", f"An unexpected error occurred: {str(e)}")
        finally:
            self.analyze_ai_button.setText("🤖 Analyze with AI")
            if self.intercepted_flow_id:
                self.analyze_ai_button.setEnabled(True)

    def show_context_menu(self, position):
        if self.history_table.selectionModel().hasSelection():
            menu = QMenu()
            action = QAction("🔄 Send to Repeater", self)
            action.triggered.connect(self.send_to_repeater)
            menu.addAction(action)
            menu.exec(self.history_table.mapToGlobal(position))

    def send_to_repeater(self):
        selected_rows = self.history_table.selectionModel().selectedRows()
        if not selected_rows: return
        row_index = selected_rows[0].row()

        if 0 <= row_index < len(self.full_requests):
            request_data = self.full_requests[row_index]
            self.repeater_tab.load_request(request_data)
            self.main_window.tab_widget.setCurrentWidget(self.repeater_tab)

    def export_ca_cert(self):
        mitm_ca_path = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
        if not mitm_ca_path.exists():
            QMessageBox.warning(self, "CA Not Found",
                              "Could not find mitmproxy CA certificate. "
                              "Please start the proxy once to generate it.")
            return

        default_path = str(Path.home() / "galdr_mitm_ca.pem")
        filename, _ = QFileDialog.getSaveFileName(self, "Export Galdr CA Certificate", default_path, "PEM Files (*.pem)")
        if filename:
            try:
                shutil.copy(mitm_ca_path, filename)
                QMessageBox.information(self, "Export Successful", f"CA certificate exported to:\n{filename}")
            except Exception as e:
                QMessageBox.critical(self, "Export Failed", f"Could not export certificate: {e}")

    def toggle_proxy(self, checked):
        if checked:
            try:
                self.history_table.setRowCount(0)
                self.full_requests.clear()

                self.event_server.start()

                addon_path = os.path.join('galdr', 'proxy', 'galdr_addon.py')
                command = [
                    "mitmdump", "-p", str(self.proxy_port), "-s", addon_path,
                    "--set", f"galdr_event_port={self.event_server_port}",
                    "--set", f"galdr_command_port={self.addon_command_port}",
                    "--set", "block_global=false"
                ]

                self.proxy_process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

                # Give the addon a moment to start its own server
                QTimer.singleShot(500, self._send_state_update_to_addon)

                self.proxy_button.setText("⏹️ Stop Proxy")
                self.proxy_status_label.setText(f"Status: Running on {self.proxy_host}:{self.proxy_port}")
                self.proxy_status_label.setStyleSheet("background-color: #4CAF50; color: white; padding: 5px; border-radius: 3px;")
            except Exception as e:
                self.proxy_status_label.setText(f"Status: Error - {e}")
                self.proxy_status_label.setStyleSheet("background-color: #D32F2F; color: white; padding: 5px; border-radius: 3px;")
                self.proxy_button.setChecked(False)
                self.event_server.stop()
        else:
            if self.proxy_process and self.proxy_process.poll() is None:
                self.proxy_process.terminate()
                try:
                    self.proxy_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.proxy_process.kill()
                self.proxy_process = None

            self.event_server.stop()

            self.proxy_button.setText("🚀 Start Proxy")
            self.proxy_status_label.setText("Status: Inactive")
            self.proxy_status_label.setStyleSheet("background-color: #f44336; color: white; padding: 5px; border-radius: 3px;")

    def add_log_entry(self, log_data):
        self.full_requests.append(log_data)
        row_position = self.history_table.rowCount()
        self.history_table.insertRow(row_position)

        self.history_table.setItem(row_position, 0, QTableWidgetItem(str(row_position + 1)))
        self.history_table.setItem(row_position, 1, QTableWidgetItem(log_data.get('method', '')))
        self.history_table.setItem(row_position, 2, QTableWidgetItem(log_data.get('url', '')))
        self.history_table.setItem(row_position, 3, QTableWidgetItem(str(log_data.get('status', ''))))
        self.history_table.setItem(row_position, 4, QTableWidgetItem(str(log_data.get('size', ''))))

        self.history_table.scrollToBottom()

    def closeEvent(self, event):
        """Ensure background processes are terminated when the widget is closed."""
        self.toggle_proxy(False) # Gracefully stop proxy and server
        self.command_executor.shutdown(wait=False, cancel_futures=True)
        event.accept()
