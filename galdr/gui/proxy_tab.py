from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QSplitter, QTabWidget, QTextEdit, QPushButton, QGroupBox, QLabel, QLineEdit
)
from PyQt6.QtCore import Qt, pyqtSignal

class ProxyTab(QWidget):
    """
    UI Tab for the Intercepting Proxy.
    Displays HTTP/HTTPS traffic in real-time and allows for interception.
    """
    toggle_intercept_signal = pyqtSignal(bool)
    forward_request_signal = pyqtSignal(dict)
    drop_request_signal = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.intercepted_flow_id = None
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout(self)

        controls_layout = QHBoxLayout()
        self.start_proxy_btn = QPushButton("Start Proxy")
        self.stop_proxy_btn = QPushButton("Stop Proxy")
        self.stop_proxy_btn.setEnabled(False)
        self.intercept_btn = QPushButton("Intercept is OFF")
        self.intercept_btn.setCheckable(True)
        self.intercept_btn.toggled.connect(self.toggle_intercept)

        self.forward_btn = QPushButton("Forward")
        self.forward_btn.setEnabled(False)
        self.forward_btn.clicked.connect(self.forward_request)
        self.drop_btn = QPushButton("Drop")
        self.drop_btn.setEnabled(False)
        self.drop_btn.clicked.connect(self.drop_request)

        self.clear_btn = QPushButton("Clear")

        controls_layout.addWidget(self.start_proxy_btn)
        controls_layout.addWidget(self.stop_proxy_btn)
        controls_layout.addWidget(self.intercept_btn)
        controls_layout.addWidget(self.forward_btn)
        controls_layout.addWidget(self.drop_btn)
        controls_layout.addStretch()
        controls_layout.addWidget(self.clear_btn)
        main_layout.addLayout(controls_layout)

        main_splitter = QSplitter(Qt.Orientation.Vertical)

        self.history_table = QTableWidget()
        self.history_table.setColumnCount(5)
        self.history_table.setHorizontalHeaderLabels(["ID", "Method", "URL", "Status", "Content-Type"])
        self.history_table.setColumnWidth(0, 50)
        self.history_table.setColumnWidth(2, 400)
        self.history_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.history_table.itemSelectionChanged.connect(self.display_flow_details)
        main_splitter.addWidget(self.history_table)

        viewer_splitter = QSplitter(Qt.Orientation.Horizontal)

        request_group = QGroupBox("Request")
        request_layout = QVBoxLayout(request_group)

        request_line_layout = QHBoxLayout()
        self.request_method_input = QLineEdit()
        self.request_method_input.setPlaceholderText("GET")
        self.request_method_input.setFixedWidth(80)
        self.request_url_input = QLineEdit()
        self.request_url_input.setPlaceholderText("https://example.com")
        request_line_layout.addWidget(self.request_method_input)
        request_line_layout.addWidget(self.request_url_input)
        request_layout.addLayout(request_line_layout)

        self.request_tabs = QTabWidget()
        self.request_headers_view = QTextEdit()
        self.request_body_view = QTextEdit()
        self.request_tabs.addTab(self.request_headers_view, "Headers")
        self.request_tabs.addTab(self.request_body_view, "Body")
        request_layout.addWidget(self.request_tabs)
        viewer_splitter.addWidget(request_group)

        response_group = QGroupBox("Response")
        response_layout = QVBoxLayout(response_group)
        self.response_tabs = QTabWidget()
        self.response_headers_view = QTextEdit()
        self.response_body_view = QTextEdit()
        self.response_tabs.addTab(self.response_headers_view, "Headers")
        self.response_tabs.addTab(self.response_body_view, "Body")
        response_layout.addWidget(self.response_tabs)
        viewer_splitter.addWidget(response_group)

        main_splitter.addWidget(viewer_splitter)
        main_splitter.setSizes([200, 400])

        main_layout.addWidget(main_splitter)

        self.clear_btn.clicked.connect(self.clear_history)
        self.reset_intercept_ui()

    def toggle_intercept(self, checked):
        if checked:
            self.intercept_btn.setText("Intercept is ON")
            self.intercept_btn.setStyleSheet("background-color: #ff6b6b;")
        else:
            self.intercept_btn.setText("Intercept is OFF")
            self.intercept_btn.setStyleSheet("")
            if self.forward_btn.isEnabled():
                self.forward_request()
        self.toggle_intercept_signal.emit(checked)

    def handle_intercepted_request(self, flow_summary):
        self.intercepted_flow_id = flow_summary['id']
        self.display_flow_details(flow_summary, editable=True)
        self.forward_btn.setEnabled(True)
        self.drop_btn.setEnabled(True)
        self.intercept_btn.setEnabled(False)

    def forward_request(self):
        modified_request = {
            "method": self.request_method_input.text(),
            "url": self.request_url_input.text(),
            "headers": self.parse_headers(self.request_headers_view.toPlainText()),
            "content": self.request_body_view.toPlainText().encode('utf-8')
        }
        self.forward_request_signal.emit(modified_request)
        self.reset_intercept_ui()

    def drop_request(self):
        self.drop_request_signal.emit()
        self.reset_intercept_ui()

    def reset_intercept_ui(self):
        self.intercepted_flow_id = None
        self.forward_btn.setEnabled(False)
        self.drop_btn.setEnabled(False)
        self.intercept_btn.setEnabled(True)
        self.request_method_input.setReadOnly(True)
        self.request_url_input.setReadOnly(True)
        self.request_headers_view.setReadOnly(True)
        self.request_body_view.setReadOnly(True)

    def add_flow_to_history(self, flow_summary):
        row_position = self.history_table.rowCount()
        self.history_table.insertRow(row_position)

        self.history_table.setItem(row_position, 0, QTableWidgetItem(str(flow_summary['id'])))
        self.history_table.setItem(row_position, 1, QTableWidgetItem(flow_summary['request']['method']))
        self.history_table.setItem(row_position, 2, QTableWidgetItem(flow_summary['request']['url']))

        status_item = QTableWidgetItem(str(flow_summary['response']['status_code']) if flow_summary['response'] else "In-flight")
        self.history_table.setItem(row_position, 3, status_item)

        content_type = flow_summary['response']['headers'].get('content-type', 'N/A') if flow_summary['response'] else 'N/A'
        self.history_table.setItem(row_position, 4, QTableWidgetItem(content_type))

        self.history_table.item(row_position, 0).setData(Qt.ItemDataRole.UserRole, flow_summary)

    def display_flow_details(self, flow_summary=None, editable=False):
        if flow_summary is None:
            selected_items = self.history_table.selectedItems()
            if not selected_items:
                return
            flow_summary = self.history_table.item(selected_items[0].row(), 0).data(Qt.ItemDataRole.UserRole)

        self.request_method_input.setText(flow_summary['request']['method'])
        self.request_url_input.setText(flow_summary['request']['url'])
        req_headers = "\n".join(f"{k}: {v}" for k, v in flow_summary['request']['headers'].items())
        self.request_headers_view.setPlainText(req_headers)
        self.request_body_view.setPlainText(flow_summary['request']['content'].decode('utf-8', 'ignore'))

        if flow_summary['response']:
            res_headers = "\n".join(f"{k}: {v}" for k, v in flow_summary['response']['headers'].items())
            self.response_headers_view.setPlainText(res_headers)
            self.response_body_view.setPlainText(flow_summary['response']['content'].decode('utf-8', 'ignore'))
        else:
            self.response_headers_view.clear()
            self.response_body_view.clear()

        self.request_method_input.setReadOnly(not editable)
        self.request_url_input.setReadOnly(not editable)
        self.request_headers_view.setReadOnly(not editable)
        self.request_body_view.setReadOnly(not editable)

    def clear_history(self):
        self.history_table.setRowCount(0)
        self.request_method_input.clear()
        self.request_url_input.clear()
        self.request_headers_view.clear()
        self.request_body_view.clear()
        self.response_headers_view.clear()
        self.response_body_view.clear()

    def parse_headers(self, text):
        headers = {}
        for line in text.splitlines():
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        return headers
