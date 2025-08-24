from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget, QTableWidgetItem,
    QSplitter, QTabWidget, QTextEdit, QGroupBox, QLabel, QSpinBox, QHeaderView,
    QMenu
)
from PyQt6.QtCore import Qt, pyqtSlot
from PyQt6.QtGui import QFont, QAction

from galdr.proxy.proxy_core import ProxyManager

class ProxyTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.proxy_manager = ProxyManager()
        self.flows = {}  # Store full flow data by id
        self.init_ui()
        self.connect_signals()

    def init_ui(self):
        layout = QVBoxLayout(self)

        # --- Controls ---
        controls_group = QGroupBox("Proxy Controls")
        controls_layout = QHBoxLayout()

        controls_layout.addWidget(QLabel("Listen Port:"))
        self.port_spinbox = QSpinBox()
        self.port_spinbox.setRange(1024, 65535)
        self.port_spinbox.setValue(8080)
        controls_layout.addWidget(self.port_spinbox)

        self.start_btn = QPushButton("Start Proxy")
        controls_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Stop Proxy")
        self.stop_btn.setEnabled(False)
        controls_layout.addWidget(self.stop_btn)

        self.clear_btn = QPushButton("Clear History")
        controls_layout.addWidget(self.clear_btn)

        controls_layout.addStretch()
        controls_group.setLayout(controls_layout)
        layout.addWidget(controls_group)

        # --- Main Splitter ---
        main_splitter = QSplitter(Qt.Orientation.Vertical)

        # --- History Table ---
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(5)
        self.history_table.setHorizontalHeaderLabels(["ID", "Method", "URL", "Status", "Length"])
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.history_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        self.history_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.history_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.history_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        main_splitter.addWidget(self.history_table)

        # --- Detail View ---
        detail_splitter = QSplitter(Qt.Orientation.Horizontal)

        # Request View
        request_group = QGroupBox("Request")
        request_layout = QVBoxLayout(request_group)
        self.request_tabs = QTabWidget()
        self.request_headers_view = QTextEdit()
        self.request_body_view = QTextEdit()
        self.request_tabs.addTab(self.request_body_view, "Body")
        self.request_tabs.addTab(self.request_headers_view, "Headers")
        request_layout.addWidget(self.request_tabs)
        detail_splitter.addWidget(request_group)

        # Response View
        response_group = QGroupBox("Response")
        response_layout = QVBoxLayout(response_group)
        self.response_tabs = QTabWidget()
        self.response_headers_view = QTextEdit()
        self.response_body_view = QTextEdit()
        self.response_tabs.addTab(self.response_body_view, "Body")
        self.response_tabs.addTab(self.response_headers_view, "Headers")
        response_layout.addWidget(self.response_tabs)
        detail_splitter.addWidget(response_group)

        main_splitter.addWidget(detail_splitter)
        main_splitter.setSizes([200, 400])
        layout.addWidget(main_splitter)

        # --- Log Area ---
        log_group = QGroupBox("Proxy Log")
        log_layout = QVBoxLayout(log_group)
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setFont(QFont("Courier", 9))
        self.log_area.setMaximumHeight(100)
        log_group.setLayout(log_layout)
        layout.addWidget(log_group)

    def connect_signals(self):
        self.start_btn.clicked.connect(self.start_proxy)
        self.stop_btn.clicked.connect(self.stop_proxy)
        self.clear_btn.clicked.connect(self.clear_history)

        self.proxy_manager.flow_received.connect(self.add_flow_to_history)
        self.proxy_manager.log_message.connect(self.log_message)

        self.history_table.itemSelectionChanged.connect(self.display_flow_details)
        self.history_table.customContextMenuRequested.connect(self.show_context_menu)

    def show_context_menu(self, position):
        menu = QMenu()
        send_to_repeater_action = QAction("Send to Repeater", self)
        send_to_scanner_action = QAction("Send to Active Scanner", self)
        send_to_raider_action = QAction("Send to Raider", self)

        send_to_repeater_action.triggered.connect(self.send_to_repeater)
        send_to_scanner_action.triggered.connect(self.send_to_scanner)
        send_to_raider_action.triggered.connect(self.send_to_raider)

        menu.addAction(send_to_repeater_action)
        menu.addAction(send_to_scanner_action)
        menu.addAction(send_to_raider_action)

        menu.exec(self.history_table.mapToGlobal(position))

    def get_selected_flow_as_request_data(self):
        selected_items = self.history_table.selectedItems()
        if not selected_items:
            return None

        flow_id = selected_items[0].data(Qt.ItemDataRole.UserRole)
        flow_data = self.flows.get(flow_id)

        if not flow_data:
            return None

        return {
            'method': flow_data['request']['method'],
            'url': flow_data['url'],
            'headers': dict(flow_data['request']['headers']),
            'body': flow_data['request']['content']
        }

    def send_to_repeater(self):
        request_data = self.get_selected_flow_as_request_data()
        if request_data:
            self.main_window.repeater_tab.load_request(request_data)
            self.main_window.tab_widget.setCurrentWidget(self.main_window.repeater_tab)
            self.log_message(f"Sent {request_data['url']} to Repeater.")

    def send_to_scanner(self):
        request_data = self.get_selected_flow_as_request_data()
        if request_data:
            self.main_window.scanner_tab.load_request(request_data)
            self.main_window.tab_widget.setCurrentWidget(self.main_window.scanner_tab)
            self.log_message(f"Sent {request_data['url']} to Active Scanner.")

    def send_to_raider(self):
        request_data = self.get_selected_flow_as_request_data()
        if request_data:
            self.main_window.raider_tab.load_request(request_data)
            self.main_window.tab_widget.setCurrentWidget(self.main_window.raider_tab)
            self.log_message(f"Sent {request_data['url']} to Raider.")

    @pyqtSlot()
    def start_proxy(self):
        port = self.port_spinbox.value()
        self.proxy_manager.start_proxy(port)
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.port_spinbox.setEnabled(False)

    @pyqtSlot()
    def stop_proxy(self):
        self.proxy_manager.stop_proxy()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.port_spinbox.setEnabled(True)

    @pyqtSlot()
    def clear_history(self):
        self.history_table.setRowCount(0)
        self.flows.clear()
        self.request_headers_view.clear()
        self.request_body_view.clear()
        self.response_headers_view.clear()
        self.response_body_view.clear()
        self.log_message("History cleared.")

    @pyqtSlot(dict)
    def add_flow_to_history(self, flow_data):
        flow_id = flow_data['id']
        self.flows[flow_id] = flow_data

        row_position = self.history_table.rowCount()
        self.history_table.insertRow(row_position)

        self.history_table.setItem(row_position, 0, QTableWidgetItem(str(row_position))) # Simple ID
        self.history_table.setItem(row_position, 1, QTableWidgetItem(flow_data['method']))
        self.history_table.setItem(row_position, 2, QTableWidgetItem(flow_data['url']))
        self.history_table.setItem(row_position, 3, QTableWidgetItem(str(flow_data['status_code'])))
        self.history_table.setItem(row_position, 4, QTableWidgetItem(str(flow_data['content_length'])))

        # Store the flow ID in the first item for later retrieval
        self.history_table.item(row_position, 0).setData(Qt.ItemDataRole.UserRole, flow_id)

    @pyqtSlot()
    def display_flow_details(self):
        selected_items = self.history_table.selectedItems()
        if not selected_items:
            return

        flow_id = selected_items[0].data(Qt.ItemDataRole.UserRole)
        flow_data = self.flows.get(flow_id)

        if not flow_data:
            return

        # Request
        req_headers = "\n".join([f"{k}: {v}" for k, v in flow_data['request']['headers']])
        self.request_headers_view.setPlainText(req_headers)
        self.request_body_view.setPlainText(flow_data['request']['content'])

        # Response
        res_headers = "\n".join([f"{k}: {v}" for k, v in flow_data['response']['headers']])
        self.response_headers_view.setPlainText(res_headers)
        self.response_body_view.setPlainText(flow_data['response']['content'])

    @pyqtSlot(str)
    def log_message(self, message):
        self.log_area.append(message)

    def closeEvent(self, event):
        self.stop_proxy()
        super().closeEvent(event)
