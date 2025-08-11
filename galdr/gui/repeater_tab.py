import asyncio
import time
import difflib
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QTabWidget, 
    QTextEdit, QLabel, QComboBox, QLineEdit, QPushButton, QGroupBox
)
from PyQt6.QtGui import QTextCharFormat, QColor, QFont
from PyQt6.QtCore import Qt, pyqtSignal, QThread
from playwright.async_api import async_playwright

class RepeaterRequestThread(QThread):
    response_received = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, method, url, headers, body):
        super().__init__()
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body
    
    def run(self):
        asyncio.run(self.send_request())
    
    async def send_request(self):
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context()
                page = await context.new_page()
                
                start_time = time.time()
                
                response = await page.request.fetch(
                    self.url,
                    method=self.method,
                    headers=self.headers,
                    data=self.body.encode('utf-8') if self.body else None
                )
                
                response_time = int((time.time() - start_time) * 1000)
                response_text = await response.text()
                response_headers = response.headers
                
                response_data = {
                    'status': response.status,
                    'text': response_text,
                    'headers': dict(response_headers),
                    'response_time': response_time,
                    'size': len(response_text)
                }
                
                self.response_received.emit(response_data)
                await browser.close()
                
        except Exception as e:
            self.error_occurred.emit(str(e))

class RepeaterTab(QWidget):
    request_sent = pyqtSignal(dict)  # Signal for logging
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        self.original_response = None
        self.response_history = []
        self.request_thread = None
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Create splitter for request/response
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Request editor (left side)
        request_widget = self.create_request_editor()
        splitter.addWidget(request_widget)
        
        # Response area with tabs (right side)
        response_widget = self.create_response_area()
        splitter.addWidget(response_widget)
        
        splitter.setSizes([400, 600])  # Give more space to response
        layout.addWidget(splitter)
    
    def create_request_editor(self):
        """Create request editing interface"""
        request_group = QGroupBox("🔄 Request Editor")
        layout = QVBoxLayout(request_group)
        
        # URL and method
        url_layout = QHBoxLayout()
        self.method_combo = QComboBox()
        self.method_combo.addItems(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'])
        self.method_combo.setFixedWidth(80)
        url_layout.addWidget(self.method_combo)
        
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com/api/endpoint")
        url_layout.addWidget(self.url_input)
        layout.addLayout(url_layout)
        
        # Headers editor
        layout.addWidget(QLabel("📋 Headers:"))
        self.headers_editor = QTextEdit()
        self.headers_editor.setPlaceholderText(
            "Content-Type: application/json\n"
            "Authorization: Bearer token\n"
            "User-Agent: Galdr-Repeater/2.0"
        )
        self.headers_editor.setMaximumHeight(120)
        self.headers_editor.setFont(QFont("Courier", 9))
        layout.addWidget(self.headers_editor)
        
        # Body editor
        layout.addWidget(QLabel("📝 Request Body:"))
        self.body_editor = QTextEdit()
        self.body_editor.setPlaceholderText('{"key": "value", "param": "test"}')
        self.body_editor.setFont(QFont("Courier", 9))
        layout.addWidget(self.body_editor)
        
        # Control buttons
        button_layout = QHBoxLayout()
        self.send_btn = QPushButton("🚀 Send Request")
        self.send_btn.clicked.connect(self.send_request)
        self.send_btn.setStyleSheet("""
            QPushButton {
                background-color: #00d4aa;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #00b899;
            }
        """)
        button_layout.addWidget(self.send_btn)
        
        self.clear_btn = QPushButton("🗑️ Clear")
        self.clear_btn.clicked.connect(self.clear_request)
        button_layout.addWidget(self.clear_btn)
        
        self.save_original_btn = QPushButton("📌 Save as Original")
        self.save_original_btn.clicked.connect(self.save_as_original)
        button_layout.addWidget(self.save_original_btn)
        
        layout.addLayout(button_layout)
        return request_group
    
    def create_response_area(self):
        """Create tabbed response area with comparison functionality"""
        response_group = QGroupBox("📊 Response Viewer")
        layout = QVBoxLayout(response_group)
        
        # Response info bar
        self.response_info = QLabel("No response yet")
        self.response_info.setStyleSheet("""
            QLabel {
                background-color: #2d2d2d;
                color: white;
                padding: 8px;
                border-radius: 4px;
                font-family: monospace;
            }
        """)
        layout.addWidget(self.response_info)
        
        # Response tabs
        self.response_tabs = QTabWidget()
        
        # Current response tab
        self.response_viewer = QTextEdit()
        self.response_viewer.setReadOnly(True)
        self.response_viewer.setFont(QFont("Courier", 9))
        self.response_tabs.addTab(self.response_viewer, "📄 Response")
        
        # Comparison tab
        self.comparison_viewer = QTextEdit()
        self.comparison_viewer.setReadOnly(True)
        self.comparison_viewer.setFont(QFont("Courier", 9))
        self.response_tabs.addTab(self.comparison_viewer, "🔄 Comparison")
        
        # Headers tab
        self.headers_viewer = QTextEdit()
        self.headers_viewer.setReadOnly(True)
        self.headers_viewer.setFont(QFont("Courier", 9))
        self.response_tabs.addTab(self.headers_viewer, "📋 Headers")
        
        layout.addWidget(self.response_tabs)
        return response_group
    
    def load_request(self, request_data):
        """Load a request from network history or results table"""
        self.method_combo.setCurrentText(request_data.get('method', 'GET'))
        self.url_input.setText(request_data.get('url', ''))
        
        # Format headers
        headers = request_data.get('headers', {})
        headers_text = '\n'.join([f"{k}: {v}" for k, v in headers.items()])
        self.headers_editor.setPlainText(headers_text)
        
        # Set body if present
        body = request_data.get('body') or request_data.get('post_data')
        if body:
            self.body_editor.setPlainText(body)
    
    def send_request(self):
        """Send the request using threaded Playwright"""
        if self.request_thread and self.request_thread.isRunning():
            return
        
        # Parse headers
        headers = {}
        for line in self.headers_editor.toPlainText().split('\n'):
            if ':' in line and line.strip():
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        method = self.method_combo.currentText()
        url = self.url_input.text().strip()
        body = self.body_editor.toPlainText().strip()
        
        if not url:
            self.response_info.setText("❌ Error: URL is required")
            return
        
        self.send_btn.setEnabled(False)
        self.send_btn.setText("⏳ Sending...")
        
        # Create and start request thread
        self.request_thread = RepeaterRequestThread(method, url, headers, body)
        self.request_thread.response_received.connect(self.handle_response)
        self.request_thread.error_occurred.connect(self.handle_error)
        self.request_thread.start()
    
    def handle_response(self, response_data):
        """Handle successful response"""
        # Store original response if this is the first request
        if self.original_response is None:
            self.original_response = response_data.copy()
        
        # Display response info
        self.response_info.setText(
            f"✅ Status: {response_data['status']} | "
            f"Size: {response_data['size']} bytes | "
            f"Time: {response_data['response_time']}ms"
        )
        
        # Display response body
        self.response_viewer.setPlainText(response_data['text'])
        
        # Display headers
        headers_text = '\n'.join([f"{k}: {v}" for k, v in response_data['headers'].items()])
        self.headers_viewer.setPlainText(headers_text)
        
        # Store in history
        self.response_history.append(response_data)
        
        # Compare with original if available and different
        if (self.original_response and 
            response_data['text'] != self.original_response['text']):
            self.compare_responses(
                self.original_response['text'], 
                response_data['text']
            )
        
        # Emit signal for logging
        self.request_sent.emit({
            'method': self.method_combo.currentText(),
            'url': self.url_input.text(),
            'status': response_data['status'],
            'response_time': response_data['response_time']
        })
        
        self.send_btn.setEnabled(True)
        self.send_btn.setText("🚀 Send Request")
    
    def handle_error(self, error_msg):
        """Handle request error"""
        self.response_info.setText(f"❌ Error: {error_msg}")
        self.response_viewer.setPlainText("")
        self.send_btn.setEnabled(True)
        self.send_btn.setText("🚀 Send Request")
    
    def compare_responses(self, original_text, modified_text):
        """Generate and display response comparison"""
        diff = list(difflib.unified_diff(
            original_text.splitlines(keepends=True),
            modified_text.splitlines(keepends=True),
            fromfile='🔵 Original Response',
            tofile='🟢 Current Response',
            n=3
        ))
        
        if not diff:
            self.comparison_viewer.setPlainText("✅ No differences found")
            return
        
        self.display_colored_diff(diff)
        self.response_tabs.setCurrentIndex(1)  # Switch to comparison tab
    
from galdr.utils.ui_utils import display_colored_diff

    def display_colored_diff(self, diff_lines):
        """Display diff with color highlighting"""
        display_colored_diff(self.comparison_viewer, diff_lines)
    
    def save_as_original(self):
        """Save current response as original for comparison"""
        if self.response_history:
            self.original_response = self.response_history[-1].copy()
            self.response_info.setText("📌 Current response saved as original")
    
    def clear_request(self):
        """Clear all request fields"""
        self.url_input.clear()
        self.headers_editor.clear()
        self.body_editor.clear()
        self.method_combo.setCurrentText('GET')
        self.response_viewer.clear()
        self.comparison_viewer.clear()
        self.headers_viewer.clear()
        self.response_info.setText("Request cleared")
