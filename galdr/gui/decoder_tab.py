from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit, QGroupBox, QGridLayout
)
from PyQt6.QtCore import Qt
from galdr.utils import coding_utils

class DecoderTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        """Initialize the UI for the Decoder tab."""
        main_layout = QHBoxLayout(self)

        # Input/Output Text Areas
        text_layout = QVBoxLayout()
        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("Enter text to encode or decode here...")
        self.output_text = QTextEdit()
        self.output_text.setPlaceholderText("Output will appear here...")
        self.output_text.setReadOnly(True)
        text_layout.addWidget(self.input_text)
        text_layout.addWidget(self.output_text)

        # Operations Panel
        operations_group = QGroupBox("Operations")
        ops_layout = QGridLayout()

        # URL Encoding
        self.url_encode_btn = QPushButton("URL Encode")
        self.url_encode_btn.clicked.connect(lambda: self.transform_text(coding_utils.url_encode))
        self.url_decode_btn = QPushButton("URL Decode")
        self.url_decode_btn.clicked.connect(lambda: self.transform_text(coding_utils.url_decode))
        ops_layout.addWidget(self.url_encode_btn, 0, 0)
        ops_layout.addWidget(self.url_decode_btn, 0, 1)

        # Base64 Encoding
        self.base64_encode_btn = QPushButton("Base64 Encode")
        self.base64_encode_btn.clicked.connect(lambda: self.transform_text(coding_utils.base64_encode))
        self.base64_decode_btn = QPushButton("Base64 Decode")
        self.base64_decode_btn.clicked.connect(lambda: self.transform_text(coding_utils.base64_decode))
        ops_layout.addWidget(self.base64_encode_btn, 1, 0)
        ops_layout.addWidget(self.base64_decode_btn, 1, 1)

        # HTML Encoding
        self.html_encode_btn = QPushButton("HTML Encode")
        self.html_encode_btn.clicked.connect(lambda: self.transform_text(coding_utils.html_encode))
        self.html_decode_btn = QPushButton("HTML Decode")
        self.html_decode_btn.clicked.connect(lambda: self.transform_text(coding_utils.html_decode))
        ops_layout.addWidget(self.html_encode_btn, 2, 0)
        ops_layout.addWidget(self.html_decode_btn, 2, 1)

        # Smart Decode
        self.smart_decode_btn = QPushButton("🧠 Smart Decode")
        self.smart_decode_btn.clicked.connect(lambda: self.transform_text(coding_utils.smart_decode))
        ops_layout.addWidget(self.smart_decode_btn, 3, 0, 1, 2) # Span across 2 columns

        operations_group.setLayout(ops_layout)

        main_layout.addLayout(text_layout, 3) # Give text area more space
        main_layout.addWidget(operations_group, 1)

        self.setLayout(main_layout)

    def transform_text(self, func):
        """Generic handler to transform text from input to output using a given function."""
        input_val = self.input_text.toPlainText()
        if not input_val:
            self.output_text.setPlainText("")
            return

        output_val = func(input_val)
        self.output_text.setPlainText(output_val)
