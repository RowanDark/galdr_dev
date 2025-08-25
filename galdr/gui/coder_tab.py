from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit, QGroupBox,
    QSizePolicy
)
from PyQt6.QtGui import QFont

from galdr.utils.coder import Coder

class CoderTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        main_layout = QHBoxLayout(self)

        # --- Input Pane ---
        input_group = QGroupBox("Input")
        input_layout = QVBoxLayout(input_group)
        self.input_editor = QTextEdit()
        self.input_editor.setFont(QFont("Courier", 10))
        input_layout.addWidget(self.input_editor)
        main_layout.addWidget(input_group)

        # --- Controls Pane ---
        controls_widget = QWidget()
        controls_layout = QVBoxLayout(controls_widget)
        controls_widget.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Expanding)

        # URL
        self.url_encode_btn = QPushButton("URL Encode ->")
        self.url_decode_btn = QPushButton("<- URL Decode")
        controls_layout.addWidget(self.url_encode_btn)
        controls_layout.addWidget(self.url_decode_btn)
        controls_layout.addSpacing(20)

        # Base64
        self.base64_encode_btn = QPushButton("Base64 Encode ->")
        self.base64_decode_btn = QPushButton("<- Base64 Decode")
        controls_layout.addWidget(self.base64_encode_btn)
        controls_layout.addWidget(self.base64_decode_btn)
        controls_layout.addSpacing(20)

        # HTML
        self.html_encode_btn = QPushButton("HTML Encode ->")
        self.html_decode_btn = QPushButton("<- HTML Decode")
        controls_layout.addWidget(self.html_encode_btn)
        controls_layout.addWidget(self.html_decode_btn)
        controls_layout.addSpacing(20)

        # Hex
        self.hex_encode_btn = QPushButton("Hex Encode ->")
        self.hex_decode_btn = QPushButton("<- Hex Decode")
        controls_layout.addWidget(self.hex_encode_btn)
        controls_layout.addWidget(self.hex_decode_btn)

        main_layout.addWidget(controls_widget)

        # --- Output Pane ---
        output_group = QGroupBox("Output")
        output_layout = QVBoxLayout(output_group)
        self.output_editor = QTextEdit()
        self.output_editor.setFont(QFont("Courier", 10))
        self.output_editor.setReadOnly(True)
        output_layout.addWidget(self.output_editor)
        main_layout.addWidget(output_group)

        self.connect_signals()

    def connect_signals(self):
        self.url_encode_btn.clicked.connect(lambda: self.transform_text(Coder.url_encode))
        self.url_decode_btn.clicked.connect(lambda: self.transform_text(Coder.url_decode, reverse=True))

        self.base64_encode_btn.clicked.connect(lambda: self.transform_text(Coder.base64_encode))
        self.base64_decode_btn.clicked.connect(lambda: self.transform_text(Coder.base64_decode, reverse=True))

        self.html_encode_btn.clicked.connect(lambda: self.transform_text(Coder.html_encode))
        self.html_decode_btn.clicked.connect(lambda: self.transform_text(Coder.html_decode, reverse=True))

        self.hex_encode_btn.clicked.connect(lambda: self.transform_text(Coder.hex_encode))
        self.hex_decode_btn.clicked.connect(lambda: self.transform_text(Coder.hex_decode, reverse=True))

    def transform_text(self, func, reverse=False):
        if not reverse:
            input_text = self.input_editor.toPlainText()
            output_text = func(input_text)
            self.output_editor.setPlainText(output_text)
        else:
            # For decoding, we take from the output and put in the input
            input_text = self.output_editor.toPlainText()
            output_text = func(input_text)
            self.input_editor.setPlainText(output_text)
