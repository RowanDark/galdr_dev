from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit, QGroupBox,
    QSizePolicy
)
from PyQt6.QtGui import QFont

from galdr.utils.crypto_utils import CryptoUtils

class CryptographerTab(QWidget):
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

        main_layout.setStretch(0, 2) # Input
        main_layout.setStretch(1, 1) # Controls
        main_layout.setStretch(2, 2) # Output

        # --- JWT Section ---
        jwt_group = QGroupBox("JWT Decoder / Verifier")
        jwt_group_layout = QVBoxLayout(jwt_group)

        # JWT Input
        jwt_group_layout.addWidget(QLabel("JWT Token:"))
        self.jwt_input_editor = QTextEdit()
        self.jwt_input_editor.setFont(QFont("Courier", 10))
        self.jwt_input_editor.setPlaceholderText("Paste your JWT token here...")
        self.jwt_input_editor.setMaximumHeight(100)
        jwt_group_layout.addWidget(self.jwt_input_editor)

        # Decoded Panes
        decoded_layout = QHBoxLayout()
        header_group = QGroupBox("Decoded Header")
        header_layout = QVBoxLayout(header_group)
        self.jwt_header_view = QTextEdit()
        self.jwt_header_view.setReadOnly(True)
        self.jwt_header_view.setFont(QFont("Courier", 10))
        header_layout.addWidget(self.jwt_header_view)

        payload_group = QGroupBox("Decoded Payload")
        payload_layout = QVBoxLayout(payload_group)
        self.jwt_payload_view = QTextEdit()
        self.jwt_payload_view.setReadOnly(True)
        self.jwt_payload_view.setFont(QFont("Courier", 10))
        payload_layout.addWidget(self.jwt_payload_view)

        decoded_layout.addWidget(header_group)
        decoded_layout.addWidget(payload_group)
        jwt_group_layout.addLayout(decoded_layout)

        # Verification Section
        verify_layout = QHBoxLayout()
        verify_layout.addWidget(QLabel("Secret / Key (for signature verification):"))
        self.jwt_secret_input = QLineEdit()
        self.jwt_secret_input.setPlaceholderText("Enter a secret or a PEM-formatted public key")
        verify_layout.addWidget(self.jwt_secret_input)
        self.jwt_verify_btn = QPushButton("Verify Signature")
        verify_layout.addWidget(self.jwt_verify_btn)
        self.jwt_status_label = QLabel("Status: Awaiting token...")
        verify_layout.addWidget(self.jwt_status_label)
        jwt_group_layout.addLayout(verify_layout)

        # Add the main layout to a container widget for nesting
        top_widget = QWidget()
        top_widget.setLayout(main_layout)

        # Main vertical layout
        v_layout = QVBoxLayout(self)
        v_layout.addWidget(top_widget)
        v_layout.addWidget(jwt_group)

        self.connect_signals()

    def connect_signals(self):
        self.url_encode_btn.clicked.connect(lambda: self.transform_text(CryptoUtils.url_encode))
        self.url_decode_btn.clicked.connect(lambda: self.transform_text(CryptoUtils.url_decode, reverse=True))

        self.base64_encode_btn.clicked.connect(lambda: self.transform_text(CryptoUtils.base64_encode))
        self.base64_decode_btn.clicked.connect(lambda: self.transform_text(CryptoUtils.base64_decode, reverse=True))

        self.html_encode_btn.clicked.connect(lambda: self.transform_text(CryptoUtils.html_encode))
        self.html_decode_btn.clicked.connect(lambda: self.transform_text(CryptoUtils.html_decode, reverse=True))

        self.hex_encode_btn.clicked.connect(lambda: self.transform_text(CryptoUtils.hex_encode))
        self.hex_decode_btn.clicked.connect(lambda: self.transform_text(CryptoUtils.hex_decode, reverse=True))

        # JWT signals
        self.jwt_input_editor.textChanged.connect(self.on_jwt_input_changed)
        self.jwt_verify_btn.clicked.connect(self.on_verify_button_clicked)

    def on_jwt_input_changed(self):
        token = self.jwt_input_editor.toPlainText().strip()
        if not token:
            self.jwt_header_view.clear()
            self.jwt_payload_view.clear()
            self.jwt_status_label.setText("Status: Awaiting token...")
            return

        header, payload, error = CryptoUtils.decode_jwt(token)

        if error:
            self.jwt_header_view.clear()
            self.jwt_payload_view.clear()
            self.jwt_status_label.setText(f"Status: {error}")
        else:
            self.jwt_header_view.setPlainText(header)
            self.jwt_payload_view.setPlainText(payload)
            self.jwt_status_label.setText("Status: Decoded successfully (signature not verified).")

    def on_verify_button_clicked(self):
        token = self.jwt_input_editor.toPlainText().strip()
        secret = self.jwt_secret_input.text()

        if not token:
            self.jwt_status_label.setText("Status: No token to verify.")
            return

        result = CryptoUtils.verify_jwt_signature(token, secret)
        self.jwt_status_label.setText(f"Status: {result}")

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
