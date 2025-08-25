from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QTextEdit,
    QPushButton, QGroupBox, QLabel, QLineEdit, QComboBox, QMessageBox
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont

from utils.crypto_utils import (
    base32_encode, base32_decode,
    base45_encode, base45_decode,
    base58_encode, base58_decode,
    base62_encode, base62_decode,
    base85_encode, base85_decode,
    text_to_decimal, decimal_to_text,
    text_to_binary, binary_to_text,
    text_to_octal, octal_to_text,
    rot13_cipher,
    xor_cipher, xor_decipher
)

class CryptographerTab(QWidget):
    """A widget for cryptographic operations, similar to CyberChef."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        """Initialize the user interface."""
        main_layout = QVBoxLayout(self)

        # Splitter for Input and Output
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Input Area
        input_group = QGroupBox("Input")
        input_layout = QVBoxLayout(input_group)
        self.input_text = QTextEdit()
        self.input_text.setFont(QFont("Courier", 10))
        self.input_text.setPlaceholderText("Enter text to transform...")
        input_layout.addWidget(self.input_text)
        splitter.addWidget(input_group)

        # Output Area
        output_group = QGroupBox("Output")
        output_layout = QVBoxLayout(output_group)
        self.output_text = QTextEdit()
        self.output_text.setFont(QFont("Courier", 10))
        self.output_text.setReadOnly(True)
        output_layout.addWidget(self.output_text)
        splitter.addWidget(output_group)

        splitter.setSizes([400, 400])
        main_layout.addWidget(splitter)

        # Operations Panel
        operations_layout = QHBoxLayout()

        # Base Encodings
        encodings_group = QGroupBox("Base Encodings")
        encodings_layout = QVBoxLayout(encodings_group)
        self.add_buttons(encodings_layout, [
            "Base32", "Base45", "Base58", "Base62", "Base85"
        ])
        operations_layout.addWidget(encodings_group)

        # Number Systems
        numbers_group = QGroupBox("Number Systems")
        numbers_layout = QVBoxLayout(numbers_group)
        self.add_buttons(numbers_layout, [
            "Decimal", "Binary", "Octal"
        ])
        operations_layout.addWidget(numbers_group)

        # Simple Ciphers
        ciphers_group = QGroupBox("Simple Ciphers")
        ciphers_layout = QVBoxLayout(ciphers_group)
        self.add_buttons(ciphers_layout, ["ROT13", "XOR"])

        # XOR Key Input
        xor_key_layout = QHBoxLayout()
        xor_key_layout.addWidget(QLabel("XOR Key:"))
        self.xor_key_input = QLineEdit()
        self.xor_key_input.setPlaceholderText("secret")
        xor_key_layout.addWidget(self.xor_key_input)
        ciphers_layout.addLayout(xor_key_layout)
        operations_layout.addWidget(ciphers_group)

        main_layout.addLayout(operations_layout)

        # Mode Selection
        mode_layout = QHBoxLayout()
        mode_layout.addWidget(QLabel("Mode:"))
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Encode", "Decode"])
        mode_layout.addWidget(self.mode_combo)
        mode_layout.addStretch()
        main_layout.addLayout(mode_layout)

    def add_buttons(self, layout, names):
        """Helper to add multiple buttons to a layout."""
        for name in names:
            button = QPushButton(name)
            button.clicked.connect(self.handle_operation)
            layout.addWidget(button)

    def handle_operation(self):
        """Handle a click on any operation button."""
        sender = self.sender()
        operation = sender.text()

        input_text = self.input_text.toPlainText()
        if not input_text:
            return

        mode = self.mode_combo.currentText()

        try:
            result = self.dispatch_operation(operation, input_text, mode)
            self.output_text.setPlainText(result)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")
            self.output_text.setPlainText(f"Error: {str(e)}")

    def dispatch_operation(self, operation, text, mode):
        """Dispatch to the correct crypto function based on operation and mode."""
        is_encode = mode == "Encode"

        op_map = {
            "Base32": (base32_encode, base32_decode),
            "Base45": (base45_encode, base45_decode),
            "Base58": (base58_encode, base58_decode),
            "Base62": (base62_encode, base62_decode),
            "Base85": (base85_encode, base85_decode),
            "Decimal": (text_to_decimal, decimal_to_text),
            "Binary": (text_to_binary, binary_to_text),
            "Octal": (text_to_octal, octal_to_text),
            "ROT13": (rot13_cipher, rot13_cipher), # ROT13 is its own inverse
            "XOR": (self.run_xor_cipher, self.run_xor_decipher)
        }

        if operation in op_map:
            func = op_map[operation][0] if is_encode else op_map[operation][1]
            return func(text)

        raise ValueError(f"Unknown operation: {operation}")

    def run_xor_cipher(self, text):
        """Wrapper for XOR cipher to get the key from the UI."""
        key = self.xor_key_input.text()
        if not key:
            raise ValueError("XOR key cannot be empty.")
        return xor_cipher(text, key)

    def run_xor_decipher(self, text):
        """Wrapper for XOR decipher to get the key from the UI."""
        key = self.xor_key_input.text()
        if not key:
            raise ValueError("XOR key cannot be empty.")
        return xor_decipher(text, key)
