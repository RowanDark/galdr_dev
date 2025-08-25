from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QTextEdit,
    QPushButton, QGroupBox, QLabel, QLineEdit, QComboBox, QMessageBox
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
import base64

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
    xor_cipher, xor_decipher,
    symmetric_encrypt, symmetric_decrypt
)

class CryptographerTab(QWidget):
    """A widget for cryptographic operations, similar to CyberChef."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        self.update_sym_modes()

    def init_ui(self):
        """Initialize the user interface."""
        main_layout = QVBoxLayout(self)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        input_group = QGroupBox("Input")
        input_layout = QVBoxLayout(input_group)
        self.input_text = QTextEdit()
        self.input_text.setFont(QFont("Courier", 10))
        self.input_text.setPlaceholderText("Enter text to transform...")
        input_layout.addWidget(self.input_text)
        splitter.addWidget(input_group)

        output_group = QGroupBox("Output")
        output_layout = QVBoxLayout(output_group)
        self.output_text = QTextEdit()
        self.output_text.setFont(QFont("Courier", 10))
        self.output_text.setReadOnly(True)
        output_layout.addWidget(self.output_text)
        splitter.addWidget(output_group)

        splitter.setSizes([400, 400])
        main_layout.addWidget(splitter)

        controls_layout = QHBoxLayout()

        # Left side controls
        left_controls_layout = QVBoxLayout()

        # Base Encodings
        encodings_group = QGroupBox("Base Encodings")
        encodings_layout = QVBoxLayout(encodings_group)
        self.add_buttons(encodings_layout, ["Base32", "Base45", "Base58", "Base62", "Base85"])
        left_controls_layout.addWidget(encodings_group)

        # Number Systems
        numbers_group = QGroupBox("Number Systems")
        numbers_layout = QVBoxLayout(numbers_group)
        self.add_buttons(numbers_layout, ["Decimal", "Binary", "Octal"])
        left_controls_layout.addWidget(numbers_group)

        # Simple Ciphers
        ciphers_group = QGroupBox("Simple Ciphers")
        ciphers_layout = QVBoxLayout(ciphers_group)
        self.add_buttons(ciphers_layout, ["ROT13", "XOR"])
        xor_key_layout = QHBoxLayout()
        xor_key_layout.addWidget(QLabel("XOR Key:"))
        self.xor_key_input = QLineEdit()
        self.xor_key_input.setPlaceholderText("secret")
        xor_key_layout.addWidget(self.xor_key_input)
        ciphers_layout.addLayout(xor_key_layout)
        left_controls_layout.addWidget(ciphers_group)

        left_controls_layout.addStretch()
        controls_layout.addLayout(left_controls_layout)

        # Right side controls (Symmetric Ciphers)
        sym_ciphers_group = QGroupBox("Symmetric Ciphers")
        sym_ciphers_layout = QVBoxLayout(sym_ciphers_group)

        sym_cipher_layout = QHBoxLayout()
        sym_cipher_layout.addWidget(QLabel("Cipher:"))
        self.sym_cipher_combo = QComboBox()
        self.sym_cipher_combo.addItems(["AES", "TripleDES", "Blowfish", "RC4"])
        self.sym_cipher_combo.currentTextChanged.connect(self.update_sym_modes)
        sym_cipher_layout.addWidget(self.sym_cipher_combo)
        sym_ciphers_layout.addLayout(sym_cipher_layout)

        sym_mode_layout = QHBoxLayout()
        sym_mode_layout.addWidget(QLabel("Mode:"))
        self.sym_mode_combo = QComboBox()
        sym_mode_layout.addWidget(self.sym_mode_combo)
        sym_ciphers_layout.addLayout(sym_mode_layout)

        sym_key_layout = QHBoxLayout()
        sym_key_layout.addWidget(QLabel("Key (hex):"))
        self.sym_key_input = QLineEdit()
        self.sym_key_input.setPlaceholderText("e.g., 001122...ff")
        sym_key_layout.addWidget(self.sym_key_input)
        sym_ciphers_layout.addLayout(sym_key_layout)

        sym_iv_layout = QHBoxLayout()
        sym_iv_layout.addWidget(QLabel("IV (hex):"))
        self.sym_iv_input = QLineEdit()
        self.sym_iv_input.setPlaceholderText("e.g., 001122...ff")
        sym_iv_layout.addWidget(self.sym_iv_input)
        sym_ciphers_layout.addLayout(sym_iv_layout)

        sym_button = QPushButton("Run Symmetric Cipher")
        sym_button.clicked.connect(self.handle_symmetric_operation)
        sym_ciphers_layout.addWidget(sym_button)

        sym_ciphers_layout.addStretch()
        controls_layout.addWidget(sym_ciphers_group)

        main_layout.addLayout(controls_layout)

        # Bottom mode selection
        mode_layout = QHBoxLayout()
        mode_layout.addWidget(QLabel("Mode:"))
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Encode / Encrypt", "Decode / Decrypt"])
        mode_layout.addWidget(self.mode_combo)
        mode_layout.addStretch()
        main_layout.addLayout(mode_layout)

    def add_buttons(self, layout, names):
        for name in names:
            button = QPushButton(name)
            button.clicked.connect(self.handle_operation)
            layout.addWidget(button)

    def update_sym_modes(self):
        cipher = self.sym_cipher_combo.currentText()
        self.sym_mode_combo.clear()

        # Stream ciphers like RC4 don't use modes
        if cipher in ["RC4"]:
            self.sym_mode_combo.setEnabled(False)
            self.sym_iv_input.setEnabled(False)
            return

        self.sym_mode_combo.setEnabled(True)
        self.sym_iv_input.setEnabled(True)

        # All other block ciphers in this list support these modes
        self.sym_mode_combo.addItems(["CBC", "ECB", "CFB", "OFB"])

    def handle_operation(self):
        sender = self.sender()
        operation = sender.text()

        input_text = self.input_text.toPlainText()
        if not input_text:
            return

        mode = "Encode" if self.mode_combo.currentIndex() == 0 else "Decode"

        try:
            result = self.dispatch_operation(operation, input_text, mode)
            self.output_text.setPlainText(result)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")
            self.output_text.setPlainText(f"Error: {str(e)}")

    def handle_symmetric_operation(self):
        input_text = self.input_text.toPlainText()
        if not input_text:
            return

        mode = "Encrypt" if self.mode_combo.currentIndex() == 0 else "Decrypt"
        cipher_name = self.sym_cipher_combo.currentText()
        mode_name = self.sym_mode_combo.currentText()
        key_hex = self.sym_key_input.text()
        iv_hex = self.sym_iv_input.text()

        try:
            if not key_hex:
                raise ValueError("Key cannot be empty.")

            # For modes that don't require an IV
            if mode_name == "ECB" and not iv_hex:
                iv_hex = "00" * 16 # Dummy IV, won't be used but needed for function signature

            if mode != "ECB" and not iv_hex and cipher_name != "RC4":
                 raise ValueError("IV cannot be empty for this mode.")

            if mode == "Encrypt":
                if cipher_name == "RC4":
                    # Input is text, output is bytes, so we hex encode for display
                    result_bytes = symmetric_encrypt(cipher_name, mode_name, key_hex, iv_hex, input_text)
                    result = result_bytes.hex()
                else:
                    # Input is text, output is bytes, so we hex encode for display
                    result_bytes = symmetric_encrypt(cipher_name, mode_name, key_hex, iv_hex, input_text)
                    result = result_bytes.hex()
            else: # Decrypt
                # Input is hex, so we decode it to bytes first
                input_bytes = bytes.fromhex(input_text)
                if cipher_name == "RC4":
                    result = symmetric_decrypt(cipher_name, mode_name, key_hex, iv_hex, input_bytes).decode('utf-8', 'ignore')
                else:
                    result = symmetric_decrypt(cipher_name, mode_name, key_hex, iv_hex, input_bytes)

            self.output_text.setPlainText(result)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")
            self.output_text.setPlainText(f"Error: {str(e)}")

    def dispatch_operation(self, operation, text, mode):
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
            "ROT13": (rot13_cipher, rot13_cipher),
            "XOR": (self.run_xor_cipher, self.run_xor_decipher)
        }

        if operation in op_map:
            func = op_map[operation][0] if is_encode else op_map[operation][1]
            # Handle text vs bytes for output
            result = func(text)
            if isinstance(result, bytes):
                return base64.b64encode(result).decode('utf-8')
            return result

        raise ValueError(f"Unknown operation: {operation}")

    def run_xor_cipher(self, text):
        key = self.xor_key_input.text()
        if not key:
            raise ValueError("XOR key cannot be empty.")
        return xor_cipher(text, key)

    def run_xor_decipher(self, text):
        key = self.xor_key_input.text()
        if not key:
            raise ValueError("XOR key cannot be empty.")
        return xor_decipher(text, key)
