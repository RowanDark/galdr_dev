from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit, QGroupBox, QSplitter
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from galdr.utils import coding_utils, ui_utils

class ComparerTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        """Initialize the UI for the Comparer tab."""
        main_layout = QVBoxLayout(self)

        # Top splitter for the two text inputs
        input_splitter = QSplitter(Qt.Orientation.Horizontal)

        group1 = QGroupBox("Text 1")
        layout1 = QVBoxLayout(group1)
        self.text1_input = QTextEdit()
        self.text1_input.setPlaceholderText("Paste first block of text here...")
        layout1.addWidget(self.text1_input)

        group2 = QGroupBox("Text 2")
        layout2 = QVBoxLayout(group2)
        self.text2_input = QTextEdit()
        self.text2_input.setPlaceholderText("Paste second block of text here...")
        layout2.addWidget(self.text2_input)

        input_splitter.addWidget(group1)
        input_splitter.addWidget(group2)

        main_layout.addWidget(input_splitter)

        # Compare button
        self.compare_button = QPushButton("Compare")
        self.compare_button.clicked.connect(self.perform_comparison)
        main_layout.addWidget(self.compare_button)

        # Results area
        results_group = QGroupBox("Comparison Result")
        results_layout = QVBoxLayout(results_group)
        self.results_display = QTextEdit()
        self.results_display.setReadOnly(True)
        self.results_display.setFont(QFont("Courier", 9))
        results_layout.addWidget(self.results_display)

        main_layout.addWidget(results_group)

        self.setLayout(main_layout)

    def perform_comparison(self):
        """Generates and displays the diff between the two text inputs."""
        text1 = self.text1_input.toPlainText()
        text2 = self.text2_input.toPlainText()

        diff_lines = coding_utils.generate_diff(text1, text2)

        if not diff_lines:
            self.results_display.setPlainText("✅ No differences found.")
            return

        ui_utils.display_colored_diff(self.results_display, diff_lines)
