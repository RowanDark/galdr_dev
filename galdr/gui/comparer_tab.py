import difflib
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit, QGroupBox,
    QRadioButton
)
from PyQt6.QtGui import QFont, QTextCharFormat, QColor

class ComparerTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        self.connect_signals()

    def init_ui(self):
        main_layout = QVBoxLayout(self)

        # --- Controls ---
        controls_group = QGroupBox("Comparer Controls")
        controls_layout = QHBoxLayout(controls_group)

        self.compare_btn = QPushButton("Compare")
        controls_layout.addWidget(self.compare_btn)

        self.word_diff_radio = QRadioButton("Word-level diff")
        self.char_diff_radio = QRadioButton("Character-level diff")
        self.word_diff_radio.setChecked(True)
        controls_layout.addWidget(self.word_diff_radio)
        controls_layout.addWidget(self.char_diff_radio)

        controls_layout.addStretch()
        main_layout.addWidget(controls_group)

        # --- Text Panes ---
        text_layout = QHBoxLayout()

        self.text1_editor = QTextEdit()
        self.text1_editor.setFont(QFont("Courier", 10))
        self.text1_editor.setPlaceholderText("Paste first text block here...")

        self.text2_editor = QTextEdit()
        self.text2_editor.setFont(QFont("Courier", 10))
        self.text2_editor.setPlaceholderText("Paste second text block here...")

        text_layout.addWidget(self.text1_editor)
        text_layout.addWidget(self.text2_editor)

        main_layout.addLayout(text_layout)

    def connect_signals(self):
        self.compare_btn.clicked.connect(self.compare_text)

    def compare_text(self):
        text1 = self.text1_editor.toPlainText()
        text2 = self.text2_editor.toPlainText()

        # Reset formatting first
        self.highlight_text(self.text1_editor, [])
        self.highlight_text(self.text2_editor, [])

        if self.word_diff_radio.isChecked():
            seq1 = text1.split()
            seq2 = text2.split()
        else: # Character-level
            seq1 = text1
            seq2 = text2

        matcher = difflib.SequenceMatcher(None, seq1, seq2)

        highlights1 = []
        highlights2 = []

        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == 'replace':
                highlights1.append((i1, i2, QColor("red")))
                highlights2.append((j1, j2, QColor("red")))
            elif tag == 'delete':
                highlights1.append((i1, i2, QColor("orange")))
            elif tag == 'insert':
                highlights2.append((j1, j2, QColor("green")))

        self.highlight_sequences(self.text1_editor, seq1, highlights1)
        self.highlight_sequences(self.text2_editor, seq2, highlights2)

    def highlight_sequences(self, editor, sequences, highlights):
        # This is a simplified highlighting logic. A real implementation would be
        # more careful about matching indices to cursor positions.
        full_text = editor.toPlainText()
        cursor = editor.textCursor()

        # Reset format
        cursor.select(cursor.SelectionType.Document)
        cursor.setCharFormat(QTextCharFormat())
        cursor.clearSelection()

        for start, end, color in highlights:
            # This logic assumes split by words. It needs to be smarter for chars.
            # For now, this is a visual approximation.
            start_pos = 0
            end_pos = 0

            # Find start position
            for i in range(start):
                start_pos += len(sequences[i]) + 1 # +1 for space

            # Find end position
            end_pos = start_pos
            for i in range(start, end):
                end_pos += len(sequences[i]) + 1

            cursor.setPosition(start_pos)
            cursor.setPosition(end_pos, cursor.MoveMode.KeepAnchor)

            fmt = QTextCharFormat()
            fmt.setBackground(color)
            cursor.mergeCharFormat(fmt)

    # This is a placeholder for a more robust highlighting implementation
    def highlight_text(self, editor, ranges):
        pass
