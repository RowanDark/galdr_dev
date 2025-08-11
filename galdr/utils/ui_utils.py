from PyQt6.QtGui import QTextCharFormat, QColor

def display_colored_diff(text_edit_widget, diff_lines):
    """
    Displays a list of diff lines in a QTextEdit widget with color highlighting.

    :param text_edit_widget: The QTextEdit widget to display the diff in.
    :param diff_lines: A list of strings representing the diff output.
    """
    text_edit_widget.clear()
    cursor = text_edit_widget.textCursor()

    # Define formats
    added_format = QTextCharFormat()
    added_format.setBackground(QColor(46, 125, 50)) # Green background
    added_format.setForeground(QColor(255, 255, 255))

    removed_format = QTextCharFormat()
    removed_format.setBackground(QColor(183, 28, 28)) # Red background
    removed_format.setForeground(QColor(255, 255, 255))

    context_format = QTextCharFormat()
    context_format.setForeground(QColor(117, 117, 117)) # Gray text

    for line in diff_lines:
        if line.startswith('+') and not line.startswith('+++'):
            cursor.setCharFormat(added_format)
        elif line.startswith('-') and not line.startswith('---'):
            cursor.setCharFormat(removed_format)
        else:
            cursor.setCharFormat(context_format)

        cursor.insertText(line)
