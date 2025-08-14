import unittest
from unittest.mock import patch, MagicMock
import os
import sys
import time

# Add project root to path to allow importing galdr
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from PyQt6.QtWidgets import QApplication
from galdr.gui.ai_copilot_tab import AICoPilotTab

class ChatExportTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # A QApplication is needed to instantiate Qt widgets
        cls.app = QApplication.instance()
        if cls.app is None:
            cls.app = QApplication(sys.argv)

    def test_export_chat_functionality(self):
        """
        Tests the export_chat method by mocking the QFileDialog.
        """
        print("\n--- Running Test: Chat Export Verification ---")

        # 1. Create an instance of the tab. It needs a mock analyzer.
        mock_analyzer = MagicMock()
        copilot_tab = AICoPilotTab(ai_analyzer=mock_analyzer)

        # 2. Add some dummy chat history
        copilot_tab.chat_history = [
            {'sender': 'User', 'message': 'Hello AI', 'timestamp': '12:00:00', 'is_system': False},
            {'sender': 'AI Co-pilot', 'message': 'Hello User', 'timestamp': '12:00:01', 'is_system': False}
        ]

        # 3. Define the temporary file path for the mock to return
        temp_export_file = "temp_chat_export.md"

        # 4. Use mock.patch to replace QFileDialog.getSaveFileName
        with patch('PyQt6.QtWidgets.QFileDialog.getSaveFileName') as mock_dialog:
            # Configure the mock to return our temporary file path
            mock_dialog.return_value = (temp_export_file, "Markdown Files (*.md)")

            # Mock the QMessageBox to prevent it from showing
            with patch('PyQt6.QtWidgets.QMessageBox.information') as mock_infobox:

                # 5. Call the method we want to test
                print("Calling export_chat()...")
                copilot_tab.export_chat()

                # 6. Assert that the dialog was called
                mock_dialog.assert_called_once()
                print("QFileDialog.getSaveFileName was called as expected.")

                # Assert that the success message box was shown
                mock_infobox.assert_called_once()
                print("QMessageBox.information was called as expected.")

        # 7. Verify the file content
        self.assertTrue(os.path.exists(temp_export_file), "Export file was not created.")

        with open(temp_export_file, 'r', encoding='utf-8') as f:
            content = f.read()

        print(f"Content of exported file:\n---\n{content[:200]}...\n---")

        self.assertIn("Hello AI", content)
        self.assertIn("Hello User", content)
        self.assertIn("[12:00:00] User", content)
        self.assertIn("[12:00:01] AI Co-pilot", content)

        print("File content is correct.")

        # 8. Clean up the temporary file
        os.remove(temp_export_file)
        print(f"Cleaned up temporary file: {temp_export_file}")

        print("--- ✅ Test Passed: Chat Export Verification ---")


if __name__ == "__main__":
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(ChatExportTest))
    runner = unittest.TextTestRunner()
    runner.run(suite)
