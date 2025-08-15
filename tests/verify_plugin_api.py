import unittest
from unittest.mock import patch, MagicMock
import os
import sys
import time
import subprocess
import requests

# Add project root to path to allow importing galdr
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from PyQt6.QtWidgets import QApplication
from galdr.gui.main_window import MainWindow

# --- Test Case ---
class PluginAPITest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # A QApplication is needed to instantiate Qt widgets
        cls.app = QApplication.instance()
        if cls.app is None:
            cls.app = QApplication(sys.argv)

    @patch('galdr.plugins.example_logger_plugin.ExampleLoggerPlugin.log_request')
    @patch('galdr.plugins.example_logger_plugin.ExampleLoggerPlugin.log_response')
    def test_plugin_api_integration(self, mock_log_response, mock_log_request):
        """
        Tests that the PluginManager loads the sample plugin and that the
        proxy hooks are called correctly.
        """
        print("\n--- Running Test: Plugin API Integration Verification ---")

        # 1. Instantiate the MainWindow, which will load the plugins
        # We need to pass a dummy user for the constructor
        print("Initializing MainWindow to load plugins...")
        main_window = MainWindow(authenticated_user="test_user")

        # 2. Verify that the custom tab from the plugin was added
        tab_found = False
        for i in range(main_window.tab_widget.count()):
            if "Example Tab" in main_window.tab_widget.tabText(i):
                tab_found = True
                break
        self.assertTrue(tab_found, "Custom tab from example plugin was not found in the UI.")
        print("✅ Custom tab was loaded successfully.")

        # 3. Start the proxy
        # This is a complex operation involving threads and subprocesses.
        # For this test, we will simulate the event flow instead of running the full proxy.
        print("Simulating a proxy 'flow_log' event...")

        # 4. Create a sample flow data dictionary
        sample_flow_data = {
            'id': 'flow-123',
            'method': 'GET',
            'url': 'http://example.com/plugin_test',
            'status': 200,
            'size': 123,
            'headers': {'Content-Type': 'text/html'},
            'body': '<html>Hello Plugin</html>'
        }

        # 5. Manually call the event handler in ProxyTab that triggers the hooks
        # This isolates the test to the hook-calling logic without needing the full proxy stack.
        main_window.proxy_tab._handle_event({
            "type": "flow_log",
            "data": sample_flow_data
        })

        # 6. Assert that our mocked hook methods were called
        mock_log_request.assert_called_once_with(sample_flow_data)
        print("✅ Plugin's request hook was called correctly.")

        mock_log_response.assert_called_once_with(sample_flow_data)
        print("✅ Plugin's response hook was called correctly.")

        print("--- ✅ Test Passed: Plugin API Integration ---")


if __name__ == "__main__":
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(PluginAPITest))
    runner = unittest.TextTestRunner()
    runner.run(suite)
