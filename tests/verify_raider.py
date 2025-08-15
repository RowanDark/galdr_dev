import unittest
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

# Add project root to path to allow importing galdr
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from PyQt6.QtWidgets import QApplication
from galdr.gui.raider_tab import RaiderTab

# --- Mock Web Server ---
class MockServer(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"Galdr Raider Target OK")

def run_mock_server(server_class=HTTPServer, handler_class=MockServer, port=8002):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()

# --- Verification Test Case ---
class RaiderFeatureTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Start the mock server in a background thread
        cls.mock_server_port = 8002
        cls.server_thread = Thread(target=run_mock_server, args=(HTTPServer, MockServer, cls.mock_server_port), daemon=True)
        cls.server_thread.start()
        time.sleep(1)
        print(f"Mock server running on port {cls.mock_server_port}")

        # A QApplication is needed to instantiate Qt widgets
        cls.app = QApplication.instance()
        if cls.app is None:
            cls.app = QApplication(sys.argv)

    def test_raider_attack_completes_and_populates_results(self):
        """
        Tests the full loop of the Raider tool: configure, start, run, and get results.
        """
        print("\n--- Running Test: Raider Feature Verification ---")

        # 1. Instantiate the RaiderTab
        raider_tab = RaiderTab()

        # 2. Configure the UI programmatically
        target_url = f"http://localhost:{self.mock_server_port}/?param=§"
        raider_tab.url_input.setText(target_url)

        payloads = ["test1", "test2", "test3"]
        raider_tab.simple_payload_list.setPlainText("\n".join(payloads))
        raider_tab.payload_tabs.setCurrentIndex(0) # Ensure Simple List tab is active

        # 3. Start the attack
        print("Starting Raider attack...")
        raider_tab.start_attack()

        # 4. Wait for the attack thread to finish
        self.assertIsNotNone(raider_tab.attack_thread, "Attack thread was not created.")

        # Wait for up to 20 seconds for the thread to complete
        raider_tab.attack_thread.wait(20000)

        self.assertFalse(raider_tab.attack_thread.isRunning(), "Attack thread did not finish in time.")
        print("Attack thread finished.")

        # 5. Verify the results table
        row_count = raider_tab.results_table.rowCount()
        self.assertEqual(row_count, len(payloads), f"Expected {len(payloads)} rows in results table, but found {row_count}.")
        print(f"✅ Correct number of results ({row_count}) found in the table.")

        # Check content of the first row
        status = raider_tab.results_table.item(0, 2).text()
        length = raider_tab.results_table.item(0, 3).text()
        self.assertEqual(status, "200")
        self.assertEqual(length, str(len(b"Galdr Raider Target OK")))
        print("✅ First result row has correct status and length.")

        print("--- ✅ Test Passed: Raider Feature Verification ---")

if __name__ == "__main__":
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(RaiderFeatureTest))
    runner = unittest.TextTestRunner()
    runner.run(suite)
