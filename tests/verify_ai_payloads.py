import unittest
from unittest.mock import MagicMock, AsyncMock
import os
import sys
import requests
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
import time

# Add project root to path to allow importing galdr
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from galdr.scanner.checks.sqli_check import SqliCheck, Vulnerability

# --- Mock Web Application that is vulnerable to a specific AI payload ---
class MockVulnerableServer(BaseHTTPRequestHandler):
    # This error pattern must exist in galdr/scanner/payloads/sqli_errors.txt
    SQL_ERROR_MESSAGE = "You have an error in your SQL syntax"

    def do_GET(self):
        # Check if the parameter 'id' contains the specific payload we expect from the mock AI
        if "id=' OR 1=1--" in self.path:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(self.SQL_ERROR_MESSAGE.encode('utf-8'))
        else:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"<html><body>OK</body></html>")

def run_mock_server(server_class=HTTPServer, handler_class=MockVulnerableServer, port=8001):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()

# --- Verification Test Case ---
class AIPayloadIntegrationTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Start the mock server in a background thread
        cls.mock_server_port = 8001
        cls.server_thread = Thread(target=run_mock_server, args=(HTTPServer, MockVulnerableServer, cls.mock_server_port), daemon=True)
        cls.server_thread.start()
        time.sleep(1)
        print(f"Mock vulnerable server running on port {cls.mock_server_port}")

    def test_sqli_check_uses_ai_payloads(self):
        """
        Tests that SqliCheck calls the AI analyzer and uses the provided payloads.
        """
        print("\n--- Running Test: AI Payload Generation Integration ---")

        # 1. Create a mock AI Analyzer
        mock_analyzer = MagicMock()

        # 2. Configure the mock's async generate_payloads method
        # This is the specific payload the mock server will react to
        ai_payload = "' OR 1=1--"
        mock_analyzer.generate_payloads = AsyncMock(return_value=[ai_payload])

        # 3. Instantiate the check with AI mode enabled and the mock analyzer
        target_url = f"http://localhost:{self.mock_server_port}/?id=1"
        sqli_check = SqliCheck(target_url=target_url, ai_mode=True, ai_analyzer=mock_analyzer)

        # 4. Run the check
        print("Running SqliCheck with AI mode enabled...")
        findings = sqli_check.run()

        # 5. Assertions
        # Assert that the AI function was called
        mock_analyzer.generate_payloads.assert_called_once()
        context_arg = mock_analyzer.generate_payloads.call_args[0][0]
        self.assertEqual(context_arg['param'], 'id')
        print("✅ ai_analyzer.generate_payloads was called with the correct parameter.")

        # Assert that a vulnerability was found using the AI payload
        self.assertEqual(len(findings), 1, "Expected to find exactly one SQLi vulnerability.")
        finding = findings[0]
        self.assertIsInstance(finding, Vulnerability)
        self.assertIn(ai_payload, finding.details, "Vulnerability details should include the AI-generated payload.")
        print(f"✅ Vulnerability correctly identified using AI payload: {finding.details}")

        print("--- ✅ Test Passed: AI Payload Generation Integration ---")

if __name__ == "__main__":
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(AIPayloadIntegrationTest))
    runner = unittest.TextTestRunner()
    runner.run(suite)
