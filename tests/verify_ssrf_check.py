import unittest
import os
import sys
import time
import requests
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from urllib.parse import urlparse, parse_qs
from PyQt6.QtCore import QCoreApplication

# Add project root to path to allow importing galdr
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from galdr.scanner.active_scanner import ActiveScanner
from galdr.scanner.checks.ssrf_check import SsrfCheck

# --- Mock Web Application with a time-based SSRF vulnerability ---
class MockVulnerableServer(BaseHTTPRequestHandler):
    def do_GET(self):
        url_parts = urlparse(self.path)
        params = parse_qs(url_parts.query)

        # The vulnerable parameter is 'url'
        if 'url' in params:
            try:
                # Simulate the SSRF by actually trying to fetch the provided URL
                requests.get(params['url'][0], timeout=10)
            except requests.exceptions.RequestException:
                # This is expected for our time-based payloads
                pass

        # Respond to the scanner
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"<html><body>Hello</body></html>")

def run_mock_server(server_class=HTTPServer, handler_class=MockVulnerableServer, port=8000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()

# --- Verification Test Case ---
class SSRFCheckTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Start the mock server in a background thread
        cls.mock_server_port = 8000
        cls.server_thread = Thread(target=run_mock_server, args=(HTTPServer, MockVulnerableServer, cls.mock_server_port), daemon=True)
        cls.server_thread.start()
        time.sleep(1) # Give server time to start
        print(f"Mock vulnerable server running on port {cls.mock_server_port}")

    def test_ssrf_check_identifies_vulnerability(self):
        """
        Tests that the SSRFCheck can correctly identify a time-based SSRF vulnerability.
        """
        print("\n--- Running Test: SSRF Check Verification ---")

        # We need a QCoreApplication for the QThread signals to work
        app = QCoreApplication.instance()
        if app is None:
            app = QCoreApplication(sys.argv)

        target_url = f"http://localhost:{self.mock_server_port}/?page=home&url=http://example.com"

        # Configure the scanner to run ONLY the SsrfCheck for this test
        scanner = ActiveScanner(targets=[target_url])
        scanner.checks_to_run = [SsrfCheck]

        found_vulnerabilities = []

        def on_vulnerability_found(vuln):
            print(f"✅ Vulnerability Found: {vuln.check_name} in parameter '{vuln.parameter}'")
            found_vulnerabilities.append(vuln)

        scanner.vulnerability_found.connect(on_vulnerability_found)

        print(f"Starting scanner against mock target: {target_url}")
        scanner.start()
        # Wait for the QThread to finish
        scanner.wait(30000) # 30 second timeout

        self.assertEqual(len(found_vulnerabilities), 1, "Expected to find exactly one SSRF vulnerability.")

        vuln = found_vulnerabilities[0]
        self.assertEqual(vuln.check_name, "Server-Side Request Forgery (Time-Based)")
        self.assertEqual(vuln.parameter, "url")
        self.assertEqual(vuln.severity, "High")

        print("--- ✅ Test Passed: SSRF Check Verification ---")

if __name__ == "__main__":
    # This allows running the test directly
    # Note: Payloads like httpbin.org/delay/X will require internet access.
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(SSRFCheckTest))
    runner = unittest.TextTestRunner()
    runner.run(suite)
