import unittest
from unittest.mock import patch, AsyncMock

from galdr.core.passive_scanner import PassiveSecurityScanner
from galdr.core.active_scanner import ActiveSecurityScanner

class TestMiscChecks(unittest.TestCase):

    # --- Passive CSRF Tests ---
    def test_passive_csrf_check_no_token(self):
        # Arrange
        scanner = PassiveSecurityScanner()
        mock_headers = {'Content-Type': 'text/html'}
        mock_body = """
        <html><body>
        <form method="post" action="/transfer">
            <input type="text" name="amount">
            <input type="submit" value="Transfer">
        </form>
        </body></html>
        """

        # Act
        findings = scanner.check_csrf_protection("http://test.com", mock_headers, mock_body, {})

        # Assert
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "Missing Anti-CSRF Token")

    def test_passive_csrf_check_with_token(self):
        # Arrange
        scanner = PassiveSecurityScanner()
        mock_headers = {'Content-Type': 'text/html'}
        mock_body = """
        <html><body>
        <form method="post" action="/transfer">
            <input type="hidden" name="csrf_token" value="abc123xyz">
            <input type="text" name="amount">
            <input type="submit" value="Transfer">
        </form>
        </body></html>
        """

        # Act
        findings = scanner.check_csrf_protection("http://test.com", mock_headers, mock_body, {})

        # Assert
        self.assertEqual(len(findings), 0)

    # --- Active Command Injection Tests ---
    @patch('galdr.core.active_scanner.ActiveSecurityScanner._send_request', new_callable=AsyncMock)
    def test_active_command_injection_found(self, mock_send_request):
        # Arrange
        base_request = {'url': 'http://test.com/page?file=test', 'method': 'GET', 'headers': {}, 'body': ''}
        scanner = ActiveSecurityScanner(base_request)
        findings = []
        scanner.finding_detected.connect(lambda f: findings.append(f['finding']))

        # Configure the mock to return different values on subsequent calls
        mock_send_request.side_effect = [
            # First call (baseline)
            {'response_time_sec': 0.5, 'status': 200, 'text': '', 'headers': {}, 'payload': 'GaldrBaselineCheck', 'url': ''},
            # Second call (timed payload)
            {'response_time_sec': 10.5, 'status': 200, 'text': '', 'headers': {}, 'payload': '&& sleep 10', 'url': ''}
        ]

        # Act
        original_checks = scanner.checks
        scanner.checks = [("Command Injection", scanner.check_command_injection)]
        scanner.run_scan()
        scanner.checks = original_checks

        # Assert
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding['title'], "Command Injection")
        self.assertEqual(finding['severity'], "High")

if __name__ == '__main__':
    unittest.main()
