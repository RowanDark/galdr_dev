import unittest
from unittest.mock import patch, AsyncMock

from galdr.core.active_scanner import ActiveSecurityScanner

class TestSQLiChecks(unittest.TestCase):

    def setUp(self):
        self.base_request = {
            'url': 'http://test.com/page?id=1',
            'method': 'GET',
            'headers': {},
            'body': ''
        }
        self.scanner = ActiveSecurityScanner(self.base_request)
        self.findings = []
        self.scanner.finding_detected.connect(lambda f: self.findings.append(f['finding']))

    @patch('galdr.core.active_scanner.ActiveSecurityScanner._send_request', new_callable=AsyncMock)
    def test_error_based_sqli_found(self, mock_send_request):
        # Arrange
        payload = "'"
        mock_send_request.return_value = {
            'status': 500,
            'text': "Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''1''' at line 1",
            'headers': {'content-type': 'text/html'},
            'payload': payload,
            'url': f'http://test.com/page?id=1{payload}'
        }

        # Act
        original_checks = self.scanner.checks
        self.scanner.checks = [("SQL Injection", self.scanner.check_sql_injection)]
        self.scanner.run_scan()
        self.scanner.checks = original_checks

        # Assert
        self.assertEqual(len(self.findings), 1)
        finding = self.findings[0]
        self.assertEqual(finding['title'], "SQL Injection")
        self.assertEqual(finding['severity'], "High")
        self.assertEqual(finding['confidence'], "Firm")

    @patch('galdr.core.active_scanner.ActiveSecurityScanner._send_request', new_callable=AsyncMock)
    def test_no_sqli_found(self, mock_send_request):
        # Arrange
        payload = "'"
        mock_send_request.return_value = {
            'status': 200,
            'text': "<html><body>No results found.</body></html>",
            'headers': {'content-type': 'text/html'},
            'payload': payload,
            'url': f'http://test.com/page?id=1{payload}'
        }

        # Act
        original_checks = self.scanner.checks
        self.scanner.checks = [("SQL Injection", self.scanner.check_sql_injection)]
        self.scanner.run_scan()
        self.scanner.checks = original_checks

        # Assert
        self.assertEqual(len(self.findings), 0)

if __name__ == '__main__':
    unittest.main()
