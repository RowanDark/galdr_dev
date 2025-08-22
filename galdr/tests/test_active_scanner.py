import unittest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock

from galdr.core.active_scanner import ActiveSecurityScanner, SecurityFinding

class TestActiveSecurityScanner(unittest.TestCase):

    def setUp(self):
        self.base_request = {
            'url': 'http://test.com/page?param=test',
            'method': 'GET',
            'headers': {},
            'body': ''
        }
        self.scanner = ActiveSecurityScanner(self.base_request)
        self.findings = []
        self.scanner.finding_detected.connect(self.handle_finding)

    def handle_finding(self, finding_data):
        self.findings.append(finding_data['finding'])

    @patch('galdr.core.active_scanner.ActiveSecurityScanner._send_request', new_callable=AsyncMock)
    def test_file_path_traversal_found(self, mock_send_request):
        # Arrange
        mock_send_request.return_value = {
            'status': 200,
            'text': "root:x:0:0:root:/root:/bin/bash",
            'headers': {},
            'payload': '../../../../../../../../etc/passwd',
            'url': 'http://test.com/page?param=../../../../../../../../etc/passwd'
        }

        # Act
        self.scanner.run_scan()

        # Assert
        self.assertEqual(len(self.findings), 1)
        finding = self.findings[0]
        self.assertEqual(finding['title'], "File Path Traversal")
        self.assertEqual(finding['severity'], "High")

    @patch('galdr.core.active_scanner.ActiveSecurityScanner._send_request', new_callable=AsyncMock)
    def test_no_vulnerability_found(self, mock_send_request):
        # Arrange
        mock_send_request.return_value = {
            'status': 200,
            'text': "<html><body>Hello</body></html>",
            'headers': {},
            'payload': 'test',
            'url': 'http://test.com/page?param=test'
        }

        # Act
        self.scanner.run_scan()

        # Assert
        self.assertEqual(len(self.findings), 0)

if __name__ == '__main__':
    unittest.main()
