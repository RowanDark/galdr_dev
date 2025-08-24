import unittest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock

from galdr.core.passive_scanner import PassiveSecurityScanner
from galdr.core.active_scanner import ActiveSecurityScanner
from galdr.core.finding import SecurityFinding

class TestXSSChecks(unittest.TestCase):

    def test_passive_weak_csp_check(self):
        # Arrange
        scanner = PassiveSecurityScanner()
        csp_header = "script-src 'unsafe-inline' example.com"

        # Act
        findings = scanner._check_csp(csp_header)

        # Assert
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.title, "Weak Content Security Policy")
        self.assertIn("'unsafe-inline'", finding.description)

    def test_passive_permissive_csp_check(self):
        # Arrange
        scanner = PassiveSecurityScanner()
        csp_header = "script-src *"

        # Act
        findings = scanner._check_csp(csp_header)

        # Assert
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.title, "Permissive Content Security Policy")
        self.assertIn("wildcard ('*')", finding.description)

    @patch('galdr.core.active_scanner.ActiveSecurityScanner._send_request', new_callable=AsyncMock)
    def test_active_reflected_xss_found(self, mock_send_request):
        # Arrange
        base_request = {
            'url': 'http://test.com/page?param=test',
            'method': 'GET',
            'headers': {},
            'body': ''
        }
        scanner = ActiveSecurityScanner(base_request)
        findings = []
        scanner.finding_detected.connect(lambda f: findings.append(f['finding']))

        payload = "<script>alert('GaldrXSS')</script>"
        mock_send_request.return_value = {
            'status': 200,
            'text': f"<html><body>{payload}</body></html>",
            'headers': {'content-type': 'text/html'},
            'payload': payload,
            'url': f'http://test.com/page?param={payload}'
        }

        # Act
        # We need to run the scan, but only for the XSS check to be efficient
        # A bit of a workaround: temporarily replace checks
        original_checks = scanner.builtin_checks
        scanner.builtin_checks = [("Reflected XSS", scanner.check_reflected_xss)]
        scanner.run_scan()
        scanner.builtin_checks = original_checks # restore

        # Assert
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding['title'], "Reflected Cross-Site Scripting (XSS)")
        self.assertEqual(finding['severity'], "High")

if __name__ == '__main__':
    unittest.main()
