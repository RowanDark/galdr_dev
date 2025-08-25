import unittest
from unittest.mock import patch, MagicMock

from galdr.core.raider_engine import RaiderEngine

class TestRaiderEngine(unittest.TestCase):

    def test_parse_simple_get_request(self):
        """Test parsing a simple GET request."""
        raw_request = (
            "GET /index.html HTTP/1.1\n"
            "Host: example.com\n"
            "User-Agent: Test-Agent"
        )
        engine = RaiderEngine(raw_request, [])
        headers, body, method, path, host, scheme = engine.parse_raw_request()

        self.assertEqual(method, "GET")
        self.assertEqual(path, "/index.html")
        self.assertEqual(host, "example.com")
        self.assertEqual(scheme, "http")
        self.assertEqual(headers['User-Agent'], "Test-Agent")
        self.assertIsNone(body)

    def test_parse_post_request_with_body(self):
        """Test parsing a POST request with a body."""
        raw_request = (
            "POST /login HTTP/1.1\n"
            "Host: example.com\n"
            "Content-Type: application/x-www-form-urlencoded\n\n"
            "user=test&pass=123"
        )
        engine = RaiderEngine(raw_request, [])
        headers, body, method, path, host, scheme = engine.parse_raw_request()

        self.assertEqual(method, "POST")
        self.assertEqual(path, "/login")
        self.assertEqual(body, "user=test&pass=123")
        self.assertEqual(headers['Content-Type'], "application/x-www-form-urlencoded")

    def test_missing_host_header(self):
        """Test that a missing Host header raises a ValueError."""
        raw_request = "GET / HTTP/1.1\n"
        engine = RaiderEngine(raw_request, [])
        with self.assertRaises(ValueError):
            engine.parse_raw_request()

    @patch('requests.request')
    def test_sniper_attack_body_injection(self, mock_request):
        """Test payload injection in the request body."""
        raw_request = (
            "POST /search HTTP/1.1\n"
            "Host: example.com\n\n"
            "query=§"
        )
        payloads = ["payload1", "payload2"]

        with patch('PyQt6.QtCore.QThread.start'):
            engine = RaiderEngine(raw_request, payloads)
            # Mock the signals to prevent Qt errors
            engine.result_ready = MagicMock()
            engine.attack_finished = MagicMock()
            engine.run()

        self.assertEqual(mock_request.call_count, 2)

        args, kwargs = mock_request.call_args_list[0]
        self.assertEqual(kwargs['data'], b'query=payload1')

        args, kwargs = mock_request.call_args_list[1]
        self.assertEqual(kwargs['data'], b'query=payload2')

    @patch('requests.request')
    def test_sniper_attack_header_injection(self, mock_request):
        """Test payload injection in a request header."""
        raw_request = (
            "GET / HTTP/1.1\n"
            "Host: example.com\n"
            "User-Agent: Galdr-§"
        )
        payloads = ["1.0", "2.0"]

        with patch('PyQt6.QtCore.QThread.start'):
            engine = RaiderEngine(raw_request, payloads)
            engine.result_ready = MagicMock()
            engine.attack_finished = MagicMock()
            engine.run()

        self.assertEqual(mock_request.call_count, 2)

        args, kwargs = mock_request.call_args_list[0]
        self.assertEqual(kwargs['headers']['User-Agent'], "Galdr-1.0")

        args, kwargs = mock_request.call_args_list[1]
        self.assertEqual(kwargs['headers']['User-Agent'], "Galdr-2.0")

if __name__ == '__main__':
    unittest.main()
