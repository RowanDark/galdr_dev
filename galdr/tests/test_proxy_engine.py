import unittest
from unittest.mock import Mock, MagicMock, patch
import threading


from galdr.core.proxy_engine import ProxyAddon, InterceptedFlow, ProxySignals

class TestProxyEngine(unittest.TestCase):

    def setUp(self):
        """Set up for each test."""
        self.mock_signals = Mock(spec=ProxySignals)
        self.addon = ProxyAddon(self.mock_signals)

    def create_mock_flow(self):
        """Creates a mock mitmproxy HTTPFlow object."""
        flow = MagicMock()
        flow.id = "test-flow-id"
        flow.request.method = "GET"
        flow.request.url = "http://example.com"
        flow.request.headers = {"Host": "example.com"}
        flow.request.content = b"request content"
        flow.response.status_code = 200
        flow.response.headers = {"Content-Type": "text/html"}
        flow.response.content = b"response content"
        return flow

    def test_response_emits_new_flow_signal(self):
        """Test that the response handler emits the new_flow signal."""
        mock_flow = self.create_mock_flow()

        self.addon.response(mock_flow)

        self.mock_signals.new_flow.emit.assert_called_once()
        emitted_data = self.mock_signals.new_flow.emit.call_args[0][0]
        self.assertEqual(emitted_data['id'], mock_flow.id)
        self.assertEqual(emitted_data['request']['url'], mock_flow.request.url)

    def test_request_interception_disabled(self):
        """Test that the request handler does nothing when interception is off."""
        self.addon.intercept_enabled = False
        mock_flow = self.create_mock_flow()

        self.addon.request(mock_flow)

        self.mock_signals.request_intercepted.emit.assert_not_called()
        self.assertIsNone(self.addon.intercepted_flow)

    @patch('threading.Event.wait')
    def test_request_interception_enabled(self, mock_event_wait):
        """Test that the request handler intercepts when enabled."""
        self.addon.intercept_enabled = True
        mock_flow = self.create_mock_flow()

        self.addon.request(mock_flow)

        self.assertIsNotNone(self.addon.intercepted_flow)
        self.assertEqual(self.addon.intercepted_flow.flow, mock_flow)
        self.mock_signals.request_intercepted.emit.assert_called_once()
        mock_event_wait.assert_called_once()

    def test_resume_flow_without_modification(self):
        """Test resuming a flow without changes."""
        mock_flow = self.create_mock_flow()
        self.addon.intercepted_flow = InterceptedFlow(mock_flow)

        self.addon.resume_flow(None)

        mock_flow.resume.assert_called_once()
        self.assertIsNone(self.addon.intercepted_flow)

    def test_resume_flow_with_modification(self):
        """Test resuming a flow with a modified request."""
        mock_flow = self.create_mock_flow()
        self.addon.intercepted_flow = InterceptedFlow(mock_flow)

        modified_request = {
            "method": "POST",
            "url": "http://modified.com",
            "headers": {"New-Header": "value"},
            "content": b"modified content"
        }

        self.addon.resume_flow(modified_request)

        self.assertEqual(mock_flow.request.method, "POST")
        self.assertEqual(mock_flow.request.url, "http://modified.com")
        self.assertEqual(mock_flow.request.content, b"modified content")
        mock_flow.resume.assert_called_once()
        self.assertIsNone(self.addon.intercepted_flow)

    def test_drop_flow(self):
        """Test dropping an intercepted flow."""
        mock_flow = self.create_mock_flow()
        self.addon.intercepted_flow = InterceptedFlow(mock_flow)

        self.addon.drop_flow()

        mock_flow.kill.assert_called_once()
        self.assertIsNone(self.addon.intercepted_flow)

if __name__ == '__main__':
    unittest.main()
