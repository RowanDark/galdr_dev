import unittest
from unittest.mock import MagicMock, patch

from galdr.proxy.proxy_core import ProxyManager, FlowAddon

class TestProxyCore(unittest.TestCase):

    def test_start_proxy(self):
        with patch('galdr.proxy.proxy_core.DumpMaster') as mock_dump_master, \
             patch('galdr.proxy.proxy_core.Thread') as mock_thread:

            # Arrange
            manager = ProxyManager()

            # Act
            manager.start_proxy(port=8888)

            # Assert
            mock_dump_master.assert_called_once()
            mock_thread.assert_called_once()
            mock_thread.return_value.start.assert_called_once()
            self.assertIsNotNone(manager.master)
            self.assertIsNotNone(manager.thread)

    def test_stop_proxy(self):
        with patch('galdr.proxy.proxy_core.DumpMaster') as mock_dump_master, \
             patch('galdr.proxy.proxy_core.Thread') as mock_thread:

            # Arrange
            manager = ProxyManager()

            mock_master_instance = mock_dump_master.return_value
            mock_thread_instance = mock_thread.return_value

            manager.master = mock_master_instance
            manager.thread = mock_thread_instance
            manager.thread.is_alive.return_value = True

            # Act
            manager.stop_proxy()

            # Assert
            mock_master_instance.shutdown.assert_called_once()
            mock_thread_instance.join.assert_called_once()
            self.assertIsNone(manager.master)
            self.assertIsNone(manager.thread)

    def test_flow_addon(self):
        # Arrange
        mock_manager = MagicMock()
        addon = FlowAddon(mock_manager)

        # Create a mock flow object that mimics mitmproxy's HTTPFlow
        mock_flow = MagicMock()
        mock_flow.id = "test-id"
        mock_flow.request.method = "GET"
        mock_flow.request.pretty_url = "http://example.com/test"
        mock_flow.request.headers.items.return_value = [("Host", "example.com")]
        mock_flow.request.get_text.return_value = "Request Body"

        mock_flow.response.status_code = 200
        mock_flow.response.reason = "OK"
        mock_flow.response.content = b"Response Body"
        mock_flow.response.headers.items.return_value = [("Content-Type", "text/html")]
        mock_flow.response.get_text.return_value = "Response Body"

        # Act
        addon.response(mock_flow)

        # Assert
        mock_manager.emit_flow.assert_called_once()

        # Check the data passed to emit_flow
        emitted_data = mock_manager.emit_flow.call_args[0][0]
        self.assertEqual(emitted_data['id'], "test-id")
        self.assertEqual(emitted_data['method'], "GET")
        self.assertEqual(emitted_data['url'], "http://example.com/test")
        self.assertEqual(emitted_data['status_code'], 200)
        self.assertEqual(emitted_data['request']['content'], "Request Body")
        self.assertEqual(emitted_data['response']['content'], "Response Body")


if __name__ == '__main__':
    unittest.main()
