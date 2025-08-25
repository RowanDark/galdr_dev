import unittest
import asyncio
from unittest.mock import patch, AsyncMock

from galdr.raider.raider_core import RaiderManager

# Mocking PyQt6 QObject to avoid needing a QApplication instance
@patch('PyQt6.QtCore.QObject', new=unittest.mock.MagicMock)
class TestRaiderCore(unittest.TestCase):

    def setUp(self):
        self.template = "http://test.com?p1=§1§&p2=§2§"
        self.payloads = {
            "1": ["a1", "a2"],
            "2": ["b1", "b2"],
        }
        self.results = []

    def setup_manager(self, manager):
        """Helper to connect signals for a test."""
        self.results = []
        manager.request_completed.connect(lambda r: self.results.append(r))

    @patch('galdr.raider.raider_core.RaiderManager._send_request', new_callable=AsyncMock)
    def test_sniper_attack(self, mock_send_request):
        # Arrange
        mock_send_request.return_value = {"status": 200, "length": 10, "time_sec": 0.1}
        manager = RaiderManager(self.template, {"1": self.payloads["1"]}, "Sniper")
        self.setup_manager(manager)

        # Act
        asyncio.run(manager._fuzzing_loop())

        # Assert
        self.assertEqual(mock_send_request.call_count, 4)
        mock_send_request.assert_any_call(unittest.mock.ANY, "http://test.com?p1=a1&p2=§2§")
        mock_send_request.assert_any_call(unittest.mock.ANY, "http://test.com?p1=a2&p2=§2§")
        mock_send_request.assert_any_call(unittest.mock.ANY, "http://test.com?p1=§1§&p2=a1")
        mock_send_request.assert_any_call(unittest.mock.ANY, "http://test.com?p1=§1§&p2=a2")

    @patch('galdr.raider.raider_core.RaiderManager._send_request', new_callable=AsyncMock)
    def test_battering_ram_attack(self, mock_send_request):
        # Arrange
        mock_send_request.return_value = {"status": 200, "length": 10, "time_sec": 0.1}
        manager = RaiderManager(self.template, {"1": self.payloads["1"]}, "Battering Ram")
        self.setup_manager(manager)

        # Act
        asyncio.run(manager._fuzzing_loop())

        # Assert
        self.assertEqual(mock_send_request.call_count, 2)
        mock_send_request.assert_any_call(unittest.mock.ANY, "http://test.com?p1=a1&p2=a1")
        mock_send_request.assert_any_call(unittest.mock.ANY, "http://test.com?p1=a2&p2=a2")

    @patch('galdr.raider.raider_core.RaiderManager._send_request', new_callable=AsyncMock)
    def test_pitchfork_attack(self, mock_send_request):
        # Arrange
        mock_send_request.return_value = {"status": 200, "length": 10, "time_sec": 0.1}
        manager = RaiderManager(self.template, self.payloads, "Pitchfork")
        self.setup_manager(manager)

        # Act
        asyncio.run(manager._fuzzing_loop())

        # Assert
        self.assertEqual(mock_send_request.call_count, 2)
        mock_send_request.assert_any_call(unittest.mock.ANY, "http://test.com?p1=a1&p2=b1")
        mock_send_request.assert_any_call(unittest.mock.ANY, "http://test.com?p1=a2&p2=b2")

    @patch('galdr.raider.raider_core.RaiderManager._send_request', new_callable=AsyncMock)
    def test_cluster_bomb_attack(self, mock_send_request):
        # Arrange
        mock_send_request.return_value = {"status": 200, "length": 10, "time_sec": 0.1}
        manager = RaiderManager(self.template, self.payloads, "Cluster Bomb")
        self.setup_manager(manager)

        # Act
        asyncio.run(manager._fuzzing_loop())

        # Assert
        self.assertEqual(mock_send_request.call_count, 4)
        mock_send_request.assert_any_call(unittest.mock.ANY, "http://test.com?p1=a1&p2=b1")
        mock_send_request.assert_any_call(unittest.mock.ANY, "http://test.com?p1=a1&p2=b2")
        mock_send_request.assert_any_call(unittest.mock.ANY, "http://test.com?p1=a2&p2=b1")
        mock_send_request.assert_any_call(unittest.mock.ANY, "http://test.com?p1=a2&p2=b2")

if __name__ == '__main__':
    unittest.main()
