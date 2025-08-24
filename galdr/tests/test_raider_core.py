import unittest
import asyncio
import sys
from unittest.mock import patch, MagicMock, AsyncMock

from PyQt6.QtCore import QCoreApplication

from galdr.raider.raider_core import RaiderManager

app = None

def setUpModule():
    """Create a QCoreApplication instance for non-GUI testing."""
    global app
    # Use QCoreApplication for tests that don't need a GUI.
    app = QCoreApplication.instance()
    if app is None:
        app = QCoreApplication(sys.argv)

def tearDownModule():
    """Clean up the QApplication instance after all tests are done."""
    global app
    app = None

class TestRaiderCore(unittest.TestCase):

    def setUp(self):
        self.template = "http://test.com?q=§payload§"
        self.injection_point = "§payload§"
        self.payloads = ["p1", "p2", "p3"]
        self.manager = RaiderManager(self.template, [self.injection_point], self.payloads)
        self.results = []
        self.manager.request_completed.connect(lambda r: self.results.append(r))

    def test_start_creates_and_starts_thread(self):
        thread_patcher = patch('galdr.raider.raider_core.Thread')
        mock_thread = thread_patcher.start()
        self.addCleanup(thread_patcher.stop)

        # Act
        self.manager.start()

        # Assert
        mock_thread.assert_called_once_with(target=self.manager._run_fuzzing_job, daemon=True)
        mock_thread.return_value.start.assert_called_once()

    def test_run_fuzzing_job_calls_async_loop(self):
        run_patcher = patch('galdr.raider.raider_core.asyncio.run')
        mock_asyncio_run = run_patcher.start()
        self.addCleanup(run_patcher.stop)

        # Act
        self.manager._run_fuzzing_job()

        # Assert
        # We can't assert the coroutine object directly, but we can check the call.
        self.assertTrue(mock_asyncio_run.called)

    def test_fuzzing_loop_sends_requests(self):
        playwright_patcher = patch('galdr.raider.raider_core.async_playwright')
        mock_async_playwright = playwright_patcher.start()
        self.addCleanup(playwright_patcher.stop)

        # Arrange
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.body = AsyncMock(return_value=b'response_body')

        mock_page = MagicMock()
        mock_page.request.fetch = AsyncMock(return_value=mock_response)

        mock_context = AsyncMock()
        mock_context.new_page.return_value = mock_page

        mock_browser = AsyncMock()
        mock_browser.new_context.return_value = mock_context

        mock_playwright_instance = AsyncMock()
        mock_playwright_instance.chromium.launch.return_value = mock_browser

        # The entry point for the `async with` statement
        mock_async_playwright.return_value.__aenter__.return_value = mock_playwright_instance

        # Act
        asyncio.run(self.manager._fuzzing_loop())

        # Assert
        self.assertEqual(len(self.results), len(self.payloads))
        self.assertEqual(self.results[0]['payload'], 'p1')
        self.assertEqual(self.results[1]['payload'], 'p2')
        self.assertEqual(self.results[2]['payload'], 'p3')
        self.assertEqual(self.results[0]['status'], 200)

if __name__ == '__main__':
    unittest.main()
