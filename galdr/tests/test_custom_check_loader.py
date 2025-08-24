import unittest
from unittest.mock import patch

from galdr.core.passive_scanner import PassiveSecurityScanner
from galdr.core.active_scanner import ActiveSecurityScanner
from galdr.custom_checks.example_debug_header_check import ExampleDebugHeaderCheck
from galdr.custom_checks.example_active_check import ExampleActiveCheck

class TestCustomCheckLoader(unittest.TestCase):

    def test_passive_loader(self):
        # Arrange & Act
        # The loader is called in the constructor
        scanner = PassiveSecurityScanner()

        # Assert
        # Check that the name of our custom check is in the list of loaded check names
        loaded_check_names = [check.__self__.name for check in scanner.checks if hasattr(check, '__self__') and hasattr(check.__self__, 'name')]
        self.assertIn(ExampleDebugHeaderCheck.name, loaded_check_names)

    @patch('galdr.core.active_scanner.asyncio') # prevent the event loop from actually running
    def test_active_loader(self, mock_asyncio):
        # Arrange & Act
        scanner = ActiveSecurityScanner({})

        # Assert
        self.assertEqual(len(scanner.custom_checks), 1)
        # Check class name to avoid dynamic import issues
        self.assertEqual(scanner.custom_checks[0].__class__.__name__, 'ExampleActiveCheck')

if __name__ == '__main__':
    unittest.main()
