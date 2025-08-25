import unittest
import os
import tempfile
import shutil

from galdr.payloads.manager import PayloadManager

class TestPayloadManager(unittest.TestCase):

    def setUp(self):
        # Create a temporary directory for test payload files
        self.test_dir = tempfile.mkdtemp()
        self.payload_manager = PayloadManager(payload_path=self.test_dir)

    def tearDown(self):
        # Clean up the temporary directory
        shutil.rmtree(self.test_dir)

    def test_get_available_lists(self):
        # Arrange
        with open(os.path.join(self.test_dir, "list1.txt"), "w") as f:
            f.write("a\nb\n")
        with open(os.path.join(self.test_dir, "list2.txt"), "w") as f:
            f.write("c\nd\n")
        # Create a non-txt file that should be ignored
        with open(os.path.join(self.test_dir, "list3.dat"), "w") as f:
            f.write("e\n")

        # Act
        lists = self.payload_manager.get_available_lists()

        # Assert
        self.assertEqual(len(lists), 2)
        self.assertIn("list1.txt", lists)
        self.assertIn("list2.txt", lists)
        self.assertNotIn("list3.dat", lists)

    def test_load_payload_list(self):
        # Arrange
        payloads_in = ["payload1", "payload2", "  payload3  "]
        with open(os.path.join(self.test_dir, "test.txt"), "w") as f:
            f.write("\n".join(payloads_in))

        # Act
        payloads_out = self.payload_manager.load_payload_list("test.txt")

        # Assert
        self.assertEqual(len(payloads_out), 3)
        self.assertEqual(payloads_out[0], "payload1")
        self.assertEqual(payloads_out[2], "payload3") # Check that whitespace is stripped

    def test_load_nonexistent_list(self):
        # Act
        payloads = self.payload_manager.load_payload_list("nonexistent.txt")
        # Assert
        self.assertEqual(payloads, [])

if __name__ == '__main__':
    unittest.main()
