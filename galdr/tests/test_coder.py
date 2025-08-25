import unittest
from galdr.utils.coder import Coder

class TestCoder(unittest.TestCase):

    def test_url_encoding(self):
        plain = "a test string with spaces & symbols!"
        encoded = "a%20test%20string%20with%20spaces%20%26%20symbols%21"
        self.assertEqual(Coder.url_encode(plain), encoded)
        self.assertEqual(Coder.url_decode(encoded), plain)
        self.assertEqual(Coder.url_encode(""), "")
        self.assertEqual(Coder.url_decode(""), "")

    def test_base64_encoding(self):
        plain = "Galdr base64 test"
        encoded = "R2FsZHIgYmFzZTY0IHRlc3Q="
        self.assertEqual(Coder.base64_encode(plain), encoded)
        self.assertEqual(Coder.base64_decode(encoded), plain)
        self.assertEqual(Coder.base64_encode(""), "")
        self.assertEqual(Coder.base64_decode(""), "")
        self.assertIn("Error", Coder.base64_decode("invalid-base64"))

    def test_html_encoding(self):
        plain = "<p>Hello & Welcome!</p>"
        encoded = "&lt;p&gt;Hello &amp; Welcome!&lt;/p&gt;"
        self.assertEqual(Coder.html_encode(plain), encoded)
        self.assertEqual(Coder.html_decode(encoded), plain)
        self.assertEqual(Coder.html_encode(""), "")
        self.assertEqual(Coder.html_decode(""), "")

    def test_hex_encoding(self):
        plain = "Galdr hex test"
        encoded = "47616c6472206865782074657374"
        self.assertEqual(Coder.hex_encode(plain), encoded)
        self.assertEqual(Coder.hex_decode(encoded), plain)
        self.assertEqual(Coder.hex_encode(""), "")
        self.assertEqual(Coder.hex_decode(""), "")
        # Test with spaces in hex string
        self.assertEqual(Coder.hex_decode("47 61 6c 64 72"), "Galdr")
        self.assertIn("Error", Coder.hex_decode("invalid hex"))

if __name__ == '__main__':
    unittest.main()
