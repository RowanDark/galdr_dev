import unittest
from galdr.utils.crypto_utils import (
    base32_encode, base32_decode,
    base45_encode, base45_decode,
    base58_encode, base58_decode,
    base62_encode, base62_decode,
    base85_encode, base85_decode,
    text_to_decimal, decimal_to_text,
    text_to_binary, binary_to_text,
    text_to_octal, octal_to_text,
    rot13_cipher,
    xor_cipher, xor_decipher
)

class TestCryptoUtils(unittest.TestCase):

    def test_base32(self):
        original = "Hello, World!"
        encoded = base32_encode(original)
        decoded = base32_decode(encoded)
        self.assertEqual(decoded, original)
        self.assertEqual(base32_encode(""), "")
        self.assertEqual(base32_decode(""), "")

    def test_base45(self):
        original = "Hello, World!"
        encoded = base45_encode(original)
        decoded = base45_decode(encoded)
        self.assertEqual(decoded, original)
        self.assertEqual(base45_encode(""), "")
        self.assertEqual(base45_decode(""), "")

    def test_base58(self):
        original = "Hello, World!"
        encoded = base58_encode(original)
        decoded = base58_decode(encoded)
        self.assertEqual(decoded, original)
        self.assertEqual(base58_encode(""), "")
        self.assertEqual(base58_decode(""), "")

    def test_base62(self):
        original = "Hello, World!"
        encoded = base62_encode(original)
        decoded = base62_decode(encoded)
        self.assertEqual(decoded, original)
        self.assertEqual(base62_encode(""), "")
        self.assertEqual(base62_decode(""), "")

    def test_base85(self):
        original = "Hello, World!"
        encoded = base85_encode(original)
        decoded = base85_decode(encoded)
        self.assertEqual(decoded, original)
        self.assertEqual(base85_encode(""), "")
        self.assertEqual(base85_decode(""), "")

    def test_decimal(self):
        original = "ABC"
        encoded = text_to_decimal(original)
        self.assertEqual(encoded, "65 66 67")
        decoded = decimal_to_text(encoded)
        self.assertEqual(decoded, original)

    def test_binary(self):
        original = "ABC"
        encoded = text_to_binary(original)
        self.assertEqual(encoded, "01000001 01000010 01000011")
        decoded = binary_to_text(encoded)
        self.assertEqual(decoded, original)

    def test_octal(self):
        original = "ABC"
        encoded = text_to_octal(original)
        self.assertEqual(encoded, "101 102 103")
        decoded = octal_to_text(encoded)
        self.assertEqual(decoded, original)

    def test_rot13(self):
        original = "Hello, World!"
        encoded = rot13_cipher(original)
        self.assertEqual(encoded, "Uryyb, Jbeyq!")
        decoded = rot13_cipher(encoded)
        self.assertEqual(decoded, original)

    def test_xor(self):
        original = "Hello, World!"
        key = "key"
        encoded = xor_cipher(original, key)
        self.assertNotEqual(encoded, original)
        decoded = xor_decipher(encoded, key)
        self.assertEqual(decoded, original)

if __name__ == '__main__':
    unittest.main()
