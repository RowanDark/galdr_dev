import unittest
import time
import jwt

from galdr.utils.crypto_utils import CryptoUtils

class TestCryptoUtils(unittest.TestCase):

    # --- Coder tests ---
    def test_url_encoding(self):
        plain = "a test string with spaces & symbols!"
        encoded = "a%20test%20string%20with%20spaces%20%26%20symbols%21"
        self.assertEqual(CryptoUtils.url_encode(plain), encoded)
        self.assertEqual(CryptoUtils.url_decode(encoded), plain)

    def test_base64_encoding(self):
        plain = "Galdr base64 test"
        encoded = "R2FsZHIgYmFzZTY0IHRlc3Q="
        self.assertEqual(CryptoUtils.base64_encode(plain), encoded)
        self.assertEqual(CryptoUtils.base64_decode(encoded), plain)
        self.assertIn("Error", CryptoUtils.base64_decode("invalid-base64"))

    def test_html_encoding(self):
        plain = "<p>Hello & Welcome!</p>"
        encoded = "&lt;p&gt;Hello &amp; Welcome!&lt;/p&gt;"
        self.assertEqual(CryptoUtils.html_encode(plain), encoded)
        self.assertEqual(CryptoUtils.html_decode(encoded), plain)

    def test_hex_encoding(self):
        plain = "Galdr hex test"
        encoded = "47616c6472206865782074657374"
        self.assertEqual(CryptoUtils.hex_encode(plain), encoded)
        self.assertEqual(CryptoUtils.hex_decode(encoded), plain)

    # --- JWT tests ---
    def setUp(self):
        self.secret_key = "secret"
        self.payload = {"user_id": 123, "exp": int(time.time()) + 3600}
        self.expired_payload = {"user_id": 123, "exp": int(time.time()) - 3600}

        self.valid_token = jwt.encode(self.payload, self.secret_key, algorithm="HS256")
        self.expired_token = jwt.encode(self.expired_payload, self.secret_key, algorithm="HS256")
        self.invalid_signature_token = jwt.encode(self.payload, "wrong-secret", algorithm="HS256")

    def test_jwt_decode(self):
        header, payload, error = CryptoUtils.decode_jwt(self.valid_token)
        self.assertEqual(error, "")
        self.assertIn('"alg": "HS256"', header)
        self.assertIn('"user_id": 123', payload)

    def test_jwt_decode_invalid_token(self):
        header, payload, error = CryptoUtils.decode_jwt("not.a.real.token")
        self.assertNotEqual(error, "")
        self.assertEqual(header, "")
        self.assertEqual(payload, "")

    def test_jwt_verify_valid(self):
        result = CryptoUtils.verify_jwt_signature(self.valid_token, self.secret_key)
        self.assertIn("Signature is valid", result)

    def test_jwt_verify_invalid_signature(self):
        result = CryptoUtils.verify_jwt_signature(self.invalid_signature_token, self.secret_key)
        self.assertIn("Invalid Signature", result)

    def test_jwt_verify_expired(self):
        result = CryptoUtils.verify_jwt_signature(self.expired_token, self.secret_key)
        self.assertIn("Signature has expired", result)

if __name__ == '__main__':
    unittest.main()
