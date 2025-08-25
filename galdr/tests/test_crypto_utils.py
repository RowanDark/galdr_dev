import unittest
import time
import jwt

from galdr.utils.crypto_utils import CryptoUtils
from Crypto.Cipher import AES

class TestCryptoUtils(unittest.TestCase):

    def setUp(self):
        # This setup is only for JWT tests
        self.secret_key = "secret"
        self.payload = {"user_id": 123, "exp": int(time.time()) + 3600}
        self.expired_payload = {"user_id": 123, "exp": int(time.time()) - 3600}

        self.valid_token = jwt.encode(self.payload, self.secret_key, algorithm="HS256")
        self.expired_token = jwt.encode(self.expired_payload, self.secret_key, algorithm="HS256")
        self.invalid_signature_token = jwt.encode(self.payload, "wrong-secret", algorithm="HS256")

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

    def test_base58_encoding(self):
        plain = "hello world"
        encoded = "StV1DL6CwTryKyV"
        self.assertEqual(CryptoUtils.base58_encode(plain), encoded)
        self.assertEqual(CryptoUtils.base58_decode(encoded), plain)

    def test_base85_encoding(self):
        plain = "Galdr base85 test"
        encoded = "M`3Jaav)-1b7eR+AarGObN"
        self.assertEqual(CryptoUtils.base85_encode(plain), encoded)
        self.assertEqual(CryptoUtils.base85_decode(encoded), plain)

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

    # --- Number System tests ---
    def test_binary_conversion(self):
        plain = "abc"
        binary = "01100001 01100010 01100011"
        self.assertEqual(CryptoUtils.text_to_binary(plain), binary)
        self.assertEqual(CryptoUtils.binary_to_text(binary), plain)

    def test_octal_conversion(self):
        plain = "abc"
        octal = "141 142 143"
        self.assertEqual(CryptoUtils.text_to_octal(plain), octal)
        self.assertEqual(CryptoUtils.octal_to_text(octal), plain)

    def test_decimal_conversion(self):
        plain = "abc"
        decimal = "97 98 99"
        self.assertEqual(CryptoUtils.text_to_decimal(plain), decimal)
        self.assertEqual(CryptoUtils.decimal_to_text(decimal), plain)

    # --- Simple Cipher tests ---
    def test_rot13_cipher(self):
        plain = "Galdr ROT13 Test"
        encrypted = "Tnyqe EBG13 Grfg"
        self.assertEqual(CryptoUtils.rot13(plain), encrypted)
        self.assertEqual(CryptoUtils.rot13(encrypted), plain)

    def test_xor_cipher(self):
        plain = "Galdr"
        key = "key"
        encrypted_hex = "2c04150f17"
        self.assertEqual(CryptoUtils.xor(plain, key), encrypted_hex)
        decrypted = CryptoUtils.xor(CryptoUtils.hex_decode(encrypted_hex), key)
        self.assertEqual(CryptoUtils.hex_decode(decrypted), plain)

    # --- JWT tests ---
    def test_jwt_decode(self):
        header, payload, error = CryptoUtils.decode_jwt(self.valid_token)
        self.assertEqual(error, "")
        self.assertIn('"alg": "HS256"', header)
        self.assertIn('"user_id": 123', payload)

    def test_jwt_decode_invalid_token(self):
        header, payload, error = CryptoUtils.decode_jwt("not.a.real.token")
        self.assertNotEqual(error, "")

    def test_jwt_verify_valid(self):
        result = CryptoUtils.verify_jwt_signature(self.valid_token, self.secret_key)
        self.assertIn("Signature is valid", result)

    def test_jwt_verify_invalid_signature(self):
        result = CryptoUtils.verify_jwt_signature(self.invalid_signature_token, self.secret_key)
        self.assertIn("Invalid Signature", result)

    def test_jwt_verify_expired(self):
        result = CryptoUtils.verify_jwt_signature(self.expired_token, self.secret_key)
        self.assertIn("Signature has expired", result)

    # --- Symmetric Cipher Tests ---
    def test_symmetric_aes_cbc(self):
        key = b'Sixteen byte key' # 16 bytes -> AES-128
        iv = b'This is an IV456'  # 16 bytes
        plain_text = b'This is the data to be encrypted.'

        encrypted_hex = CryptoUtils.symmetric_encrypt("AES", AES.MODE_CBC, plain_text, key, iv)
        decrypted_text = CryptoUtils.symmetric_decrypt("AES", AES.MODE_CBC, bytes.fromhex(encrypted_hex), key, iv)

        self.assertEqual(decrypted_text.encode('utf-8'), plain_text)

    def test_symmetric_arc4(self):
        key = b'somekey'
        plain_text = b'This is a stream cipher test.'

        encrypted_hex = CryptoUtils.symmetric_encrypt("ARC4", -1, plain_text, key, b'') # mode/iv not used
        decrypted_text = CryptoUtils.symmetric_decrypt("ARC4", -1, bytes.fromhex(encrypted_hex), key, b'')

        self.assertEqual(decrypted_text.encode('utf-8'), plain_text)


if __name__ == '__main__':
    unittest.main()
