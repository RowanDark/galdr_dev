import base64
import urllib.parse
import html
import binascii
import jwt
import json
from typing import Tuple
import base45
import base58
# import pybase62 as base62 # This package is causing issues

from Crypto.Cipher import AES, DES, DES3, Blowfish, ARC2, ARC4
from Crypto.Util.Padding import pad, unpad

class CryptoUtils:
    """
    A utility class for various encoding, decoding, and crypto operations.
    All methods are static.
    """

    # --- URL Encoding ---
    @staticmethod
    def url_encode(text: str) -> str:
        try:
            return urllib.parse.quote(text)
        except Exception as e:
            return f"Error: {e}"

    @staticmethod
    def url_decode(text: str) -> str:
        try:
            return urllib.parse.unquote(text)
        except Exception as e:
            return f"Error: {e}"

    # --- Base64 Encoding ---
    @staticmethod
    def base64_encode(text: str) -> str:
        try:
            return base64.b64encode(text.encode('utf-8')).decode('utf-8')
        except Exception as e:
            return f"Error: {e}"

    @staticmethod
    def base64_decode(text: str) -> str:
        try:
            return base64.b64decode(text.encode('utf-8')).decode('utf-8')
        except (binascii.Error, UnicodeDecodeError) as e:
            return f"Error: {e}"

    # --- Symmetric Ciphers ---
    CIPHER_MODES = {
        "AES": {"modes": [AES.MODE_ECB, AES.MODE_CBC, AES.MODE_CFB, AES.MODE_OFB], "key_sizes": [16, 24, 32]},
        "DES": {"modes": [DES.MODE_ECB, DES.MODE_CBC], "key_sizes": [8]},
        "DES3": {"modes": [DES3.MODE_ECB, DES3.MODE_CBC], "key_sizes": [16, 24]},
        "Blowfish": {"modes": [Blowfish.MODE_ECB, Blowfish.MODE_CBC], "key_sizes": list(range(4, 57))},
        "ARC2": {"modes": [ARC2.MODE_ECB, ARC2.MODE_CBC], "key_sizes": list(range(5, 129))},
    }
    STREAM_CIPHERS = ["ARC4"]

    @staticmethod
    def _get_cipher_obj(cipher_name, key, iv, mode):
        cipher_class = globals()[cipher_name]
        if cipher_name in CryptoUtils.STREAM_CIPHERS:
            return cipher_class.new(key)
        else:
            return cipher_class.new(key, mode, iv)

    @staticmethod
    def symmetric_encrypt(cipher_name: str, mode: int, data: bytes, key: bytes, iv: bytes) -> str:
        try:
            cipher = CryptoUtils._get_cipher_obj(cipher_name, key, iv, mode)
            if cipher_name in CryptoUtils.STREAM_CIPHERS:
                encrypted = cipher.encrypt(data)
            else:
                padded_data = pad(data, cipher.block_size)
                encrypted = cipher.encrypt(padded_data)
            return binascii.hexlify(encrypted).decode('utf-8')
        except Exception as e:
            return f"Encryption Error: {e}"

    @staticmethod
    def symmetric_decrypt(cipher_name: str, mode: int, data: bytes, key: bytes, iv: bytes) -> str:
        try:
            cipher = CryptoUtils._get_cipher_obj(cipher_name, key, iv, mode)
            decrypted = cipher.decrypt(data)
            if cipher_name in CryptoUtils.STREAM_CIPHERS:
                return decrypted.decode('utf-8', errors='ignore')
            else:
                unpadded_data = unpad(decrypted, cipher.block_size)
                return unpadded_data.decode('utf-8', errors='ignore')
        except (ValueError, KeyError) as e:
            return f"Decryption Error: {e}. Check key, IV, padding, and mode."
        except Exception as e:
            return f"Decryption Error: {e}"

    # --- Number Systems ---
    @staticmethod
    def text_to_binary(text: str) -> str:
        try:
            return ' '.join(format(ord(c), '08b') for c in text)
        except Exception as e:
            return f"Error: {e}"

    @staticmethod
    def binary_to_text(text: str) -> str:
        try:
            clean_text = ''.join(text.split())
            return ''.join(chr(int(clean_text[i:i+8], 2)) for i in range(0, len(clean_text), 8))
        except Exception as e:
            return f"Error: {e}"

    @staticmethod
    def text_to_decimal(text: str) -> str:
        try:
            return ' '.join(str(ord(c)) for c in text)
        except Exception as e:
            return f"Error: {e}"

    @staticmethod
    def decimal_to_text(text: str) -> str:
        try:
            return ''.join(chr(int(i)) for i in text.split())
        except Exception as e:
            return f"Error: {e}"

    @staticmethod
    def text_to_octal(text: str) -> str:
        try:
            return ' '.join(format(ord(c), 'o') for c in text)
        except Exception as e:
            return f"Error: {e}"

    @staticmethod
    def octal_to_text(text: str) -> str:
        try:
            return ''.join(chr(int(i, 8)) for i in text.split())
        except Exception as e:
            return f"Error: {e}"

    # --- Simple Ciphers ---
    @staticmethod
    def rot13(text: str) -> str:
        try:
            return text.translate(str.maketrans(
                "ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz",
                "NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm"
            ))
        except Exception as e:
            return f"Error: {e}"

    @staticmethod
    def xor(text: str, key: str) -> str:
        if not key:
            return "Error: XOR requires a key."
        try:
            key_bytes = key.encode('utf-8')
            text_bytes = text.encode('utf-8')
            encoded_bytes = bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(text_bytes)])
            # The result might not be valid utf-8, so we return a hex representation
            return binascii.hexlify(encoded_bytes).decode('utf-8')
        except Exception as e:
            return f"Error: {e}"

    # --- Other Base Encodings ---
    @staticmethod
    def base32_encode(text: str) -> str:
        try:
            return base64.b32encode(text.encode('utf-8')).decode('utf-8')
        except Exception as e:
            return f"Error: {e}"

    @staticmethod
    def base32_decode(text: str) -> str:
        try:
            return base64.b32decode(text.encode('utf-8')).decode('utf-8')
        except Exception as e:
            return f"Error: {e}"

    @staticmethod
    def base45_encode(text: str) -> str:
        try:
            return base45.b45encode(text.encode('utf-8')).decode('utf-8')
        except Exception as e:
            return f"Error: {e}"

    @staticmethod
    def base45_decode(text: str) -> str:
        try:
            return base45.b45decode(text.encode('utf-8')).decode('utf-8')
        except Exception as e:
            return f"Error: {e}"

    @staticmethod
    def base58_encode(text: str) -> str:
        try:
            return base58.b58encode(text.encode('utf-8')).decode('utf-8')
        except Exception as e:
            return f"Error: {e}"

    @staticmethod
    def base58_decode(text: str) -> str:
        try:
            return base58.b58decode(text.encode('utf-8')).decode('utf-8')
        except Exception as e:
            return f"Error: {e}"

    @staticmethod
    def base85_encode(text: str) -> str:
        try:
            return base64.b85encode(text.encode('utf-8')).decode('utf-8')
        except Exception as e:
            return f"Error: {e}"

    @staticmethod
    def base85_decode(text: str) -> str:
        try:
            return base64.b85decode(text.encode('utf-8')).decode('utf-8')
        except Exception as e:
            return f"Error: {e}"

    # --- JWT Operations ---
    @staticmethod
    def decode_jwt(token: str) -> Tuple[str, str, str]:
        """
        Decodes a JWT token into its header and payload without verification.

        Returns:
            A tuple of (header, payload, error_string).
        """
        try:
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})

            header_str = json.dumps(header, indent=4)
            payload_str = json.dumps(payload, indent=4)

            return header_str, payload_str, ""
        except Exception as e:
            return "", "", f"Error decoding JWT: {e}"

    @staticmethod
    def verify_jwt_signature(token: str, secret: str) -> str:
        """
        Verifies a JWT's signature against a given secret or public key.
        """
        if not secret:
            return "Error: A secret or public key is required for verification."

        try:
            # First, get the algorithm from the header
            header = jwt.get_unverified_header(token)
            alg = header.get('alg')

            # PyJWT will verify the signature, expiration, etc.
            jwt.decode(token, secret, algorithms=[alg])

            return "✅ Signature is valid."

        except jwt.InvalidSignatureError:
            return "❌ Invalid Signature."
        except jwt.ExpiredSignatureError:
            return "⚠️ Signature has expired."
        except jwt.InvalidAlgorithmError:
            return f"❌ Invalid Algorithm: {alg}. The key is not suitable for this algorithm."
        except Exception as e:
            return f"Error: {e}"

    # --- HTML Encoding ---
    @staticmethod
    def html_encode(text: str) -> str:
        try:
            return html.escape(text)
        except Exception as e:
            return f"Error: {e}"

    @staticmethod
    def html_decode(text: str) -> str:
        try:
            return html.unescape(text)
        except Exception as e:
            return f"Error: {e}"

    # --- Hex Encoding ---
    @staticmethod
    def hex_encode(text: str) -> str:
        try:
            return binascii.hexlify(text.encode('utf-8')).decode('utf-8')
        except Exception as e:
            return f"Error: {e}"

    @staticmethod
    def hex_decode(text: str) -> str:
        try:
            # Remove any spaces or newlines from hex string
            clean_text = ''.join(text.split())
            return binascii.unhexlify(clean_text).decode('utf-8')
        except (binascii.Error, UnicodeDecodeError) as e:
            return f"Error: {e}"
