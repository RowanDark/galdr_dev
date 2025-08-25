import base64
import urllib.parse
import html
import binascii
import jwt
import json
from typing import Tuple

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
