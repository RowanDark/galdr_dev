import base64
import urllib.parse
import html
import binascii

class Coder:
    """
    A utility class for various encoding and decoding operations.
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
