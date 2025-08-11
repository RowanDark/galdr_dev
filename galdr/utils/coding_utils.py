import base64
import urllib.parse
import html

def url_encode(text: str) -> str:
    """URL-encodes a string."""
    return urllib.parse.quote(text)

def url_decode(text: str) -> str:
    """URL-decodes a string."""
    return urllib.parse.unquote(text)

def base64_encode(text: str) -> str:
    """Base64-encodes a string."""
    try:
        return base64.b64encode(text.encode('utf-8')).decode('utf-8')
    except Exception as e:
        return f"Error: {e}"

def base64_decode(text: str) -> str:
    """Base64-decodes a string."""
    try:
        # Add padding if it's missing
        missing_padding = len(text) % 4
        if missing_padding:
            text += '=' * (4 - missing_padding)
        return base64.b64decode(text).decode('utf-8')
    except Exception as e:
        return f"Error: Not a valid Base64 string."

def html_encode(text: str) -> str:
    """HTML-encodes a string."""
    return html.escape(text)

def html_decode(text: str) -> str:
    """HTML-decodes a string."""
    return html.unescape(text)

def smart_decode(text: str) -> str:
    """Tries to decode a string using common formats."""
    # Try Base64 first
    try:
        decoded = base64_decode(text)
        if not decoded.startswith("Error:"):
            return f"Base64 Decoded:\n\n{decoded}"
    except Exception:
        pass

    # Try URL decoding
    try:
        decoded = url_decode(text)
        if decoded != text: # Check if any change was made
            return f"URL Decoded:\n\n{decoded}"
    except Exception:
        pass

    return "Could not automatically decode the input."
