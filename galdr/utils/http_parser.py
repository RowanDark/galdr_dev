import re
from typing import Dict, Optional

def parse_raw_http_request(raw_request: str) -> Optional[Dict]:
    """
    Parses a raw HTTP request string into its components.

    Args:
        raw_request: The raw HTTP request as a string.

    Returns:
        A dictionary containing the request components (method, host, path,
        headers, body), or None if parsing fails.
    """
    try:
        request_line_and_headers, body = raw_request.split('\r\n\r\n', 1)
    except ValueError:
        request_line_and_headers = raw_request
        body = ''

    lines = request_line_and_headers.split('\r\n')
    request_line = lines[0]
    header_lines = lines[1:]

    # Parse request line
    match = re.match(r'(\S+)\s+(\S+)\s+HTTP/(\d\.\d)', request_line)
    if not match:
        return None
    method, path, version = match.groups()

    # Parse headers
    headers = {}
    host = None
    for line in header_lines:
        if ': ' in line:
            key, value = line.split(': ', 1)
            headers[key] = value
            if key.lower() == 'host':
                host = value

    if not host:
        return None # Host header is required

    return {
        "method": method,
        "host": host,
        "path": path,
        "version": version,
        "headers": headers,
        "body": body
    }
