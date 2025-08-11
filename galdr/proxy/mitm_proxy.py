import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import requests

class ProxyRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.handle_request('GET')

    def do_POST(self):
        self.handle_request('POST')

    def do_PUT(self):
        self.handle_request('PUT')

    def do_DELETE(self):
        self.handle_request('DELETE')

    def do_HEAD(self):
        self.handle_request('HEAD')

    def handle_request(self, method):
        # Construct the full URL
        url = f"{self.path}"

        # Copy headers from the client request
        req_headers = {key: value for key, value in self.headers.items()}

        # Read body if present
        content_length = int(self.headers.get('Content-Length', 0))
        req_body = self.rfile.read(content_length) if content_length else None

        print(f"[*] Proxying {method} request to: {url}")

        try:
            # Forward the request to the target server
            resp = requests.request(method, url, headers=req_headers, data=req_body, allow_redirects=False, verify=False)

            # Send response status code
            self.send_response(resp.status_code)

            # Send response headers
            for key, value in resp.headers.items():
                if key.lower() not in ('content-encoding', 'transfer-encoding'):
                    self.send_header(key, value)
            self.end_headers()

            # Send response body
            self.wfile.write(resp.content)

        except requests.exceptions.RequestException as e:
            self.send_error(502, f"Proxy Error: {e}")

class MitmProxy(threading.Thread):
    def __init__(self, host='127.0.0.1', port=8080):
        super().__init__()
        self.host = host
        self.port = port
        self.server = HTTPServer((self.host, self.port), ProxyRequestHandler)
        self.daemon = True  # Thread will exit when main program exits

    def run(self):
        print(f"[*] Starting proxy server on {self.host}:{self.port}")
        self.server.serve_forever()

    def stop(self):
        print("[*] Stopping proxy server...")
        self.server.shutdown()
        self.server.server_close()
