import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import requests
from PyQt6.QtCore import QObject, pyqtSignal

class ProxyLogger(QObject):
    """A QObject to handle signal emission for the proxy."""
    request_logged = pyqtSignal(dict)

import ssl
from galdr.proxy import cert_utils

class ProxyRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, logger, **kwargs):
        self.logger = logger
        self.https_host = None # To store the hostname from CONNECT
        super().__init__(*args, **kwargs)

    def do_CONNECT(self):
        """Handle CONNECT requests for HTTPS traffic."""
        hostname = self.path.split(':')[0]
        self.https_host = hostname # Store for later requests

        try:
            # 1. Get our CA
            ca_cert, ca_key = cert_utils.get_ca_certificate()

            # 2. Generate a certificate for the target host
            cert_path, key_path = cert_utils.generate_server_certificate(hostname, ca_cert, ca_key)

            # 3. Send 200 OK to the client
            self.send_response(200, "Connection established")
            self.end_headers()

            # 4. Wrap the socket with our SSL context
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile=cert_path, keyfile=key_path)

            sslsock = context.wrap_socket(self.connection, server_side=True)
            self.connection = sslsock
            self.request = sslsock # Update the request object for the socketserver

            # 5. The connection is now encrypted. We need to re-run the handler
            # on the new encrypted socket to process the subsequent request (e.g., GET).
            self.setup()
            self.handle()

        except Exception as e:
            print(f"!!! MITM Error for {hostname}: {e}")
            self.send_error(500, str(e))
            # Do not return here, let the connection close naturally.


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
        if self.https_host:
            url = f"https://{self.https_host}{self.path}"
        else:
            url = f"{self.path}"

        req_headers = {key: value for key, value in self.headers.items()}
        content_length = int(self.headers.get('Content-Length', 0))
        req_body = self.rfile.read(content_length) if content_length else b''

        log_data = {
            'method': method,
            'url': url,
            'status': 'Error',
            'size': 0,
            'headers': req_headers,
            'body': req_body.decode('latin-1') # Decode for safe JSON serialization
        }

        try:
            resp = requests.request(method, url, headers=req_headers, data=req_body, allow_redirects=False, verify=False)

            log_data['status'] = resp.status_code
            log_data['size'] = len(resp.content)

            self.send_response(resp.status_code)
            for key, value in resp.headers.items():
                if key.lower() not in ('content-encoding', 'transfer-encoding'):
                    self.send_header(key, value)
            self.end_headers()
            self.wfile.write(resp.content)

        except requests.exceptions.RequestException as e:
            self.send_error(502, f"Proxy Error: {e}")
            log_data['status'] = 502
            log_data['url'] = f"Error: {e}"

        finally:
            self.logger.request_logged.emit(log_data)


class MitmProxy(threading.Thread):
    def __init__(self, host='127.0.0.1', port=8080):
        super().__init__()
        self.host = host
        self.port = port
        self.logger = ProxyLogger()

        # Use a lambda to pass the logger instance to the handler
        handler_factory = lambda *args, **kwargs: ProxyRequestHandler(*args, logger=self.logger, **kwargs)
        self.server = HTTPServer((self.host, self.port), handler_factory)
        self.daemon = True

    def run(self):
        print(f"[*] Starting proxy server on {self.host}:{self.port}")
        self.server.serve_forever()

    def stop(self):
        print("[*] Stopping proxy server...")
        self.server.shutdown()
        self.server.server_close()
