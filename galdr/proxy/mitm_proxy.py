import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import requests
from PyQt6.QtCore import QObject, pyqtSignal

class ProxyLogger(QObject):
    """A QObject to handle signal emission for the proxy."""
    request_logged = pyqtSignal(dict)

class ProxyRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, logger, **kwargs):
        self.logger = logger
        super().__init__(*args, **kwargs)

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
        url = f"{self.path}"
        req_headers = {key: value for key, value in self.headers.items()}
        content_length = int(self.headers.get('Content-Length', 0))
        req_body = self.rfile.read(content_length) if content_length else None

        log_data = {'method': method, 'url': url, 'status': 'Error', 'size': 0}

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
