import requests
import time
from PyQt6.QtCore import QThread, pyqtSignal
from urllib.parse import urlparse

class RaiderEngine(QThread):
    """
    The backend engine for the Raider fuzzer.
    Runs in a separate thread to avoid freezing the UI.
    """
    result_ready = pyqtSignal(dict)
    attack_finished = pyqtSignal()

    def __init__(self, raw_request: str, payloads: list[str], parent=None):
        super().__init__(parent)
        self.raw_request = raw_request
        self.payloads = payloads
        self.is_running = True
        self.injection_marker = "§"

    def run(self):
        """
        Main entry point for the thread.
        Parses the request and runs the fuzzing attack.
        """
        try:
            # Parse the raw request
            headers, body, method, path, host, scheme = self.parse_raw_request()

            # Simple Sniper Attack
            for i, payload in enumerate(self.payloads):
                if not self.is_running:
                    break

                # Create a copy of headers and body to modify
                fuzzed_headers = {k: v for k, v in headers.items()}
                fuzzed_body = body

                # Replace marker in headers
                for k, v in fuzzed_headers.items():
                    fuzzed_headers[k] = v.replace(self.injection_marker, payload)

                # Replace marker in body
                if fuzzed_body:
                    fuzzed_body = fuzzed_body.replace(self.injection_marker, payload)

                # Send the request
                start_time = time.time()
                try:
                    response = requests.request(
                        method=method,
                        url=f"{scheme}://{host}{path}",
                        headers=fuzzed_headers,
                        data=fuzzed_body.encode('utf-8') if fuzzed_body else None,
                        verify=False, # In a real tool, we'd handle certs better
                        timeout=5
                    )
                    response_time = int((time.time() - start_time) * 1000)

                    self.result_ready.emit({
                        "id": i + 1,
                        "payload": payload,
                        "status": response.status_code,
                        "length": len(response.content),
                        "time": response_time
                    })

                except requests.exceptions.RequestException as e:
                    response_time = int((time.time() - start_time) * 1000)
                    self.result_ready.emit({
                        "id": i + 1,
                        "payload": payload,
                        "status": 0,
                        "length": 0,
                        "time": response_time,
                        "error": str(e)
                    })
        finally:
            self.attack_finished.emit()

    def parse_raw_request(self):
        """
        Parses a raw HTTP request string into its components.
        """
        parts = self.raw_request.strip().split('\n\n', 1)
        header_part = parts[0]
        body = parts[1] if len(parts) > 1 else None

        header_lines = header_part.split('\n')
        request_line = header_lines[0]
        method, path, _ = request_line.split(' ')

        headers = {}
        for line in header_lines[1:]:
            key, value = line.split(':', 1)
            headers[key.strip()] = value.strip()

        host = headers.get("Host")
        if not host:
            raise ValueError("Host header is missing")

        scheme = "https" if ":443" in host else "http"

        return headers, body, method, path, host, scheme

    def stop(self):
        """Stops the attack."""
        self.is_running = False
