import asyncio
from threading import Thread

from PyQt6.QtCore import QObject, pyqtSignal
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster
from mitmproxy import http

class FlowAddon:
    def __init__(self, manager):
        self.manager = manager

    def response(self, flow: http.HTTPFlow):
        """
        Called when a server response has been received.
        """
        # A more robust implementation would handle different content types
        # and encodings. For now, we assume text.
        try:
            request_content = flow.request.get_text(strict=True)
        except ValueError:
            request_content = "[Binary Content]"

        try:
            response_content = flow.response.get_text(strict=True)
        except ValueError:
            response_content = "[Binary Content]"


        flow_data = {
            'id': str(flow.id),
            'method': flow.request.method,
            'url': flow.request.pretty_url,
            'status_code': flow.response.status_code,
            'reason': flow.response.reason,
            'content_length': len(flow.response.content) if flow.response.content else 0,
            'request': {
                'headers': list(flow.request.headers.items()),
                'content': request_content,
            },
            'response': {
                'headers': list(flow.response.headers.items()),
                'content': response_content,
            }
        }
        self.manager.emit_flow(flow_data)

class ProxyManager(QObject):
    flow_received = pyqtSignal(dict)
    log_message = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.master = None
        self.thread = None

    def emit_flow(self, flow_data):
        self.flow_received.emit(flow_data)

    def start_proxy(self, port=8080):
        if self.thread and self.thread.is_alive():
            self.log_message.emit("Proxy is already running.")
            return

        opts = Options(listen_host="127.0.0.1", listen_port=port)

        # Create a new DumpMaster with the specified options
        self.master = DumpMaster(opts, with_termlog=False, with_dumper=False)

        # Add our custom addon
        self.master.addons.add(FlowAddon(self))

        self.log_message.emit(f"Starting proxy on port {port}...")

        # Run the mitmproxy event loop in a separate thread
        self.thread = Thread(target=self.master.run, daemon=True)
        self.thread.start()

        self.log_message.emit("Proxy started successfully.")
        self.log_message.emit("Configure your browser or system to use http://127.0.0.1:8080 as an HTTP proxy.")
        self.log_message.emit("Then, visit http://mitm.it to install the mitmproxy CA certificate for HTTPS interception.")


    def stop_proxy(self):
        if self.master and self.thread.is_alive():
            self.log_message.emit("Stopping proxy...")
            self.master.shutdown()
            self.thread.join(timeout=5.0)
            if self.thread.is_alive():
                self.log_message.emit("Proxy thread did not terminate gracefully.")
            else:
                self.log_message.emit("Proxy stopped.")
        self.master = None
        self.thread = None
