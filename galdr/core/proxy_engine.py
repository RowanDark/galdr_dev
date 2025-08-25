import asyncio
import threading
from PyQt6.QtCore import QThread, pyqtSignal, QObject
from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster
from mitmproxy import http, master
from mitmproxy.flow import Flow

class InterceptedFlow:
    """A helper class to manage an intercepted flow."""
    def __init__(self, flow: http.HTTPFlow):
        self.flow = flow
        self.resume = threading.Event()

class ProxyAddon:
    def __init__(self, signals):
        self.signals = signals
        self.intercept_enabled = False
        self.intercepted_flow: InterceptedFlow | None = None

    def request(self, flow: http.HTTPFlow) -> None:
        if self.intercept_enabled:
            self.intercepted_flow = InterceptedFlow(flow)

            flow_summary = self.get_flow_summary(flow)
            self.signals.request_intercepted.emit(flow_summary)

            # Wait for the UI to tell us to continue
            self.intercepted_flow.resume.wait()

    def response(self, flow: http.HTTPFlow):
        # We only emit the response if it was not an intercepted request
        # that we are just finishing.
        if not self.intercepted_flow or self.intercepted_flow.flow.id != flow.id:
            flow_summary = self.get_flow_summary(flow)
            self.signals.new_flow.emit(flow_summary)

    def get_flow_summary(self, flow: http.HTTPFlow) -> dict:
        return {
            "id": str(flow.id),
            "request": {
                "method": flow.request.method,
                "url": flow.request.url,
                "headers": dict(flow.request.headers),
                "content": flow.request.content,
            },
            "response": {
                "status_code": flow.response.status_code,
                "headers": dict(flow.response.headers),
                "content": flow.response.content,
            } if flow.response else None,
        }

    def resume_flow(self, modified_request: dict | None):
        if self.intercepted_flow:
            if modified_request:
                # Modify the original flow with the new data from the UI
                self.intercepted_flow.flow.request.method = modified_request['method']
                self.intercepted_flow.flow.request.url = modified_request['url']
                self.intercepted_flow.flow.request.headers = http.Headers([(k.encode('utf-8'), v.encode('utf-8')) for k, v in modified_request['headers'].items()])
                self.intercepted_flow.flow.request.content = modified_request['content']

            self.intercepted_flow.flow.resume()
            self.intercepted_flow.resume.set()
            self.intercepted_flow = None

    def drop_flow(self):
        if self.intercepted_flow:
            self.intercepted_flow.flow.kill()
            self.intercepted_flow.resume.set()
            self.intercepted_flow = None

class ProxySignals(QObject):
    new_flow = pyqtSignal(dict)
    request_intercepted = pyqtSignal(dict)

class ProxyEngine(QThread):
    def __init__(self, host='127.0.0.1', port=8080):
        super().__init__()
        self.host = host
        self.port = port
        self.mitm_master: master.Master | None = None
        self.signals = ProxySignals()
        self.addon = ProxyAddon(self.signals)

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        opts = options.Options(listen_host=self.host, listen_port=self.port)

        self.mitm_master = DumpMaster(opts, with_termlog=False, with_dumper=False)
        self.mitm_master.addons.add(self.addon)

        try:
            loop.run_until_complete(self.mitm_master.run())
        except (KeyboardInterrupt, asyncio.CancelledError):
            self.shutdown()
        finally:
            loop.close()

    def shutdown(self):
        if self.mitm_master:
            self.mitm_master.shutdown()

    def toggle_intercept(self, enabled: bool):
        self.addon.intercept_enabled = enabled

    def resume_flow(self, modified_request: dict | None):
        if self.addon.intercepted_flow:
            self.addon.resume_flow(modified_request)

    def drop_flow(self):
        if self.addon.intercepted_flow:
            self.addon.drop_flow()
