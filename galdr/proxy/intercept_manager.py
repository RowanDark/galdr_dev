import threading
import queue

class InterceptManager:
    """
    Manages the state for request/response interception between the GUI and proxy threads.
    """
    def __init__(self):
        # State flags
        self.intercept_request_enabled = False
        self.intercept_response_enabled = False

        # For requests
        self.request_event = threading.Event()
        self.request_queue = queue.Queue(maxsize=1)

        # For responses
        self.response_event = threading.Event()
        self.response_queue = queue.Queue(maxsize=1)

    def toggle_request_intercept(self, status: bool):
        self.intercept_request_enabled = status

    def toggle_response_intercept(self, status: bool):
        self.intercept_response_enabled = status

    def should_intercept_request(self):
        return self.intercept_request_enabled

    def should_intercept_response(self):
        return self.intercept_response_enabled

    def wait_for_request_decision(self):
        """Blocks until the GUI provides a decision for a request."""
        self.request_event.wait()
        self.request_event.clear()
        try:
            return self.request_queue.get_nowait()
        except queue.Empty:
            return {'action': 'forward'} # Default to forward if queue is empty

    def send_request_decision(self, data):
        """Called by the GUI to unblock the proxy for a request."""
        self.request_queue.put(data)
        self.request_event.set()

    def wait_for_response_decision(self):
        """Blocks until the GUI provides a decision for a response."""
        self.response_event.wait()
        self.response_event.clear()
        try:
            return self.response_queue.get_nowait()
        except queue.Empty:
            return {'action': 'forward'}

    def send_response_decision(self, data):
        """Called by the GUI to unblock the proxy for a response."""
        self.response_queue.put(data)
        self.response_event.set()
