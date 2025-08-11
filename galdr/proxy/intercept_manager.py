import threading
import queue

class InterceptManager:
    """
    Manages the state for request interception between the GUI and proxy threads.
    """
    def __init__(self):
        self.intercept_enabled = False
        self.event = threading.Event()
        self.data_queue = queue.Queue()

    def is_intercept_on(self):
        return self.intercept_enabled

    def toggle_intercept(self, status: bool):
        self.intercept_enabled = status

    def wait_for_gui(self):
        """Called by the proxy thread to block until the GUI responds."""
        self.event.wait()
        self.event.clear() # Reset the event for the next interception

    def get_gui_response(self):
        """
        Called by the proxy thread to get the data from the GUI.
        This will be the (potentially modified) request data or a drop command.
        """
        try:
            return self.data_queue.get_nowait()
        except queue.Empty:
            return None

    def send_response_to_proxy(self, data):
        """Called by the GUI to send data and unblock the proxy thread."""
        self.data_queue.put(data)
        self.event.set()
