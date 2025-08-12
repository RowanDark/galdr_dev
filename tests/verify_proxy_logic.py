import subprocess
import time
import json
import requests
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import unittest
import os

# --- Test Configuration ---
PROXY_PORT = 8080
EVENT_PORT = 8082
COMMAND_PORT = 8083
TEST_URL = "http://example.com/testpath"
TEST_MODIFY_HEADER = "X-Galdr-Test"
TEST_MODIFY_VALUE = "passed"

# --- Global state for the test ---
# We use a class to encapsulate state to avoid global variables
class TestState:
    def __init__(self):
        self.received_events = []
        self.httpd = None
        self.mitm_process = None
        self.events_lock = threading.Lock()
        self.event_queue = []
        self.stop_server = False

    def add_event(self, event):
        with self.events_lock:
            self.event_queue.append(event)

    def get_event(self, event_type, timeout=5):
        start_time = time.time()
        while time.time() - start_time < timeout:
            with self.events_lock:
                for i, event in enumerate(self.event_queue):
                    if event.get("type") == event_type:
                        return self.event_queue.pop(i)
            time.sleep(0.1)
        return None

    def clear_events(self):
        with self.events_lock:
            self.event_queue.clear()

# --- Mock GUI Event Server ---
class EventServerRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/event':
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                event = json.loads(post_data.decode('utf-8'))

                self.server.test_state.add_event(event)

                self.send_response(200)
            except Exception:
                self.send_response(500)
            finally:
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        return

def run_event_server(state):
    server_address = ('127.0.0.1', EVENT_PORT)
    state.httpd = HTTPServer(server_address, EventServerRequestHandler)
    state.httpd.test_state = state
    print(f"[Event Server] Listening on port {EVENT_PORT}...")
    while not state.stop_server:
        state.httpd.handle_request()
    print("[Event Server] Stopped.")

# --- Test Helper Functions ---
def send_command_to_addon(command):
    url = f"http://127.0.0.1:{COMMAND_PORT}/command"
    try:
        requests.post(url, json=command, timeout=2)
    except requests.RequestException:
        # This can fail if mitmproxy is slow to start, which is ok
        pass

def make_request_through_proxy(url=TEST_URL):
    proxies = {"http": f"http://127.0.0.1:{PROXY_PORT}", "https": f"http://127.0.0.1:{PROXY_PORT}"}
    try:
        response = requests.get(url, proxies=proxies, timeout=5, verify=False)
        return response
    except requests.exceptions.RequestException:
        return None

# --- Test Cases ---
class ProxyLogicTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.state = TestState()

        # Start event server
        cls.event_server_thread = threading.Thread(target=run_event_server, args=(cls.state,), daemon=True)
        cls.event_server_thread.start()
        time.sleep(1)

        # Start mitmdump
        addon_path = os.path.join("galdr", "proxy", "galdr_addon.py")
        command = [
            "mitmdump", "-p", str(PROXY_PORT), "-s", addon_path,
            "--set", f"galdr_event_port={EVENT_PORT}",
            "--set", f"galdr_command_port={COMMAND_PORT}",
            "--set", "block_global=false"
        ]
        cls.state.mitm_process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(f"[Test Runner] Started mitmdump (PID: {cls.state.mitm_process.pid})...")
        time.sleep(3) # Give mitmproxy time to fully start

    @classmethod
    def tearDownClass(cls):
        print("\n[Test Runner] Cleaning up...")
        cls.state.mitm_process.terminate()
        try:
            # Now that it's terminated, we can safely get the output.
            stdout, stderr = cls.state.mitm_process.communicate(timeout=5)
            if stdout:
                print("\n--- mitmdump stdout ---\n", stdout)
            if stderr:
                print("\n--- mitmdump stderr ---\n", stderr)
        except subprocess.TimeoutExpired:
            cls.state.mitm_process.kill()
            print("\n--- mitmdump process killed after timeout ---")

        print("[Test Runner] mitmdump process terminated.")

        cls.state.stop_server = True
        # Send a dummy request to unblock httpd.handle_request()
        try:
            requests.post(f"http://127.0.0.1:{EVENT_PORT}/shutdown", timeout=0.1)
        except requests.RequestException:
            pass

    def setUp(self):
        # Clear events before each test
        self.state.clear_events()
        # Ensure interception is off by default
        send_command_to_addon({"action": "update_state", "data": {"intercept_requests": False, "intercept_responses": False}})

    def test_01_intercept_and_forward(self):
        print("\n--- Running Test: Intercept and Forward ---")
        send_command_to_addon({"action": "update_state", "data": {"intercept_requests": True}})

        thread = threading.Thread(target=make_request_through_proxy)
        thread.start()

        intercept_event = self.state.get_event('request_intercepted')
        self.assertIsNotNone(intercept_event, "Did not receive 'request_intercepted' event.")
        self.assertEqual(intercept_event['data']['url'], TEST_URL)

        flow_id = intercept_event['data']['flow_id']
        send_command_to_addon({"flow_id": flow_id, "action": "forward", "data": {}})

        log_event = self.state.get_event('flow_log')
        self.assertIsNotNone(log_event, "Did not receive 'flow_log' event after forwarding.")
        self.assertEqual(log_event['data']['url'], TEST_URL)
        thread.join(timeout=5)
        print("--- Test Passed ---")

    def test_02_intercept_and_drop(self):
        print("\n--- Running Test: Intercept and Drop ---")
        send_command_to_addon({"action": "update_state", "data": {"intercept_requests": True}})

        response = None
        def target():
            nonlocal response
            response = make_request_through_proxy()

        thread = threading.Thread(target=target)
        thread.start()

        intercept_event = self.state.get_event('request_intercepted')
        self.assertIsNotNone(intercept_event, "Did not receive 'request_intercepted' event.")

        flow_id = intercept_event['data']['flow_id']
        send_command_to_addon({"flow_id": flow_id, "action": "drop"})

        thread.join(timeout=5)
        self.assertIsNone(response, f"Request should have been dropped, but received a response (Status: {response.status_code if response else 'N/A'})")

        log_event = self.state.get_event('flow_log', timeout=2)
        self.assertIsNone(log_event, "A 'flow_log' event should not be generated for a dropped request.")
        print("--- Test Passed ---")

    def test_03_intercept_and_modify(self):
        print("\n--- Running Test: Intercept and Modify ---")
        send_command_to_addon({"action": "update_state", "data": {"intercept_requests": True}})

        thread = threading.Thread(target=make_request_through_proxy)
        thread.start()

        intercept_event = self.state.get_event('request_intercepted')
        self.assertIsNotNone(intercept_event, "Did not receive 'request_intercepted' event.")

        flow_id = intercept_event['data']['flow_id']
        modified_data = {'request': {'headers': {TEST_MODIFY_HEADER: TEST_MODIFY_VALUE}, 'body': 'modified_body'}}
        send_command_to_addon({"flow_id": flow_id, "action": "forward", "data": modified_data})

        log_event = self.state.get_event('flow_log')
        self.assertIsNotNone(log_event, "Did not receive 'flow_log' event after forwarding modified request.")
        # Note: We can't easily verify the modification without a more complex echo server.
        # Success is defined as the flow completing without error.
        self.assertEqual(log_event['data']['url'], TEST_URL)
        thread.join(timeout=5)
        print("--- Test Passed ---")


if __name__ == "__main__":
    print("Starting proxy logic verification script...")
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(ProxyLogicTest))
    runner = unittest.TextTestRunner()
    result = runner.run(suite)

    if result.wasSuccessful():
        print("\n✅✅✅ All verification tests passed! ✅✅✅")
        exit(0)
    else:
        print("\n❌❌❌ Verification FAILED ❌❌❌")
        exit(1)
