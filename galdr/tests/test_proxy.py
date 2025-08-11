import unittest
import requests
import time
import subprocess
import sys
import os

# Global variable to hold the proxy process
proxy_process = None

def setUpModule():
    """Starts the mitmdump server in a separate process."""
    global proxy_process
    port = 8081
    # Use the new addon script
    script_path = os.path.join('galdr', 'proxy', 'galdr_addon.py')
    print(f"Starting mitmdump on port {port} with script {script_path}...")

    command = [
        "mitmdump",
        "-p", str(port),
        "-s", script_path,
        "--set", "block_global=false" # Allow connections to all hosts
    ]

    # Redirect stdout and stderr to DEVNULL to keep the test output clean
    proxy_process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Wait for mitmdump to start
    time.sleep(3)
    print("mitmdump process started.")

def tearDownModule():
    """Stops the mitmdump server process."""
    global proxy_process
    if proxy_process:
        print("Stopping mitmdump process...")
        proxy_process.terminate()
        try:
            proxy_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy_process.kill()
        print("mitmdump process stopped.")

class TestMitmProxy(unittest.TestCase):

    def setUp(self):
        self.proxy_host = '127.0.0.1'
        self.proxy_port = 8081

    def test_proxy_get_request(self):
        """Test that the proxy correctly handles a simple GET request."""
        proxies = { "http": f"http://{self.proxy_host}:{self.proxy_port}" }
        target_url = "http://httpbin.org/get"
        try:
            response = requests.get(target_url, proxies=proxies, timeout=10)
            self.assertEqual(response.status_code, 200)
        except requests.exceptions.RequestException as e:
            self.fail(f"Proxy request failed: {e}")

    def test_proxy_https_get_request(self):
        """Test that the proxy correctly handles an HTTPS GET request."""
        proxies = { "https": f"http://{self.proxy_host}:{self.proxy_port}" }
        target_url = "https://httpbin.org/get"
        try:
            # verify=False is required because the test client doesn't trust the mitmproxy CA
            response = requests.get(target_url, proxies=proxies, timeout=15, verify=False)
            self.assertEqual(response.status_code, 200)
        except requests.exceptions.RequestException as e:
            self.fail(f"HTTPS Proxy request failed: {e}")

    def test_proxy_post_request(self):
        """Test that the proxy correctly handles a POST request with a body."""
        proxies = { "http": f"http://{self.proxy_host}:{self.proxy_port}" }
        target_url = "http://httpbin.org/post"
        payload = {'key': 'value', 'test': 'galdr'}
        try:
            response = requests.post(target_url, json=payload, proxies=proxies, timeout=10)
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertEqual(data['json'], payload)
        except requests.exceptions.RequestException as e:
            self.fail(f"Proxy request failed: {e}")

if __name__ == '__main__':
    unittest.main()
