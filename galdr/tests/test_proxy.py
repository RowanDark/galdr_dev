import unittest
import requests
import time
from galdr.proxy.mitm_proxy import MitmProxy

class TestMitmProxy(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Set up the proxy server once for all tests."""
        cls.proxy_host = '127.0.0.1'
        cls.proxy_port = 8081  # Use a different port to avoid conflicts
        cls.proxy = MitmProxy(host=cls.proxy_host, port=cls.proxy_port)
        cls.proxy.start()
        time.sleep(1) # Give the server a moment to start

    @classmethod
    def tearDownClass(cls):
        """Tear down the proxy server."""
        cls.proxy.stop()
        cls.proxy.join(timeout=2) # Wait for the thread to finish

    def test_proxy_get_request(self):
        """Test that the proxy correctly handles a simple GET request."""
        proxies = {
            "http": f"http://{self.proxy_host}:{self.proxy_port}",
            "https": f"http://{self.proxy_host}:{self.proxy_port}",
        }
        target_url = "http://httpbin.org/get"

        try:
            response = requests.get(target_url, proxies=proxies, timeout=10, verify=False)

            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertEqual(data['url'], target_url)

        except requests.exceptions.ProxyError as e:
            self.fail(f"Proxy request failed: {e}")

    def test_proxy_post_request(self):
        """Test that the proxy correctly handles a POST request with a body."""
        proxies = {
            "http": f"http://{self.proxy_host}:{self.proxy_port}",
            "https": f"http://{self.proxy_host}:{self.proxy_port}",
        }
        target_url = "http://httpbin.org/post"
        payload = {'key': 'value', 'test': 'galdr'}

        try:
            response = requests.post(target_url, json=payload, proxies=proxies, timeout=10, verify=False)

            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertEqual(data['json'], payload)

        except requests.exceptions.ProxyError as e:
            self.fail(f"Proxy request failed: {e}")

if __name__ == '__main__':
    unittest.main()
