# This script is intended to be run by the test suite in a separate process.
import sys
# Add the project root to the path to allow imports
sys.path.insert(0, '.')

from galdr.proxy.mitm_runner import MitmproxyRunner

if __name__ == "__main__":
    print("Starting proxy for tests via MitmproxyRunner...")
    proxy_runner = MitmproxyRunner(host='127.0.0.1', port=8081, intercept_manager=None)
    # The run() method blocks forever, so this script will keep running.
    proxy_runner.run()
    print("Proxy runner finished.")
