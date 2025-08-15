import requests
import time
import os
from .base_check import BaseCheck, Vulnerability
import re

class XxeCheck(BaseCheck):
    def __init__(self, target_url, ai_mode=False, ai_analyzer=None):
        super().__init__(target_url, ai_mode, ai_analyzer)
        self.payloads = self.load_payloads()

    def load_payloads(self):
        """Loads XXE payloads from the payload file."""
        payloads = []
        path = os.path.join('galdr', 'scanner', 'payloads', 'xxe_payloads.txt')
        try:
            with open(path, 'r') as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            print(f"Warning: XXE payloads file not found at {path}")
        return payloads

    def run(self):
        """
        Runs the time-based XXE check.
        This check sends POST requests with an XML body to the target URL.
        """
        findings = []

        # This check is only relevant for endpoints that might process XML.
        # We will send a POST request with the appropriate Content-Type.
        headers = {'Content-Type': 'application/xml'}

        for payload in self.payloads:
            # Determine expected delay from payload
            expected_delay = 3 # Default delay for non-httpbin payloads (e.g., internal IPs)
            match = re.search(r'/delay/(\d+)', payload)
            if match:
                expected_delay = int(match.group(1))

            detection_threshold = expected_delay - 0.5

            start_time = time.time()
            try:
                # Send the XML payload in the body of a POST request
                requests.post(
                    self.target_url,
                    data=payload.encode('utf-8'),
                    headers=headers,
                    timeout=expected_delay + 2,
                    verify=False
                )
            except requests.exceptions.ReadTimeout:
                elapsed_time = time.time() - start_time
                if elapsed_time >= detection_threshold:
                    finding = Vulnerability(
                        url=self.target_url,
                        check_name="XML External Entity (XXE)",
                        parameter="XML Request Body",
                        severity="Critical",
                        details=(
                            f"The application took {elapsed_time:.2f} seconds to respond after injecting an XXE "
                            f"payload. This suggests the XML parser is resolving external entities and is "
                            f"vulnerable to time-based attacks."
                        )
                    )
                    findings.append(finding)
                    # Found a vulnerability, no need to test other payloads for this target
                    return findings
            except requests.exceptions.RequestException as e:
                # print(f"XXECheck encountered an error: {e}")
                continue

        return findings
