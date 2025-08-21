import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .base_check import BaseCheck, Vulnerability
import os
import time
import re

class SsrfCheck(BaseCheck):
    def __init__(self, request_data, ai_mode=False, ai_analyzer=None):
        super().__init__(request_data, ai_mode, ai_analyzer)
        self.payloads = self.load_payloads()

    def load_payloads(self):
        """Loads SSRF payloads from the payload file."""
        payloads = []
        path = os.path.join('galdr', 'scanner', 'payloads', 'ssrf_payloads.txt')
        try:
            with open(path, 'r') as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            print(f"Warning: SSRF payloads file not found at {path}")
        return payloads

    def run(self):
        """
        Runs the time-based SSRF check.
        It injects payloads that point to slow-responding services and measures the response time.
        """
        findings = []
        parsed_url = urlparse(self.target_url)
        query_params = parse_qs(parsed_url.query, keep_blank_values=True)

        if not query_params:
            return findings

        for param in query_params:
            original_values = query_params[param]

            for payload in self.payloads:
                # Determine the expected delay and detection threshold from the payload
                expected_delay = 0
                match = re.search(r'/delay/(\d+)', payload)
                if match:
                    expected_delay = int(match.group(1))
                else:
                    # For internal/non-routable IPs, we expect a timeout, let's set a base delay
                    expected_delay = 3

                # Set a detection threshold slightly lower than the expected delay
                detection_threshold = expected_delay - 0.5

                # Create a new set of parameters with the payload
                test_params = query_params.copy()
                test_params[param] = [payload] # Replace the parameter's value with the payload

                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed_url._replace(query=new_query))

                start_time = time.time()
                try:
                    # Send the request with a timeout slightly longer than the expected delay
                    response = requests.get(test_url, timeout=expected_delay + 2, verify=False)
                except requests.exceptions.ReadTimeout as e:
                    # A timeout is the expected outcome for a successful time-based check
                    elapsed_time = time.time() - start_time
                    if elapsed_time >= detection_threshold:
                        finding = Vulnerability(
                            url=self.target_url,
                            check_name="Server-Side Request Forgery (Time-Based)",
                            parameter=param,
                            severity="High",
                            details=(
                                f"The application took {elapsed_time:.2f} seconds to respond after injecting a payload "
                                f"designed to take at least {expected_delay} seconds. This indicates a potential "
                                f"time-based SSRF vulnerability."
                            ),
                            request=e.request,
                            response=None
                        )
                        findings.append(finding)
                        # Once a vulnerability is found for a parameter, move to the next one
                        break
                except requests.exceptions.RequestException:
                    # Ignore other connection errors
                    pass

            if findings and any(f.parameter == param for f in findings):
                continue # Skip to the next parameter if we already found a vulnerability for this one

        return findings
