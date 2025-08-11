import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .base_check import BaseCheck, Vulnerability
import os
import time

class CommandInjectionCheck(BaseCheck):
    def __init__(self, target_url):
        super().__init__(target_url)
        self.payloads = self.load_payloads()
        self.sleep_duration = 5 # Corresponds to the 'sleep 5' in payloads

    def load_payloads(self):
        """Loads Command Injection payloads from the payload file."""
        payloads = []
        path = os.path.join('galdr', 'scanner', 'payloads', 'command_injection_payloads.txt')
        try:
            with open(path, 'r') as f:
                payloads = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"Warning: Command Injection payloads file not found at {path}")
        return payloads

    def get_baseline_time(self):
        """Measures the baseline response time for a normal request."""
        try:
            start_time = time.time()
            requests.get(self.target_url, timeout=10)
            end_time = time.time()
            return end_time - start_time
        except requests.exceptions.RequestException:
            return -1 # Indicate an error

    def run(self):
        """
        Runs the time-based Command Injection check.
        Returns a list of Vulnerability findings.
        """
        findings = []
        parsed_url = urlparse(self.target_url)
        query_params = parse_qs(parsed_url.query)

        if not query_params:
            return findings

        baseline_time = self.get_baseline_time()
        if baseline_time < 0:
            print(f"Could not establish baseline for {self.target_url}, skipping check.")
            return findings

        for param, values in query_params.items():
            original_value = values[0]

            for payload in self.payloads:
                test_params = query_params.copy()
                test_params[param] = original_value + payload

                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed_url._replace(query=new_query))

                try:
                    start_time = time.time()
                    requests.get(test_url, timeout=15) # Higher timeout to allow for sleep
                    end_time = time.time()

                    response_time = end_time - start_time

                    # If response time is close to the sleep duration, flag it.
                    # We check for > sleep_duration - 1 to account for network variance.
                    if response_time > (baseline_time + self.sleep_duration - 1):
                        finding = Vulnerability(
                            url=self.target_url,
                            check_name="Time-based Command Injection",
                            parameter=param,
                            severity="High",
                            details=f"Response took {response_time:.2f}s after injecting payload '{payload}', which is significantly longer than the baseline of {baseline_time:.2f}s."
                        )
                        findings.append(finding)
                        break # Move to next parameter
                except requests.exceptions.RequestException as e:
                    # Timeouts are expected here, but other errors are not
                    if not isinstance(e, requests.exceptions.ReadTimeout):
                        print(f"CommandInjectionCheck failed for {test_url}: {e}")
                    continue

        return findings
