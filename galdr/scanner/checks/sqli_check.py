import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .base_check import BaseCheck, Vulnerability
import os
import time
import re
import asyncio

class SqliCheck(BaseCheck):
    def __init__(self, request_data, ai_mode=False, ai_analyzer=None):
        super().__init__(request_data, ai_mode, ai_analyzer)
        self.error_patterns = self.load_payloads('sqli_errors.txt')
        self.time_based_payloads = self.load_payloads('sqli_time_based_payloads.txt')

    def load_payloads(self, filename):
        """Loads payloads from a specified file."""
        payloads = []
        path = os.path.join('galdr', 'scanner', 'payloads', filename)
        try:
            with open(path, 'r') as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            print(f"Warning: Payload file not found at {path}")
        return payloads

    def run(self):
        """
        Runs both error-based and time-based SQL injection checks on all parameters.
        """
        findings = []
        parsed_url = urlparse(self.target_url)
        query_params = parse_qs(parsed_url.query, keep_blank_values=True)

        if not query_params:
            return findings

        for param in query_params:
            # Run error-based check first as it's faster
            error_finding = self._run_error_based_check(param, parsed_url, query_params)
            if error_finding:
                findings.append(error_finding)
                continue # Move to the next parameter

            # If no error was found, try a time-based check for blind SQLi
            time_finding = self._run_time_based_check(param, parsed_url, query_params)
            if time_finding:
                findings.append(time_finding)

        return findings

    def _run_error_based_check(self, param, parsed_url, query_params):
        """Performs an error-based SQLi check on a single parameter."""
        original_value = query_params.get(param, [''])[0]

        # Simple payload for error-based detection
        payload = "'"

        test_params = query_params.copy()
        test_params[param] = original_value + payload
        new_query = urlencode(test_params, doseq=True)
        test_url = urlunparse(parsed_url._replace(query=new_query))

        try:
            response = requests.get(test_url, timeout=10, verify=False)
            for pattern in self.error_patterns:
                if pattern in response.text:
                    return Vulnerability(
                        url=self.target_url,
                        check_name="Error-based SQL Injection",
                        parameter=param,
                        severity="High",
                        details=f"Found SQL error pattern '{pattern}' in response after injecting payload.",
                        request=response.request,
                        response=response
                    )
        except requests.exceptions.RequestException:
            pass # Ignore connection errors

        return None

    def _run_time_based_check(self, param, parsed_url, query_params):
        """Performs a time-based blind SQLi check on a single parameter."""
        original_value = query_params.get(param, [''])[0]

        for payload in self.time_based_payloads:
            match = re.search(r'\((\d+)\)', payload)
            expected_delay = int(match.group(1)) if match else 5
            detection_threshold = expected_delay - 1.0

            test_params = query_params.copy()
            test_params[param] = original_value + payload
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed_url._replace(query=new_query))

            start_time = time.time()
            response = None
            try:
                response = requests.get(test_url, timeout=expected_delay + 2, verify=False)
            except requests.exceptions.ReadTimeout as e:
                elapsed_time = time.time() - start_time
                if elapsed_time >= detection_threshold:
                    return Vulnerability(
                        url=self.target_url,
                        check_name="Blind SQL Injection (Time-Based)",
                        parameter=param,
                        severity="High",
                        details=f"The application took {elapsed_time:.2f} seconds to respond after injecting a time-based SQLi payload.",
                        request=e.request, # Get request from the exception
                        response=None
                    )
            except requests.exceptions.RequestException:
                continue

        return None
