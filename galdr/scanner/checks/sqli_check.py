import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .base_check import BaseCheck, Vulnerability
import os

class SqliCheck(BaseCheck):
    def __init__(self, target_url):
        super().__init__(target_url)
        self.payload = "'" # Simple payload for error-based SQLi
        self.error_patterns = self.load_error_patterns()

    def load_error_patterns(self):
        """Loads SQL error patterns from the payload file."""
        patterns = []
        # Correct path assuming the script is run from the project root
        path = os.path.join('galdr', 'scanner', 'payloads', 'sqli_errors.txt')
        try:
            with open(path, 'r') as f:
                patterns = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"Warning: SQLI error patterns file not found at {path}")
        return patterns

    def run(self):
        """
        Runs the SQL injection check on all parameters of the target URL.
        Returns a list of Vulnerability findings.
        """
        findings = []
        parsed_url = urlparse(self.target_url)
        query_params = parse_qs(parsed_url.query)

        if not query_params:
            return findings # No parameters to test

        for param, values in query_params.items():
            original_value = values[0]

            # Create a copy of the params to modify
            test_params = query_params.copy()
            test_params[param] = original_value + self.payload

            # Reconstruct the URL with the payload
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed_url._replace(query=new_query))

            try:
                # Send the request
                response = requests.get(test_url, timeout=10)

                # Check for error patterns in the response body
                for pattern in self.error_patterns:
                    if pattern in response.text:
                        finding = Vulnerability(
                            url=self.target_url,
                            check_name="Error-based SQL Injection",
                            parameter=param,
                            severity="High",
                            details=f"Found SQL error pattern '{pattern}' in response after injecting payload."
                        )
                        findings.append(finding)
                        # Stop after first finding for this parameter
                        break
            except requests.exceptions.RequestException as e:
                print(f"SqliCheck failed for {test_url}: {e}")
                continue

        return findings
