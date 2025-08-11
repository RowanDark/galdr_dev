import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .base_check import BaseCheck, Vulnerability
import time

class IdorCheck(BaseCheck):
    def __init__(self, target_url, ai_mode=False, ai_analyzer=None):
        super().__init__(target_url, ai_mode, ai_analyzer)

    def get_response_details(self, url):
        """Gets the status code and content length of a response."""
        try:
            response = requests.get(url, timeout=10)
            return response.status_code, len(response.content)
        except requests.exceptions.RequestException:
            return -1, -1

    def run(self):
        """
        Runs the IDOR check on all numeric parameters of the target URL.
        Returns a list of Vulnerability findings.
        """
        findings = []
        parsed_url = urlparse(self.target_url)
        query_params = parse_qs(parsed_url.query)

        if not query_params:
            return findings

        # Get baseline response
        baseline_status, baseline_length = self.get_response_details(self.target_url)
        if baseline_status != 200:
            return findings # Only test on successful pages

        for param, values in query_params.items():
            original_value = values[0]

            # Check if the parameter value is numeric
            if not original_value.isdigit():
                continue

            original_int = int(original_value)

            # Test with incremented and decremented values
            for i in [-2, -1, 1, 2]:
                test_int = original_int + i
                if test_int < 0: continue # Skip negative IDs for simplicity

                test_params = query_params.copy()
                test_params[param] = str(test_int)

                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed_url._replace(query=new_query))

                status, length = self.get_response_details(test_url)

                # Check for potential IDOR
                # Condition: The page still loads (200 OK) but the content length is different
                # This is a simple heuristic and might have false positives/negatives.
                if status == 200 and length > 0 and abs(length - baseline_length) > (baseline_length * 0.1):
                    finding = Vulnerability(
                        url=self.target_url,
                        check_name="Insecure Direct Object Reference (IDOR)",
                        parameter=param,
                        severity="High",
                        details=f"Accessing object with ID {test_int} returned a 200 OK with a different content length ({length} bytes) than the original ({baseline_length} bytes)."
                    )
                    findings.append(finding)
                    break # Found a vulnerability for this param, move to the next

        return findings
