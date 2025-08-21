import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .base_check import BaseCheck, Vulnerability
import time

class IdorCheck(BaseCheck):
    def __init__(self, request_data, ai_mode=False, ai_analyzer=None):
        super().__init__(request_data, ai_mode, ai_analyzer)

    def get_response_details(self, url):
        """Gets the full response object."""
        try:
            return requests.get(url, timeout=10, verify=False)
        except requests.exceptions.RequestException:
            return None

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
        baseline_response = self.get_response_details(self.target_url)
        if not baseline_response or baseline_response.status_code != 200:
            return findings # Only test on successful pages
        baseline_length = len(baseline_response.content)

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

                response = self.get_response_details(test_url)

                # Check for potential IDOR
                # Condition: The page still loads (200 OK) but the content length is different
                # This is a simple heuristic and might have false positives/negatives.
                if response and response.status_code == 200 and len(response.content) > 0 and abs(len(response.content) - baseline_length) > (baseline_length * 0.1):
                    finding = Vulnerability(
                        url=self.target_url,
                        check_name="Insecure Direct Object Reference (IDOR)",
                        parameter=param,
                        severity="High",
                        details=f"Accessing object with ID {test_int} returned a 200 OK with a different content length ({len(response.content)} bytes) than the original ({baseline_length} bytes).",
                        request=response.request,
                        response=response
                    )
                    findings.append(finding)
                    break # Found a vulnerability for this param, move to the next

        return findings
