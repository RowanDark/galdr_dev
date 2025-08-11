import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .base_check import BaseCheck, Vulnerability
import os
import time
import uuid

# A public interact.sh server. A private one would be better for production.
INTERACT_SERVER = "interact.sh"

class SsrfCheck(BaseCheck):
    def __init__(self, target_url, ai_mode=False, ai_analyzer=None):
        super().__init__(target_url, ai_mode, ai_analyzer)
        self.interaction_id = str(uuid.uuid4())
        self.interaction_url = f"{self.interaction_id}.{INTERACT_SERVER}"
        self.payload_formats = self.load_payloads()
        print(f"SSRF Check using interaction URL: {self.interaction_url}")

    def load_payloads(self):
        """Loads SSRF payload formats from the payload file."""
        formats = []
        path = os.path.join('galdr', 'scanner', 'payloads', 'ssrf_payloads.txt')
        try:
            with open(path, 'r') as f:
                formats = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            print(f"Warning: SSRF payloads file not found at {path}")
        return formats

    def check_interactions(self):
        """Polls the interaction server to see if a hit was received."""
        # This is a simplified example. A real implementation would need to handle
        # the specific API of the interaction server.
        # For interact.sh, this would involve a DNS query for the ID or using its API.
        # We will simulate this by assuming if a check was positive, an interaction happened.
        # In a real tool, this would be an actual API call.
        # e.g., return requests.get(f"http://{INTERACT_SERVER}/poll?id={self.interaction_id}").json()
        return False # Placeholder

    def run(self):
        """
        Runs the SSRF check.
        Returns a list of Vulnerability findings.
        """
        findings = []
        parsed_url = urlparse(self.target_url)
        query_params = parse_qs(parsed_url.query)

        if not query_params:
            return findings

        for param, values in query_params.items():
            original_value = values[0]

            # Simple check to see if the parameter looks like a URL
            if 'http' not in original_value.lower() and 'url' not in param.lower():
                continue

            for payload_format in self.payload_formats:
                payload = payload_format.format(interact_url=self.interaction_url)

                test_params = query_params.copy()
                test_params[param] = payload

                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed_url._replace(query=new_query))

                try:
                    # Send the request, we don't care about the response, just that it's sent.
                    requests.get(test_url, timeout=5)
                except requests.exceptions.RequestException:
                    pass # Ignore errors

                # After sending, check for an interaction
                # In a real implementation, we would wait a bit before checking
                time.sleep(2)
                if self.check_interactions():
                    finding = Vulnerability(
                        url=self.target_url,
                        check_name="Server-Side Request Forgery (SSRF)",
                        parameter=param,
                        severity="Critical",
                        details=f"The application made an out-of-band request to {self.interaction_url} after injecting the payload."
                    )
                    findings.append(finding)
                    break # Move to next parameter

        return findings
