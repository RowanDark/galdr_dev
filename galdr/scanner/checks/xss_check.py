import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .base_check import BaseCheck, Vulnerability
import os
import html

import asyncio

class XssCheck(BaseCheck):
    def __init__(self, target_url, ai_mode=False, ai_analyzer=None):
        super().__init__(target_url, ai_mode, ai_analyzer)
        self.payloads = self.load_payloads()

    def load_payloads(self):
        """Loads XSS payloads from the payload file."""
        payloads = []
        path = os.path.join('galdr', 'scanner', 'payloads', 'xss_payloads.txt')
        try:
            with open(path, 'r') as f:
                payloads = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"Warning: XSS payloads file not found at {path}")
        return payloads

    def run(self):
        """
        Runs the Reflected XSS check on all parameters of the target URL.
        Returns a list of Vulnerability findings.
        """
        findings = []
        parsed_url = urlparse(self.target_url)
        query_params = parse_qs(parsed_url.query)

        if not query_params:
            return findings

        for param, values in query_params.items():
            original_value = values[0]

            payloads_to_test = self.payloads[:] # Start with static payloads
            if self.ai_mode and self.ai_analyzer:
                print(f"Generating AI payloads for XSS on param: {param}")
                context = {'url': self.target_url, 'param': param}
                ai_payloads = asyncio.run(self.ai_analyzer.generate_payloads(context, "XSS"))
                payloads_to_test.extend(ai_payloads)

            for payload in payloads_to_test:
                test_params = query_params.copy()
                test_params[param] = original_value + payload

                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed_url._replace(query=new_query))

                try:
                    response = requests.get(test_url, timeout=10)

                    # Check if the raw payload is in the response body
                    # and that it's NOT properly HTML-encoded.
                    if payload in response.text and html.escape(payload) not in response.text:
                        finding = Vulnerability(
                            url=self.target_url,
                            check_name="Reflected Cross-Site Scripting (XSS)",
                            parameter=param,
                            severity="High",
                            details=f"Payload '{payload}' was reflected in the response without proper HTML encoding."
                        )
                        findings.append(finding)
                        # Stop after first finding for this parameter
                        break
                except requests.exceptions.RequestException as e:
                    print(f"XssCheck failed for {test_url}: {e}")
                    continue

        return findings
