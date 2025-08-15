import requests
import time
import os
from .base_check import BaseCheck, Vulnerability
import re

class DeserializationCheck(BaseCheck):
    def __init__(self, target_url, ai_mode=False, ai_analyzer=None):
        super().__init__(target_url, ai_mode, ai_analyzer)
        self.payloads = self.load_payloads()
        self.error_patterns = [
            "java.io.InvalidClassException", "System.Runtime.Serialization.SerializationException",
            "could not find type", "unrecognized token", "java.lang.ClassCastException",
            "ysoserial.payloads", "readObject", "Gadget"
        ]

    def load_payloads(self):
        """Loads Insecure Deserialization payloads from the payload file."""
        payloads = []
        path = os.path.join('galdr', 'scanner', 'payloads', 'deserialization_payloads.txt')
        try:
            with open(path, 'r') as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            print(f"Warning: Deserialization payloads file not found at {path}")
        return payloads

    def run(self):
        """
        Runs the Insecure Deserialization check.
        It sends various serialized object payloads in the request body and
        looks for either specific error messages or time-based delays.
        """
        findings = []

        # This check is most effective against endpoints expecting a complex body.
        headers = {'Content-Type': 'application/octet-stream'}

        for payload in self.payloads:
            # --- Time-based Check ---
            expected_delay = 5  # Default delay for payloads designed to sleep
            detection_threshold = expected_delay - 1.0

            start_time = time.time()
            try:
                response = requests.post(
                    self.target_url, data=payload.encode('utf-8'), headers=headers,
                    timeout=expected_delay + 2, verify=False
                )

                # --- Error-based Check ---
                for pattern in self.error_patterns:
                    if pattern in response.text:
                        finding = Vulnerability(
                            url=self.target_url,
                            check_name="Insecure Deserialization (Error-Based)",
                            parameter="Request Body",
                            severity="Critical",
                            details=f"The application returned an error message containing '{pattern}', "
                                    f"suggesting it may be attempting to deserialize untrusted data."
                        )
                        findings.append(finding)
                        return findings # Exit after first confirmed finding

            except requests.exceptions.ReadTimeout:
                elapsed_time = time.time() - start_time
                if elapsed_time >= detection_threshold:
                    finding = Vulnerability(
                        url=self.target_url,
                        check_name="Insecure Deserialization (Time-Based)",
                        parameter="Request Body",
                        severity="Critical",
                        details=f"The application took {elapsed_time:.2f} seconds to respond after injecting a "
                                f"deserialization payload. This suggests the server is processing the "
                                f"malicious serialized object."
                    )
                    findings.append(finding)
                    return findings # Exit after first confirmed finding

            except requests.exceptions.RequestException:
                continue # Ignore other errors and try next payload

        return findings
