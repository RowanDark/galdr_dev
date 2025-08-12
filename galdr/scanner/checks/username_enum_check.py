import requests
from urllib.parse import urlparse
from .base_check import BaseCheck, Vulnerability
import os
import uuid

class UsernameEnumCheck(BaseCheck):
    def __init__(self, target_url, ai_mode=False, ai_analyzer=None):
        super().__init__(target_url, ai_mode, ai_analyzer)
        self.usernames = self.load_usernames()
        # Common parameter names for login forms
        self.username_params = ['username', 'user', 'email', 'login', 'user_id']
        self.password_params = ['password', 'pass', 'pwd']

    def load_usernames(self):
        """Loads common usernames from the payload file."""
        users = []
        path = os.path.join('galdr', 'scanner', 'payloads', 'common_usernames.txt')
        try:
            with open(path, 'r') as f:
                users = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"Warning: Common usernames file not found at {path}")
        return users

    def run(self):
        """
        Runs the Username Enumeration check.
        This check is highly heuristic and may not work on all forms.
        It assumes a POST-based login form.
        """
        findings = []

        # This check is only for URLs that look like login pages
        if 'login' not in self.target_url.lower() and 'signin' not in self.target_url.lower() and 'auth' not in self.target_url.lower():
            return findings

        # Heuristically find username/password parameter names from the page content
        # For now, we will just guess from our common list. A real implementation
        # would parse the HTML for input fields.

        # For simplicity, we'll just try the first combination we find.
        user_param = self.username_params[0]
        pass_param = self.password_params[0]

        # 1. Get baseline for a non-existent user
        invalid_user = str(uuid.uuid4())
        invalid_pass = "password123"
        try:
            response_invalid = requests.post(self.target_url, data={user_param: invalid_user, pass_param: invalid_pass}, timeout=10)
            baseline_length = len(response_invalid.content)
        except requests.exceptions.RequestException as e:
            print(f"UsernameEnumCheck: Could not get baseline from {self.target_url}: {e}")
            return findings

        # 2. Test common usernames
        for user in self.usernames:
            try:
                response_test = requests.post(self.target_url, data={user_param: user, pass_param: invalid_pass}, timeout=10)

                # Check for a significant difference in response length
                if abs(len(response_test.content) - baseline_length) > 100: # Arbitrary threshold
                    finding = Vulnerability(
                        url=self.target_url,
                        check_name="Username Enumeration",
                        parameter=user_param,
                        severity="Medium",
                        details=f"The response for username '{user}' was significantly different from the response for a non-existent user, suggesting the username is valid."
                    )
                    findings.append(finding)
                    # Don't break, continue to find all valid usernames from the list
            except requests.exceptions.RequestException:
                continue

        return findings
