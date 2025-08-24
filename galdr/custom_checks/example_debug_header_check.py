from galdr.checks.api import BasePassiveCheck, SecurityFinding
from typing import List, Dict

class ExampleDebugHeaderCheck(BasePassiveCheck):
    """
    An example of a simple custom passive check.
    This check looks for a specific debug header in the response.
    """
    # --- Metadata ---
    name: str = "Example: Debug Header Check"
    description: str = "Checks for the presence of a 'X-Debug-Mode: enabled' header."
    severity: str = "Low"
    confidence: str = "Firm"
    cwe_id: int = 200 # Information Exposure

    def run(self, url: str, headers: Dict, body: str, request_headers: Dict) -> List[SecurityFinding]:
        """
        Looks for the 'X-Debug-Mode' header.
        """
        findings = []
        debug_header = headers.get('X-Debug-Mode')

        if debug_header and debug_header.lower() == 'enabled':
            finding = SecurityFinding(
                severity=self.severity,
                confidence=self.confidence,
                title=self.name,
                description=self.description,
                evidence=f"The header 'X-Debug-Mode: {debug_header}' was found.",
                remediation="Disable debug headers in production environments.",
                cwe_id=str(self.cwe_id),
                owasp_category="A05:2021-Security Misconfiguration"
            )
            findings.append(finding)

        return findings
