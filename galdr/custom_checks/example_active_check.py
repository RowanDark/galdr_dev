from galdr.checks.api import BaseActiveCheck, SecurityFinding
from typing import List, Dict, Optional, Callable, Awaitable

class ExampleActiveCheck(BaseActiveCheck):
    """
    An example of a simple custom active check.
    This check injects a payload and looks for its reflection.
    """
    # --- Metadata ---
    name: str = "Example: Active Reflection Check"
    description: str = "Injects a specific payload and checks if it's reflected in the response."
    severity: str = "Info"
    confidence: str = "Certain"
    cwe_id: int = 79 # Using XSS as a generic example for reflection

    # --- Payloads ---
    payloads: List[str] = ["GaldrActiveCheckPayload"]

    async def run(self, base_request: Dict, payload: str, send_request: Callable[[Dict, str], Awaitable[Dict]]) -> Optional[SecurityFinding]:
        """
        Sends the payload and checks for its presence in the response body.
        """
        response = await send_request(base_request, payload)

        if payload in response.get('text', ''):
            finding = SecurityFinding(
                severity=self.severity,
                confidence=self.confidence,
                title=self.name,
                description=self.description,
                evidence=f"The payload '{payload}' was found in the response.",
                remediation="This is an example check. No remediation necessary.",
                cwe_id=str(self.cwe_id)
            )
            return finding

        return None
