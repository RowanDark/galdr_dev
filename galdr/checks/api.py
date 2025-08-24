from typing import List, Dict, Optional, Callable, Awaitable

from galdr.core.finding import SecurityFinding


class BasePassiveCheck:
    """
    Base class for custom passive scanner checks.
    A passive check analyzes HTTP responses without sending new requests.
    """
    # --- Metadata ---
    name: str = "Unnamed Passive Check"
    description: str = "A custom passive check."
    severity: str = "Info"  # 'Critical', 'High', 'Medium', 'Low', 'Info'
    confidence: str = "Tentative" # 'Certain', 'Firm', 'Tentative'
    cwe_id: Optional[int] = None

    def run(self, url: str, headers: Dict, body: str, request_headers: Dict) -> List[SecurityFinding]:
        """
        This method is called by the passive scanner for each HTTP response.

        Args:
            url: The URL of the response.
            headers: A dictionary of response headers.
            body: The response body as a string.
            request_headers: A dictionary of the original request headers.

        Returns:
            A list of SecurityFinding objects. Return an empty list if no issues are found.
        """
        raise NotImplementedError("Custom passive checks must implement the 'run' method.")


class BaseActiveCheck:
    """
    Base class for custom active scanner checks.
    An active check sends new, potentially malicious requests to the target.
    """
    # --- Metadata ---
    name: str = "Unnamed Active Check"
    description: str = "A custom active check."
    severity: str = "Info"
    confidence: str = "Tentative"
    cwe_id: Optional[int] = None

    # --- Payloads ---
    # A simple list of payloads to be injected.
    # The active scanner will iterate through these and call the 'run' method for each.
    payloads: List[str] = []

    async def run(self, base_request: Dict, payload: str, send_request: Callable[[Dict, str], Awaitable[Dict]]) -> Optional[SecurityFinding]:
        """
        This method is called by the active scanner for each payload.

        Args:
            base_request: A dictionary representing the base HTTP request, with 'FUZZ'
                          as a placeholder for the payload injection point.
            payload: The payload to be injected in this run.
            send_request: An awaitable function that sends the request with the
                          injected payload and returns the response.
                          Usage: `response = await send_request(base_request, payload)`

        Returns:
            A SecurityFinding object if a vulnerability is found, otherwise None.
        """
        raise NotImplementedError("Custom active checks must implement the 'run' method.")
