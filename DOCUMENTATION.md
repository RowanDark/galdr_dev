# Galdr User Guide

Welcome to the user guide for Galdr. This document explains how to use the key features of the tool.

## Intercepting Proxy

The Intercepting Proxy is one of the core tools in Galdr. It allows you to inspect and modify HTTP and HTTPS traffic in real-time.

### Setup

To use the proxy, you must first configure your web browser or system to route traffic through it.

1.  **Start the Proxy in Galdr:**
    -   Go to the "Proxy" tab.
    -   Choose a port to listen on (default is 8080).
    -   Click "Start Proxy".

2.  **Configure Your Browser:**
    -   Open your browser's network settings.
    -   Set the HTTP Proxy to `127.0.0.1` and the port to the one you chose in Galdr (e.g., 8080).
    -   Ensure the proxy is used for all protocols, including HTTPS.

3.  **Install the CA Certificate (for HTTPS):**
    -   With the proxy running and your browser configured, navigate to the special URL: `http://mitm.it`.
    -   You will see a page with instructions to download the `mitmproxy` CA certificate. Click the icon for your operating system.
    -   Download the certificate file.
    -   Follow your operating system's instructions to install and trust the downloaded CA certificate. This step is crucial for intercepting HTTPS traffic without constant browser warnings. For example, on macOS, you need to open the downloaded file in Keychain Access and set the certificate to "Always Trust".

Once set up, all traffic from your browser will appear in the Proxy history table.

### Usage

-   **History Table:** Shows a summary of all intercepted requests.
-   **Request/Response Viewers:** Click on any entry in the history table to see the full raw request and response in the panes below.
-   **Sending to Other Tools:** Right-click on any request in the history table to send it to the Repeater, Active Scanner, or Raider for further analysis.

## Raider (Fuzzer)

Raider is a powerful tool for automating custom attacks. It allows you to take a request, mark injection points, and send a large number of payloads to the target.

### Usage

1.  **Load a Request:**
    -   The easiest way to start is to find a request in the Proxy history, right-click it, and select "Send to Raider".
    -   This will load the raw HTTP request into the "Request Template" editor on the left side of the Raider tab.

2.  **Mark Injection Points:**
    -   In the "Request Template" editor, highlight the part of the request you want to fuzz (e.g., a parameter value).
    -   Click the "Add § Injection Marker" button. This will wrap your selection with `§` symbols (e.g., `§some_value§`). This is now an injection point.
    -   You can add multiple injection points, but the simple "Sniper" attack will only use the first one it finds.

3.  **Configure Payloads:**
    -   **Simple List:** Go to the "Simple List" tab and paste your own list of payloads, with one payload per line.
    -   **Built-in Lists:** Go to the "Built-in Lists" tab, select a list (e.g., `xss_payloads.txt`), and Raider will use the payloads from that file.
    -   **AI Generated:** Go to the "AI Generated" tab, select a vulnerability type, and click "Generate". The AI will create a list of context-aware payloads for you.

4.  **Run the Attack:**
    -   Click the "Start Attack" button.
    -   The results will appear in real-time in the results table on the right. You can sort the results by clicking on the column headers (e.g., sort by "Length" or "Status") to find interesting responses.

## Subdomain Enumerator

This tool helps you discover live subdomains for a given target domain using wordlists.

### Usage

1.  **Go to the "Subdomains" tab.**
2.  **Enter the Target Domain:** Type the base domain you want to test (e.g., `example.com`) into the "Target Domain" input field.
3.  **Select a Wordlist:** Choose a wordlist from the dropdown menu. A default list of common subdomains is included.
4.  **Start Enumeration:** Click the "Start" button.
5.  **View Results:** Live subdomains will appear in the list as they are discovered. The progress bar at the bottom shows the status of the scan.
6.  **Export:** Once the scan is complete, you can click the "Export Results" button to save the list of found subdomains to a JSON or CSV file.

## Custom Scanner Checks

Galdr allows you to write your own scanner checks in Python to extend its capabilities.

### How it Works

Galdr will automatically discover and load any Python files you place in the `galdr/custom_checks/` directory. For a check to be loaded, it must be a class that inherits from one of the base classes defined in `galdr.checks.api`.

### Passive Checks

A passive check analyzes HTTP responses without sending new requests.

**Example (`galdr/custom_checks/debug_header.py`):**
```python
from galdr.checks.api import BasePassiveCheck, SecurityFinding
from typing import List, Dict

class DebugHeaderCheck(BasePassiveCheck):
    # 1. Define metadata for your check
    name: str = "Debug Header Check"
    description: str = "Checks for a custom 'X-Debug-Enabled' header."
    severity: str = "Info"
    confidence: str = "Firm"

    # 2. Implement the run method
    def run(self, url: str, headers: Dict, body: str, request_headers: Dict) -> List[SecurityFinding]:
        findings = []
        if headers.get('X-Debug-Enabled') == 'true':
            finding = SecurityFinding(
                severity=self.severity,
                confidence=self.confidence,
                title=self.name,
                description=self.description,
                evidence="The header 'X-Debug-Enabled: true' was found.",
                remediation="Disable debug headers in production."
            )
            findings.append(finding)
        return findings
```

### Active Checks

An active check sends new, potentially malicious requests to the target.

**Example (`galdr/custom_checks/reflection_check.py`):**
```python
from galdr.checks.api import BaseActiveCheck, SecurityFinding
from typing import List, Dict, Optional, Callable, Awaitable

class ReflectionCheck(BaseActiveCheck):
    # 1. Define metadata
    name: str = "Active Reflection Check"
    description: str = "Injects a payload and checks if it's reflected."
    severity: str = "Info"
    confidence: str = "Certain"

    # 2. Define a list of payloads
    payloads: List[str] = ["GaldrReflectionTest"]

    # 3. Implement the async run method
    async def run(self, base_request: Dict, payload: str, send_request: Callable) -> Optional[SecurityFinding]:
        response = await send_request(base_request, payload)
        if payload in response.get('text', ''):
            return SecurityFinding(
                severity=self.severity,
                confidence=self.confidence,
                title=self.name,
                description=self.description,
                evidence=f"The payload '{payload}' was found in the response.",
                remediation="This is an example check."
            )
        return None
```
