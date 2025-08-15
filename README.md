# Galdr: AI-Powered Cybersecurity Suite

![Galdr Logo](galdr/assets/galdr_logo.png)

Galdr is a next-generation cybersecurity suite designed for penetration testers, bug bounty hunters, and security professionals. It integrates automated reconnaissance tools with powerful AI analysis capabilities to streamline the vulnerability discovery process.

## Core Features

-   **Intercepting Web Proxy:** Manipulate HTTP/S traffic in real-time. Features request/response interception, editing, and history logging. Built on a high-performance, stable `mitmproxy` core.
-   **Advanced Web Crawler:** A sophisticated, Playwright-based crawler that can handle modern JavaScript-heavy web applications, discover pages, and enumerate subdomains.
-   **AI-Powered Analysis:**
    -   **AI Co-pilot:** An interactive chat interface to get real-time analysis of security findings, technology stacks, and scan strategies.
    -   **Automated Analysis:** Automatically analyze discovered vulnerabilities to assess severity, determine attack vectors, and prioritize remediation.
    -   **AI Payload Generation:** Generate creative, context-aware payloads for active scanner checks (e.g., SQLi) to enhance detection capabilities.
    -   **Multi-Provider Support:** Supports local models via Ollama (e.g., `foundation-sec-8b`) and major cloud providers (OpenAI, Anthropic, Gemini, etc.).
-   **Comprehensive Vulnerability Database:**
    -   Builds a local, comprehensive database of all known CVEs by cloning and parsing the official MITRE CVE List.
    -   Enriches this data by mapping CVEs to known public exploits from the Exploit-DB repository.
-   **Active Vulnerability Scanner:**
    -   Run active checks for common vulnerabilities like SQL Injection, XSS, and SSRF.
    -   Leverages AI to generate dynamic payloads.
-   **Project Management:**
    -   Create user-specific project profiles to save scan configurations, targets, and history.

## Setup and Installation

Follow these steps to get Galdr up and running on a Debian-based Linux system.

### 1. Prerequisites

-   **Python:** Galdr requires Python 3.12 or newer.
-   **Git:** Required for cloning the repository and the vulnerability databases.
-   **Ollama (Recommended for AI features):** To use the powerful local AI features, you need to have Ollama installed and running.
    -   Follow the official [Ollama installation guide](https://ollama.com/download).

### 2. Installation

```bash
# Clone the repository
git clone <repository_url>
cd galdr

# Create and activate a Python virtual environment
python3 -m venv venv
source venv/bin/activate

# Install the required Python packages
pip install -r requirements.txt

# Install Playwright's browser dependencies
playwright install
```

### 3. AI Model Setup (Recommended)

To enable the local AI analysis features, you need to pull the `foundation-sec-8b` model into your Ollama instance.

```bash
# Pull the recommended security model
ollama pull cisco/foundation-sec-8b-GGUF
```

You can verify that the model is available by running `ollama list`.

### 4. Running Galdr

Once the installation and AI model setup are complete, you can run the application:

```bash
# From the root directory of the project
python3 -m galdr.main
```

### 5. Using the Intercepting Proxy

1.  Start Galdr and navigate to the **Proxy** tab.
2.  Click **"Start Proxy"**. This will start the proxy on `localhost:8080`.
3.  Click **"Export Galdr CA"** and save the certificate file.
4.  Import the saved certificate file (`galdr_mitm_ca.pem`) into your browser's "Authorities" or "Trusted Root Certification Authorities" store. This is a crucial step to allow Galdr to intercept HTTPS traffic.
5.  Configure your browser's proxy settings to use an HTTP proxy at `127.0.0.1` on port `8080`.
6.  All traffic from your browser should now appear in Galdr's Proxy History tab.
