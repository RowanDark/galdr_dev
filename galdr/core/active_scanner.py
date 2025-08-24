import asyncio
import re
from typing import Dict, List, Optional
from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

from PyQt6.QtCore import QObject, pyqtSignal
from playwright.async_api import async_playwright


@dataclass
class SecurityFinding:
    severity: str
    confidence: str
    title: str
    description: str
    evidence: str
    remediation: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None


class ActiveSecurityScanner(QObject):
    finding_detected = pyqtSignal(dict)
    scan_progress = pyqtSignal(int, int)
    scan_finished = pyqtSignal()
    log_message = pyqtSignal(str)

    def __init__(self, request_data):
        super().__init__()
        self.request_data = request_data
        self.browser = None
        self.checks = [
            ("File Path Traversal", self.check_file_path_traversal),
            ("LDAP Injection", self.check_ldap_injection),
            ("XPath Injection", self.check_xpath_injection),
            ("XML Injection", self.check_xml_injection),
            ("Reflected XSS", self.check_reflected_xss),
            ("SQL Injection", self.check_sql_injection),
        ]
        self._stop_scan = False

    def stop(self):
        self._stop_scan = True
        self.log_message.emit("Scan stop requested.")

    def run_scan(self):
        self._stop_scan = False
        try:
            asyncio.run(self._scan())
        except Exception as e:
            self.log_message.emit(f"Active scan error: {e}")
        finally:
            self.scan_finished.emit()

    async def _scan(self):
        async with async_playwright() as p:
            self.browser = await p.chromium.launch(headless=True)
            injection_points = self._get_injection_points()

            if not injection_points:
                self.log_message.emit("No injection points found in URL parameters.")
                await self.browser.close()
                return

            payload_counts = {name: len(self._get_payloads_for_check(name)) for name, _ in self.checks}
            total_requests = len(injection_points) * sum(payload_counts.values())
            self.log_message.emit(f"Starting active scan with {total_requests} requests.")

            progress = 0
            for point in injection_points:
                if self._stop_scan: break
                self.log_message.emit(f"Scanning parameter: {point['param_name']}")

                for check_name, check_method in self.checks:
                    if self._stop_scan: break
                    payloads = self._get_payloads_for_check(check_name)
                    found_for_this_check = False
                    for payload in payloads:
                        if self._stop_scan or found_for_this_check:
                            progress += 1
                            self.scan_progress.emit(progress, total_requests)
                            continue

                        base_request = self._create_base_request_for_point(point)
                        if await check_method(base_request, payload, point['param_name']):
                            found_for_this_check = True
                        progress += 1
                        self.scan_progress.emit(progress, total_requests)

            await self.browser.close()
        self.log_message.emit("Active scan finished.")

    def _get_payloads_for_check(self, check_name):
        payloads = {
            "File Path Traversal": [
                "../../../../../../../../etc/passwd",
                "../../../../../../../../windows/win.ini",
                "....//....//....//....//etc/passwd",
                "....\\....\\....\\....\\windows\\win.ini",
            ],
            "LDAP Injection": [
                "*(|(objectClass=*))",
                "*)(uid=*))(|(objectClass=*))",
                "' or 1=1))(|(objectClass=*",
                "(&(objectClass=user)(userPassword=password))",
            ],
            "XPath Injection": [
                "' or '1'='1",
                "'] | /* | /foo[bar='",
                "' or count(//*) > 0 and '1'='1",
                "x' or 1=1 or 'y'='z",
            ],
            "XML Injection": [
                "<test>inject</test>",
                "<![CDATA[<test>inject</test>]]>",
                "<foo><bar>baz</bar></foo>",
                "<!-- an XML comment -->",
            ],
            "Reflected XSS": [
                "<script>alert('GaldrXSS')</script>",
                "'\"--><img src=x onerror=alert('GaldrXSS')>",
                "<svg/onload=alert('GaldrXSS')>",
                "javascript:alert('GaldrXSS')",
            ],
            "SQL Injection": [
                "'",
                "\"",
                "\\",
                "'))",
                "';",
            ]
        }
        return payloads.get(check_name, [])

    def _get_injection_points(self):
        points = []
        parsed_url = urlparse(self.request_data['url'])
        query_params = parse_qs(parsed_url.query, keep_blank_values=True)
        for param, values in query_params.items():
            for i, value in enumerate(values):
                points.append({'type': 'url', 'param_name': param, 'param_index': i, 'original_value': value})
        return points

    def _create_base_request_for_point(self, point):
        req = self.request_data.copy()
        if point['type'] == 'url':
            parsed_url = urlparse(req['url'])
            query_params = parse_qs(parsed_url.query, keep_blank_values=True)
            query_params[point['param_name']][point['param_index']] = 'FUZZ'
            new_query = urlencode(query_params, doseq=True)
            req['url'] = urlunparse(list(parsed_url._replace(query=new_query)))
        return req

    async def _send_request(self, base_request, payload):
        context = await self.browser.new_context(ignore_https_errors=True)
        page = await context.new_page()
        target_url = base_request['url'].replace('FUZZ', urlencode({"": payload})[1:])
        body = base_request.get('body')
        if body and 'FUZZ' in body:
            body = body.replace('FUZZ', payload)

        try:
            response = await page.request.fetch(
                target_url,
                method=base_request['method'],
                headers=base_request['headers'],
                data=body.encode('utf-8') if body else None,
                timeout=10000
            )
            response_text = await response.text()
            return {'status': response.status, 'text': response_text, 'headers': dict(response.headers),
                    'payload': payload, 'url': target_url}
        except Exception as e:
            return {'status': -1, 'text': str(e), 'headers': {}, 'payload': payload, 'url': target_url}
        finally:
            await context.close()

    async def check_file_path_traversal(self, base_request, payload, param_name):
        patterns = [re.compile(r"root:x:0:0:"), re.compile(r"\[boot loader\]"), re.compile(r"for 16-bit app support")]
        response = await self._send_request(base_request, payload)
        for pattern in patterns:
            if pattern.search(response['text']):
                self.emit_finding("File Path Traversal", "High", "Firm", response, payload, param_name, "CWE-22")
                return True
        return False

    async def check_ldap_injection(self, base_request, payload, param_name):
        patterns = [re.compile(r"LDAPException|invalid filter|more results to return", re.I)]
        response = await self._send_request(base_request, payload)
        for pattern in patterns:
            if pattern.search(response['text']):
                self.emit_finding("LDAP Injection", "High", "Tentative", response, payload, param_name, "CWE-90")
                return True
        return False

    async def check_xpath_injection(self, base_request, payload, param_name):
        patterns = [re.compile(r"XPathException|Invalid expression|Supplied expression|Evaluation error", re.I),
                    re.compile(r"MS\.Internal\.Xml\.|System\.Xml\.XPath", re.I)]
        response = await self._send_request(base_request, payload)
        for pattern in patterns:
            if pattern.search(response['text']):
                self.emit_finding("XPath Injection", "High", "Firm", response, payload, param_name, "CWE-643")
                return True
        return False

    async def check_xml_injection(self, base_request, payload, param_name):
        patterns = [re.compile(r"XML Parsing Error|Invalid XML|not well-formed", re.I)]
        response = await self._send_request(base_request, payload)
        if response['status'] != 200 and any(p.search(response['text']) for p in patterns):
            self.emit_finding("XML Injection", "Medium", "Tentative", response, payload, param_name, "CWE-91")
            return True
        return False

    async def check_reflected_xss(self, base_request, payload, param_name):
        response = await self._send_request(base_request, payload)

        # Simple check: does the payload appear in the response?
        # A more advanced check would parse HTML and check for execution context.
        if payload in response['text']:
            # Extra check for content type to reduce false positives
            content_type = response['headers'].get('content-type', '').lower()
            if 'html' in content_type:
                self.emit_finding(
                    "Reflected Cross-Site Scripting (XSS)",
                    "High",
                    "Tentative",
                    response,
                    payload,
                    param_name,
                    "CWE-79"
                )
                return True
        return False

    async def check_sql_injection(self, base_request, payload, param_name):
        # Error-based SQLi detection
        error_patterns = [
            re.compile(r"SQL syntax.*?MySQL|Fatal error.*?mysql", re.I),
            re.compile(r"You have an error in your SQL syntax", re.I),
            re.compile(r"Unclosed quotation mark after the character string", re.I),
            re.compile(r"quoted string not properly terminated", re.I),
            re.compile(r"Microsoft OLE DB Provider for ODBC Drivers", re.I),
            re.compile(r"Microsoft OLE DB Provider for SQL Server", re.I),
            re.compile(r"Oracle error", re.I),
            re.compile(r"ORA-[0-9][0-9][0-9][0-9]", re.I),
            re.compile(r"PostgreSQL.*?ERROR", re.I),
            re.compile(r"System\.Data\.SqlClient\.SqlException", re.I),
        ]

        response = await self._send_request(base_request, payload)

        for pattern in error_patterns:
            if pattern.search(response['text']):
                self.emit_finding(
                    "SQL Injection",
                    "High",
                    "Firm",
                    response,
                    payload,
                    param_name,
                    "CWE-89"
                )
                return True
        return False

    def emit_finding(self, title, severity, confidence, response, payload, param_name, cwe_id):
        finding = SecurityFinding(
            severity=severity,
            confidence=confidence,
            title=title,
            description=f"A potential {title} vulnerability was found in the '{param_name}' parameter.",
            evidence=f"Payload: {payload}\nResponse snippet:\n{response['text'][:200]}",
            remediation="Validate and sanitize all user-supplied input. Use parameterized queries or safe APIs.",
            cwe_id=cwe_id,
            owasp_category="A03:2021-Injection"
        )
        self.finding_detected.emit({'url': response['url'], 'finding': finding.__dict__})
