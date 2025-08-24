import re
import json
import base64
import hashlib
from typing import Dict, List, Optional
from dataclasses import dataclass
from PyQt6.QtCore import QObject, pyqtSignal

@dataclass
class SecurityFinding:
    severity: str  # critical, high, medium, low, info
    confidence: str  # certain, firm, tentative
    title: str
    description: str
    evidence: str
    remediation: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None

class PassiveSecurityScanner(QObject):
    finding_detected = pyqtSignal(dict)  # Emits SecurityFinding data
    
    def __init__(self):
        super().__init__()
        self.checks = [
            self.check_sensitive_data_exposure,
            self.check_security_headers,
            self.check_cookie_security,
            self.check_information_disclosure,
            self.check_ssl_tls_issues,
            self.check_authentication_issues,
            self.check_session_management,
            self.check_input_validation_hints,
            self.check_error_handling,
            self.check_business_logic_exposure
        ]
    
    def analyze_response(self, url: str, response_headers: Dict, response_body: str, 
                        request_headers: Dict = None) -> List[SecurityFinding]:
        """Analyze HTTP response for security vulnerabilities"""
        findings = []
        
        # Run all passive checks
        for check in self.checks:
            try:
                result = check(url, response_headers, response_body, request_headers)
                if result:
                    if isinstance(result, list):
                        findings.extend(result)
                    else:
                        findings.append(result)
                        
                    # Emit signal for each finding
                    for finding in (result if isinstance(result, list) else [result]):
                        self.finding_detected.emit({
                            'url': url,
                            'finding': finding.__dict__
                        })
            except Exception as e:
                print(f"Error in passive check {check.__name__}: {e}")
        
        return findings
    
    def check_sensitive_data_exposure(self, url, headers, body, req_headers) -> List[SecurityFinding]:
        """Check for sensitive data exposure in responses"""
        findings = []
        
        # AWS Keys
        aws_pattern = r'AKIA[0-9A-Z]{16}'
        if re.search(aws_pattern, body, re.IGNORECASE):
            findings.append(SecurityFinding(
                severity="critical",
                confidence="firm",
                title="AWS Access Key Exposed",
                description="AWS Access Key ID found in response body",
                evidence=re.search(aws_pattern, body).group(),
                remediation="Remove AWS credentials from response and rotate keys immediately",
                cwe_id="CWE-200",
                owasp_category="A01:2021 – Broken Access Control"
            ))
        
        # API Keys (generic patterns)
        api_patterns = [
            r'api[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})',
            r'secret[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})',
            r'access[_-]?token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})'
        ]
        
        for pattern in api_patterns:
            matches = re.finditer(pattern, body, re.IGNORECASE)
            for match in matches:
                findings.append(SecurityFinding(
                    severity="high",
                    confidence="tentative",
                    title="Potential API Key Exposure",
                    description="Possible API key or secret found in response",
                    evidence=match.group(),
                    remediation="Verify if this is a real API key and remove from response",
                    cwe_id="CWE-200"
                ))
        
        # Email addresses
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, body)
        if len(emails) > 5:  # Many emails might indicate data leakage
            findings.append(SecurityFinding(
                severity="medium",
                confidence="tentative",
                title="Multiple Email Addresses Exposed",
                description=f"Found {len(emails)} email addresses in response",
                evidence=f"Emails found: {', '.join(emails[:3])}...",
                remediation="Review if email exposure is intentional",
                cwe_id="CWE-200"
            ))
        
        return findings
    
    def check_security_headers(self, url, headers, body, req_headers) -> List[SecurityFinding]:
        """Check for missing or misconfigured security headers"""
        findings = []
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # Critical security headers
        critical_headers = {
            'x-frame-options': {
                'title': 'Missing X-Frame-Options Header',
                'description': 'X-Frame-Options header not found, page may be vulnerable to clickjacking',
                'remediation': 'Add X-Frame-Options: DENY or SAMEORIGIN header'
            },
            'x-content-type-options': {
                'title': 'Missing X-Content-Type-Options Header', 
                'description': 'X-Content-Type-Options header not found, may allow MIME sniffing attacks',
                'remediation': 'Add X-Content-Type-Options: nosniff header'
            },
            'x-xss-protection': {
                'title': 'Missing X-XSS-Protection Header',
                'description': 'X-XSS-Protection header not found',
                'remediation': 'Add X-XSS-Protection: 1; mode=block header'
            }
        }
        
        for header, info in critical_headers.items():
            if header not in headers_lower:
                findings.append(SecurityFinding(
                    severity="medium",
                    confidence="firm",
                    title=info['title'],
                    description=info['description'],
                    evidence=f"Header '{header}' not present",
                    remediation=info['remediation'],
                    cwe_id="CWE-693",
                    owasp_category="A05:2021 – Security Misconfiguration"
                ))
        
        # Content Security Policy
        findings.extend(self._check_csp(headers_lower.get('content-security-policy')))
        
        # HTTPS Strict Transport Security
        if url.startswith('https://') and 'strict-transport-security' not in headers_lower:
            findings.append(SecurityFinding(
                severity="medium",
                confidence="firm",
                title="Missing HSTS Header",
                description="HTTPS site without HSTS header",
                evidence="Strict-Transport-Security header not present",
                remediation="Add Strict-Transport-Security header for HTTPS sites",
                cwe_id="CWE-319"
            ))
        
        return findings

    def _check_csp(self, csp_header: Optional[str]) -> List[SecurityFinding]:
        """Check a Content-Security-Policy header for weaknesses."""
        findings = []
        if not csp_header:
            findings.append(SecurityFinding(
                severity="medium",
                confidence="firm",
                title="Missing Content Security Policy",
                description="No CSP header found, may be vulnerable to XSS attacks",
                evidence="Content-Security-Policy header not present",
                remediation="Implement a restrictive Content Security Policy",
                cwe_id="CWE-79"
            ))
            return findings

        # Check for weak directives that allow unsafe inline/eval
        weak_directives = ["'unsafe-inline'", "'unsafe-eval'"]
        for directive in weak_directives:
            if directive in csp_header:
                findings.append(SecurityFinding(
                    severity="medium",
                    confidence="firm",
                    title="Weak Content Security Policy",
                    description=f"CSP allows {directive}, which may lead to XSS vulnerabilities.",
                    evidence=f"CSP: {csp_header}",
                    remediation=f"Avoid using {directive} in your Content Security Policy.",
                    cwe_id="CWE-79"
                ))

        # Check for overly broad sources like '*'
        # A simple string check is not perfect but good enough for a first pass.
        if "script-src *" in csp_header or "default-src *" in csp_header:
             findings.append(SecurityFinding(
                severity="low",
                confidence="firm",
                title="Permissive Content Security Policy",
                description="CSP uses a wildcard ('*') source for scripts, which is overly permissive.",
                evidence=f"CSP: {csp_header}",
                remediation="Specify explicit sources instead of using wildcards in your CSP's script-src or default-src.",
                cwe_id="CWE-79"
            ))

        return findings
    
    def check_cookie_security(self, url, headers, body, req_headers) -> List[SecurityFinding]:
        """Check cookie security attributes"""
        findings = []
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        set_cookies = []
        for key, value in headers_lower.items():
            if key == 'set-cookie':
                set_cookies.append(value)
        
        for cookie in set_cookies:
            cookie_lower = cookie.lower()
            
            # Check for missing Secure flag on HTTPS
            if url.startswith('https://') and 'secure' not in cookie_lower:
                findings.append(SecurityFinding(
                    severity="medium",
                    confidence="firm",
                    title="Cookie Missing Secure Flag",
                    description="Cookie set without Secure flag on HTTPS site",
                    evidence=f"Cookie: {cookie[:100]}...",
                    remediation="Add Secure flag to all cookies on HTTPS sites",
                    cwe_id="CWE-614"
                ))
            
            # Check for missing HttpOnly flag
            if 'httponly' not in cookie_lower:
                findings.append(SecurityFinding(
                    severity="medium",
                    confidence="firm",
                    title="Cookie Missing HttpOnly Flag",
                    description="Cookie accessible via JavaScript",
                    evidence=f"Cookie: {cookie[:100]}...",
                    remediation="Add HttpOnly flag to prevent XSS cookie theft",
                    cwe_id="CWE-1004"
                ))
            
            # Check for missing SameSite attribute
            if 'samesite' not in cookie_lower:
                findings.append(SecurityFinding(
                    severity="low",
                    confidence="firm",
                    title="Cookie Missing SameSite Attribute",
                    description="Cookie without SameSite protection",
                    evidence=f"Cookie: {cookie[:100]}...",
                    remediation="Add SameSite=Strict or SameSite=Lax attribute",
                    cwe_id="CWE-352"
                ))
        
        return findings
    
    def check_information_disclosure(self, url, headers, body, req_headers) -> List[SecurityFinding]:
        """Check for information disclosure"""
        findings = []
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # Server version disclosure
        if 'server' in headers_lower:
            server_header = headers_lower['server']
            if re.search(r'/[\d.]+', server_header):  # Version numbers
                findings.append(SecurityFinding(
                    severity="low",
                    confidence="firm",
                    title="Server Version Disclosure",
                    description="Server header reveals version information",
                    evidence=f"Server: {server_header}",
                    remediation="Configure server to not reveal version information",
                    cwe_id="CWE-200"
                ))
        
        # Technology stack disclosure
        tech_headers = ['x-powered-by', 'x-aspnet-version', 'x-generator']
        for header in tech_headers:
            if header in headers_lower:
                findings.append(SecurityFinding(
                    severity="low",
                    confidence="firm",
                    title="Technology Stack Disclosure",
                    description=f"Header {header} reveals technology information",
                    evidence=f"{header}: {headers_lower[header]}",
                    remediation=f"Remove or obfuscate {header} header",
                    cwe_id="CWE-200"
                ))
        
        # Debug information in response
        debug_patterns = [
            r'debug[_\s]*[:=]\s*true',
            r'stack\s*trace',
            r'exception\s*details',
            r'sql\s*error',
            r'database\s*error'
        ]
        
        for pattern in debug_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                findings.append(SecurityFinding(
                    severity="medium",
                    confidence="tentative",
                    title="Debug Information Disclosure",
                    description="Response contains debug or error information",
                    evidence=re.search(pattern, body, re.IGNORECASE).group(),
                    remediation="Disable debug mode in production",
                    cwe_id="CWE-200"
                ))
        
        return findings
    
    def check_ssl_tls_issues(self, url, headers, body, req_headers) -> List[SecurityFinding]:
        """Check for SSL/TLS related issues"""
        findings = []
        
        # HTTP site handling sensitive data
        if url.startswith('http://'):
            sensitive_patterns = [
                r'password',
                r'login',
                r'auth',
                r'credit.?card',
                r'ssn',
                r'social.?security'
            ]
            
            for pattern in sensitive_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    findings.append(SecurityFinding(
                        severity="high",
                        confidence="firm",
                        title="Sensitive Data Over HTTP",
                        description="Sensitive information transmitted over unencrypted HTTP",
                        evidence=f"Pattern found: {pattern}",
                        remediation="Use HTTPS for all sensitive data transmission",
                        cwe_id="CWE-319",
                        owasp_category="A02:2021 – Cryptographic Failures"
                    ))
                    break
        
        return findings
    
    def check_authentication_issues(self, url, headers, body, req_headers) -> List[SecurityFinding]:
        """Check for authentication-related issues"""
        findings = []
        
        # Weak password requirements hints
        weak_password_patterns = [
            r'password.{0,20}minimum.{0,10}[1-6]',
            r'password.{0,20}at.?least.{0,10}[1-6]',
            r'simple.?password',
            r'easy.?password'
        ]
        
        for pattern in weak_password_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                findings.append(SecurityFinding(
                    severity="medium",
                    confidence="tentative",
                    title="Weak Password Policy Detected",
                    description="Application may have weak password requirements",
                    evidence=re.search(pattern, body, re.IGNORECASE).group(),
                    remediation="Implement strong password policy",
                    cwe_id="CWE-521"
                ))
        
        return findings
    
    def check_session_management(self, url, headers, body, req_headers) -> List[SecurityFinding]:
        """Check session management issues"""
        findings = []
        
        # Session ID in URL
        session_patterns = [
            r'jsessionid=',
            r'sessionid=',
            r'phpsessid=',
            r'aspsessionid='
        ]
        
        for pattern in session_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                findings.append(SecurityFinding(
                    severity="medium",
                    confidence="firm",
                    title="Session ID in URL",
                    description="Session identifier exposed in URL",
                    evidence=f"Pattern: {pattern}",
                    remediation="Use cookies for session management instead of URL parameters",
                    cwe_id="CWE-598"
                ))
        
        return findings
    
    def check_input_validation_hints(self, url, headers, body, req_headers) -> List[SecurityFinding]:
        """Check for input validation issues hints"""
        findings = []
        
        # SQL error patterns
        sql_error_patterns = [
            r'sql\s+error',
            r'mysql\s+error',
            r'ora-\d{5}',
            r'microsoft\s+ole\s+db',
            r'postgresql\s+error'
        ]
        
        for pattern in sql_error_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                findings.append(SecurityFinding(
                    severity="high",
                    confidence="firm",
                    title="SQL Error Message Disclosed",
                    description="Database error message exposed in response",
                    evidence=re.search(pattern, body, re.IGNORECASE).group(),
                    remediation="Implement proper error handling to prevent information disclosure",
                    cwe_id="CWE-209"
                ))
        
        return findings
    
    def check_error_handling(self, url, headers, body, req_headers) -> List[SecurityFinding]:
        """Check error handling patterns"""
        findings = []
        
        # Stack trace patterns
        stack_trace_patterns = [
            r'at\s+[\w.]+\([^)]*\.java:\d+\)',
            r'File\s+"[^"]+",\s+line\s+\d+',
            r'Traceback\s+\(most\s+recent\s+call\s+last\)',
            r'Fatal\s+error:.*in\s+.*on\s+line\s+\d+'
        ]
        
        for pattern in stack_trace_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                findings.append(SecurityFinding(
                    severity="medium",
                    confidence="firm",
                    title="Stack Trace Disclosure",
                    description="Application stack trace exposed in response",
                    evidence=re.search(pattern, body, re.IGNORECASE).group()[:200],
                    remediation="Implement custom error pages to prevent stack trace disclosure",
                    cwe_id="CWE-209"
                ))
        
        return findings
    
    def check_business_logic_exposure(self, url, headers, body, req_headers) -> List[SecurityFinding]:
        """Check for business logic exposure"""
        findings = []
        
        # Internal paths/comments
        internal_patterns = [
            r'<!--.*(?:todo|fixme|hack|temp).*-->',
            r'//.*(?:todo|fixme|hack|temp)',
            r'/internal/',
            r'/admin/',
            r'/test/',
            r'/debug/'
        ]
        
        for pattern in internal_patterns:
            matches = re.finditer(pattern, body, re.IGNORECASE)
            for match in matches:
                findings.append(SecurityFinding(
                    severity="low",
                    confidence="tentative",
                    title="Internal Information Disclosure",
                    description="Internal comments or paths found in response",
                    evidence=match.group()[:100],
                    remediation="Remove internal comments and paths from production responses",
                    cwe_id="CWE-200"
                ))
        
        return findings
