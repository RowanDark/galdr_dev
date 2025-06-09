import re
import yaml
import logging
from typing import Dict, Any, Optional, List
from playwright.async_api import Page

class AdvancedTechDetector:
    def __init__(self, tech_yaml='data/tech_patterns.yaml', cve_yaml='data/cve_db.yaml'):
        self.patterns = self.load_tech_patterns(tech_yaml)
        self.vuln_db = None
        self.logger = logging.getLogger(__name__)
        
        try:
            self.vuln_db = self.load_vulnerability_db(cve_yaml)
        except Exception as e:
            self.logger.warning(f"Could not load vulnerability database: {e}")

    def load_tech_patterns(self, path: str) -> Dict[str, Any]:
        """Load technology detection patterns from YAML"""
        try:
            with open(path, 'r') as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            self.logger.error(f"Failed to load tech patterns: {e}")
            return self.get_fallback_patterns()

    def load_vulnerability_db(self, path: str) -> Dict[str, Any]:
        """Load vulnerability database from YAML"""
        try:
            with open(path, 'r') as f:
                data = yaml.safe_load(f)
                return data.get('technologies', {})
        except Exception as e:
            self.logger.error(f"Failed to load vulnerability database: {e}")
            return {}

    def get_fallback_patterns(self) -> Dict[str, Any]:
        """Fallback patterns if YAML file fails to load"""
        return {
            'wordpress': {
                'html': ['wp-content', 'wp-includes'],
                'headers': {'x-powered-by': 'wordpress'}
            },
            'apache': {
                'headers': {'server': 'apache'}
            },
            'nginx': {
                'headers': {'server': 'nginx'}
            },
            'cloudflare': {
                'headers': {'server': 'cloudflare', 'cf-ray': '.*'},
                'html': ['cf-ray', '__cf_bm', 'cloudflare']
            },
            'react': {
                'html': ['data-reactroot', 'data-react-', '__REACT_DEVTOOLS_GLOBAL_HOOK__'],
                'scripts': ['react.production.min.js', 'react-dom.production.min.js']
            },
            'angular': {
                'html': ['ng-app', 'ng-controller', 'ng-version', 'data-ng-'],
                'scripts': ['angular.min.js', 'angular.js']
            },
            'vue': {
                'html': ['data-v-', '__VUE__', 'v-if', 'v-for'],
                'scripts': ['vue.min.js', 'vue.js']
            },
            'jquery': {
                'scripts': ['jquery.min.js', 'jquery.js'],
                'html': ['jQuery JavaScript Library']
            }
        }

    async def detect_tech(self, page: Page) -> Dict[str, Dict[str, Any]]:
        """Main technology detection method with improved error handling"""
        results = {}
        
        try:
            content = await page.content()
            
            # Fix 1: Get response headers properly
            headers = {}
            try:
                # Get the last response from the page using JavaScript evaluation
                response_info = await page.evaluate("""
                    () => {
                        // Try to get response headers from the current page
                        const headers = {};
                        
                        // Get content type if available
                        if (document.contentType) {
                            headers['content-type'] = document.contentType;
                        }
                        
                        // Get other information from the page
                        headers['url'] = window.location.href;
                        
                        // Try to get server info from meta tags
                        const serverMeta = document.querySelector('meta[name="generator"]');
                        if (serverMeta) {
                            headers['x-generator'] = serverMeta.content;
                        }
                        
                        return headers;
                    }
                """)
                headers = response_info or {}
            except Exception as e:
                self.logger.warning(f"Could not get response headers via JavaScript: {e}")
                headers = {}
            
            for tech, indicators in self.patterns.items():
                try:
                    tech_info = await self.analyze_technology(page, tech, indicators, content, headers)
                    if tech_info:
                        results[tech] = tech_info
                except re.error as regex_error:
                    self.logger.error(f"Regex error in {tech} patterns: {regex_error}")
                    continue
                except Exception as e:
                    self.logger.error(f"Technology detection failed for {tech}: {e}")
                    continue
                    
        except Exception as e:
            self.logger.error(f"Technology detection failed: {e}")
            
        return results

    async def analyze_technology(self, page: Page, tech: str, indicators: Dict, 
                               content: str, headers: Dict) -> Optional[Dict[str, Any]]:
        """Analyze a specific technology with enhanced error handling"""
        tech_found = False
        version = None
        confidence = 0
        detection_methods = []

        try:
            # Header analysis (highest confidence)
            if 'headers' in indicators:
                for header, pattern in indicators['headers'].items():
                    try:
                        header_value = headers.get(header.lower(), '')
                        if header_value and self.safe_regex_search(pattern, header_value):
                            tech_found = True
                            confidence = max(confidence, 90)
                            detection_methods.append('headers')
                            version = self.extract_version(header_value, 
                                                         indicators.get('version_patterns', {}).get(header))
                    except Exception as e:
                        self.logger.warning(f"Header analysis error for {tech} header {header}: {e}")
                        continue

            # HTML content patterns (medium confidence)
            if 'html' in indicators:
                for pattern in indicators['html']:
                    try:
                        if self.safe_regex_search(pattern, content):
                            tech_found = True
                            confidence = max(confidence, 70)
                            detection_methods.append('html')
                            # Try to extract version from HTML
                            if not version:
                                version = self.extract_version_from_content(content, tech)
                    except Exception as e:
                        self.logger.warning(f"HTML analysis error for {tech} pattern {pattern}: {e}")
                        continue

            # Script analysis (medium confidence)
            if 'scripts' in indicators:
                try:
                    scripts = await page.query_selector_all('script[src]')
                    for script in scripts:
                        try:
                            src = await script.get_attribute('src')
                            if src:
                                for pattern in indicators['scripts']:
                                    try:
                                        if self.safe_regex_search(pattern, src):
                                            tech_found = True
                                            confidence = max(confidence, 65)
                                            detection_methods.append('scripts')
                                            if not version:
                                                version = self.extract_version_from_script(src, tech)
                                            break
                                    except Exception as e:
                                        self.logger.warning(f"Script pattern error for {tech}: {e}")
                                        continue
                        except Exception as e:
                            continue
                except Exception as e:
                    self.logger.warning(f"Script analysis error for {tech}: {e}")

            # Cookie analysis (lower confidence)
            if 'cookies' in indicators:
                try:
                    cookies = await page.context.cookies()
                    cookie_names = [cookie['name'] for cookie in cookies]
                    for cookie_pattern in indicators['cookies']:
                        try:
                            if any(self.safe_regex_search(cookie_pattern, name) for name in cookie_names):
                                tech_found = True
                                confidence = max(confidence, 50)
                                detection_methods.append('cookies')
                                break
                        except Exception as e:
                            self.logger.warning(f"Cookie pattern error for {tech}: {e}")
                            continue
                except Exception as e:
                    self.logger.warning(f"Cookie analysis error for {tech}: {e}")

            if tech_found:
                result = {
                    'version': version,
                    'confidence': confidence,
                    'detection_methods': list(set(detection_methods)),
                    'risk_level': 'unknown'
                }
                
                # Add vulnerability information if available
                if self.vuln_db and tech in self.vuln_db:
                    vulns = self.get_vulnerabilities_for_tech(tech, version)
                    if vulns:
                        result['vulnerabilities'] = vulns
                        result['risk_level'] = self.calculate_risk_level(vulns)
                
                return result
            
        except Exception as e:
            self.logger.error(f"Analysis error for {tech}: {e}")
        
        return None

    def safe_regex_search(self, pattern: str, text: str) -> bool:
        """Safely perform regex search with error handling"""
        try:
            # Escape pattern if it's not a valid regex
            if isinstance(pattern, str):
                # Simple string matching for basic patterns
                if not any(char in pattern for char in r'.*+?^${}[]|()\\'): 
                    return pattern.lower() in text.lower()
                else:
                    # Try regex search
                    return bool(re.search(pattern, text, re.I | re.DOTALL))
            return False
        except re.error as e:
            self.logger.warning(f"Invalid regex pattern '{pattern}': {e}")
            # Fallback to simple string matching
            return pattern.lower() in text.lower()
        except Exception as e:
            self.logger.warning(f"Pattern matching error: {e}")
            return False

    def extract_version(self, text: str, patterns: Optional[List[str]]) -> Optional[str]:
        """Extract version number from text using patterns with error handling"""
        if not patterns:
            # Generic version extraction
            patterns = [r'([0-9]+\.[0-9]+(?:\.[0-9]+)?)']
        
        if isinstance(patterns, str):
            patterns = [patterns]
        
        for pattern in patterns:
            try:
                match = re.search(pattern, text, re.I)
                if match:
                    return match.group(1) if match.groups() else match.group(0)
            except re.error as e:
                self.logger.warning(f"Invalid version pattern '{pattern}': {e}")
                continue
            except Exception as e:
                self.logger.warning(f"Version extraction error: {e}")
                continue
        return None

    def extract_version_from_content(self, content: str, tech: str) -> Optional[str]:
        """Extract version from HTML content"""
        try:
            # Common version patterns
            patterns = [
                f'{tech}[\\s/]([0-9.]+)',
                f'{tech}.*?version[\\s:]*([0-9.]+)',
                f'{tech}.*?v([0-9.]+)',
                f'{tech}-([0-9.]+)',
            ]
            
            for pattern in patterns:
                try:
                    match = re.search(pattern, content, re.I)
                    if match:
                        return match.group(1)
                except re.error:
                    continue
        except Exception as e:
            self.logger.warning(f"Content version extraction error for {tech}: {e}")
        return None

    def extract_version_from_script(self, script_src: str, tech: str) -> Optional[str]:
        """Extract version from script source URL"""
        try:
            # Common script version patterns
            patterns = [
                f'{tech}[.-]([0-9.]+)',
                f'{tech}/([0-9.]+)',
                r'([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            ]
            
            for pattern in patterns:
                try:
                    match = re.search(pattern, script_src, re.I)
                    if match:
                        return match.group(1)
                except re.error:
                    continue
        except Exception as e:
            self.logger.warning(f"Script version extraction error for {tech}: {e}")
        return None

    def get_vulnerabilities_for_tech(self, tech: str, version: Optional[str]) -> List[Dict]:
        """Get vulnerabilities for a specific technology and version"""
        if not self.vuln_db or tech not in self.vuln_db:
            return []
        
        tech_vulns = self.vuln_db[tech]
        if not version:
            return tech_vulns  # Return all if no version specified
        
        # Filter by version if specified
        matching_vulns = []
        for vuln in tech_vulns:
            affected_versions = vuln.get('affected_versions', '')
            if self.version_matches(version, affected_versions):
                matching_vulns.append(vuln)
        
        return matching_vulns

    def version_matches(self, version: str, affected_range: str) -> bool:
        """Check if version matches the affected range"""
        if not affected_range:
            return True
        
        try:
            # Simple version matching - can be enhanced
            if version in affected_range:
                return True
            
            # Handle range patterns like ">=5.7 <5.7.2"
            range_match = re.match(r'>=([\d.]+) <([\d.]+)', affected_range)
            if range_match:
                lower, upper = range_match.groups()
                return self.compare_versions(lower, version) <= 0 and self.compare_versions(version, upper) < 0
            
        except Exception as e:
            self.logger.warning(f"Version matching error: {e}")
        
        return False

    def compare_versions(self, v1: str, v2: str) -> int:
        """Compare two version strings"""
        try:
            def normalize(v):
                return [int(x) for x in re.sub(r'(\.0+)*$','', v).split(".")]
            
            v1_parts = normalize(v1)
            v2_parts = normalize(v2)
            
            # Pad with zeros to make same length
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))
            
            if v1_parts < v2_parts:
                return -1
            elif v1_parts > v2_parts:
                return 1
            else:
                return 0
        except Exception:
            return 0

    def calculate_risk_level(self, vulnerabilities: List[Dict]) -> str:
        """Calculate overall risk level based on vulnerabilities"""
        if not vulnerabilities:
            return "low"
        
        max_cvss = max(vuln.get('cvss_score', 0) for vuln in vulnerabilities)
        
        if max_cvss >= 9.0:
            return "critical"
        elif max_cvss >= 7.0:
            return "high"
        elif max_cvss >= 4.0:
            return "medium"
        else:
            return "low"

    def get_detection_summary(self, results: Dict[str, Dict]) -> Dict[str, Any]:
        """Generate a summary of detection results"""
        summary = {
            'total_technologies': len(results),
            'high_risk_count': 0,
            'technologies_with_versions': 0,
            'confidence_distribution': {'high': 0, 'medium': 0, 'low': 0}
        }
        
        for tech, info in results.items():
            # Count technologies with versions
            if info.get('version'):
                summary['technologies_with_versions'] += 1
            
            # Count high-risk technologies
            if info.get('risk_level') in ['high', 'critical']:
                summary['high_risk_count'] += 1
            
            # Confidence distribution
            confidence = info.get('confidence', 0)
            if confidence >= 80:
                summary['confidence_distribution']['high'] += 1
            elif confidence >= 60:
                summary['confidence_distribution']['medium'] += 1
            else:
                summary['confidence_distribution']['low'] += 1
        
        return summary

    def validate_patterns(self) -> Dict[str, List[str]]:
        """Validate all regex patterns and return any invalid ones"""
        invalid_patterns = {}
        
        for tech, indicators in self.patterns.items():
            tech_invalid = []
            
            # Check header patterns
            if 'headers' in indicators:
                for header, pattern in indicators['headers'].items():
                    try:
                        re.compile(pattern)
                    except re.error as e:
                        tech_invalid.append(f"Header {header}: {pattern} - {e}")
            
            # Check HTML patterns
            if 'html' in indicators:
                for pattern in indicators['html']:
                    try:
                        re.compile(pattern)
                    except re.error as e:
                        tech_invalid.append(f"HTML: {pattern} - {e}")
            
            # Check script patterns
            if 'scripts' in indicators:
                for pattern in indicators['scripts']:
                    try:
                        re.compile(pattern)
                    except re.error as e:
                        tech_invalid.append(f"Script: {pattern} - {e}")
            
            # Check cookie patterns
            if 'cookies' in indicators:
                for pattern in indicators['cookies']:
                    try:
                        re.compile(pattern)
                    except re.error as e:
                        tech_invalid.append(f"Cookie: {pattern} - {e}")
            
            if tech_invalid:
                invalid_patterns[tech] = tech_invalid
        
        return invalid_patterns
