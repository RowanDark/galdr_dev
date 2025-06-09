import asyncio
import time
import hashlib
import logging
import uuid
import os
import re
from typing import Set, Dict, List, Optional
from dataclasses import dataclass
from playwright.async_api import async_playwright, Page, BrowserContext
from PyQt6.QtCore import QThread, pyqtSignal
from core.tech_detector import AdvancedTechDetector
from core.passive_scanner import PassiveSecurityScanner

@dataclass
class CrawlState:
    visited_urls: Set[str]
    discovered_urls: Set[str]
    failed_urls: Set[str]
    page_hashes: Set[str]
    tech_stack: Dict[str, Dict]
    security_findings: List[Dict]
    
    def __init__(self):
        self.visited_urls = set()
        self.discovered_urls = set()
        self.failed_urls = set()
        self.page_hashes = set()
        self.tech_stack = {}
        self.security_findings = []
    
    def add_discovered_url(self, url: str) -> bool:
        if url not in self.visited_urls and url not in self.failed_urls:
            self.discovered_urls.add(url)
            return True
        return False
    
    def is_duplicate_content(self, content_hash: str) -> bool:
        if content_hash in self.page_hashes:
            return True
        self.page_hashes.add(content_hash)
        return False

class NetworkMonitor:
    def __init__(self):
        self.requests = []
        self.responses = []
    
    def handle_request(self, request):
        self.requests.append({
            'url': request.url,
            'method': request.method,
            'headers': dict(request.headers),
            'timestamp': time.time(),
            'resource_type': request.resource_type
        })
    
    def handle_response(self, response):
        self.responses.append({
            'url': response.url,
            'status': response.status,
            'headers': dict(response.headers),
            'timestamp': time.time()
        })

class AdvancedCrawler(QThread):
    update_signal = pyqtSignal(dict)
    tech_signal = pyqtSignal(dict)
    log_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int, int)
    finished_signal = pyqtSignal()
    error_signal = pyqtSignal(str)
    subdomain_found = pyqtSignal(str)
    security_finding = pyqtSignal(dict)

    def __init__(self, url, depth=2, headless=True, delay=1.0, enable_screenshots=True, 
                 enable_subdomain_enum=False, enable_passive_scan=True, use_proxies=False, region_filter=None):
        super().__init__()
        self.url = url
        self.depth = depth
        self.headless = headless
        self.delay = delay
        self.enable_screenshots = enable_screenshots
        self.enable_subdomain_enum = enable_subdomain_enum
        self.enable_passive_scan = enable_passive_scan
        self.use_proxies = use_proxies
        self.region_filter = region_filter or []
        self.running = True
        self.state = CrawlState()
        self.network_monitor = NetworkMonitor()
        self.tech_detector = AdvancedTechDetector()
        self.logger = logging.getLogger(__name__)
        self.session_id = str(uuid.uuid4())
        
        # Create screenshots directory
        if self.enable_screenshots:
            self.screenshots_dir = "screenshots"
            os.makedirs(self.screenshots_dir, exist_ok=True)
        
        # Initialize passive security scanner
        if self.enable_passive_scan:
            self.passive_scanner = PassiveSecurityScanner()
            self.passive_scanner.finding_detected.connect(self.handle_security_finding)

    async def setup_network_monitoring(self, page: Page):
        """Setup network request/response monitoring"""
        page.on("request", self.network_monitor.handle_request)
        page.on("response", self.network_monitor.handle_response)

    def generate_page_hash(self, content: str, url: str) -> str:
        """Generate hash for duplicate detection"""
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(content, 'html.parser')
            # Remove dynamic elements
            for tag in soup.find_all(['script', 'style', 'noscript']):
                tag.decompose()
            
            content_hash = hashlib.md5(
                (url + soup.get_text()).encode('utf-8')
            ).hexdigest()
            return content_hash
        except Exception:
            return hashlib.md5(content.encode('utf-8')).hexdigest()

    async def capture_screenshot(self, page: Page, url: str) -> str:
        """Capture screenshot of the current page"""
        try:
            # Generate filename based on URL and timestamp
            safe_url = re.sub(r'[^\w\-_\.]', '_', url)
            timestamp = int(time.time())
            filename = f"{self.screenshots_dir}/screenshot_{safe_url}_{timestamp}.png"
            
            # Capture screenshot
            await page.screenshot(path=filename, full_page=True)
            self.log_signal.emit(f"📸 Screenshot saved: {filename}")
            
            return filename
        except Exception as e:
            self.log_signal.emit(f"❌ Screenshot failed for {url}: {str(e)}")
            return None

    async def enumerate_subdomains(self, domain: str) -> List[str]:
        """Basic subdomain enumeration for bug bounty reconnaissance"""
        common_subdomains = [
            'www', 'mail', 'admin', 'test', 'dev', 'staging', 'api', 'cdn',
            'blog', 'shop', 'support', 'help', 'docs', 'portal', 'app',
            'mobile', 'secure', 'vpn', 'remote', 'backup', 'old', 'new',
            'beta', 'demo', 'static', 'media', 'images', 'files', 'download'
        ]
        
        found_subdomains = []
        
        for subdomain in common_subdomains:
            if not self.running:
                break
                
            full_domain = f"{subdomain}.{domain}"
            try:
                # Simple HTTP check for subdomain existence
                async with async_playwright() as p:
                    browser = await p.chromium.launch(headless=True)
                    context = await browser.new_context()
                    page = await context.new_page()
                    
                    try:
                        response = await page.goto(f"https://{full_domain}", timeout=5000)
                        if response and response.status < 400:
                            found_subdomains.append(full_domain)
                            self.subdomain_found.emit(full_domain)
                            self.log_signal.emit(f"🎯 Found subdomain: {full_domain}")
                    except:
                        # Try HTTP if HTTPS fails
                        try:
                            response = await page.goto(f"http://{full_domain}", timeout=5000)
                            if response and response.status < 400:
                                found_subdomains.append(full_domain)
                                self.subdomain_found.emit(full_domain)
                                self.log_signal.emit(f"🎯 Found subdomain: {full_domain}")
                        except:
                            pass
                    
                    await browser.close()
                    
            except Exception:
                continue
        
        return found_subdomains

    def handle_security_finding(self, finding_data):
        """Handle security findings from passive scanner"""
        url = finding_data['url']
        finding = finding_data['finding']
        
        # Store finding in crawl state
        self.state.security_findings.append(finding_data)
        
        # Emit signal for UI updates
        self.security_finding.emit(finding_data)
        
        # Log finding with severity-based coloring
        severity = finding['severity']
        severity_emoji = {
            'critical': '🚨',
            'high': '🔴', 
            'medium': '🟡',
            'low': '🟢',
            'info': 'ℹ️'
        }
        
        emoji = severity_emoji.get(severity, '🔍')
        self.log_signal.emit(f"{emoji} {severity.upper()}: {finding['title']} - {url}")

    async def advanced_crawl(self):
        """Main crawling logic with Playwright and enhanced features"""
        try:
            # Extract domain for subdomain enumeration
            from urllib.parse import urlparse
            parsed_url = urlparse(self.url)
            domain = parsed_url.netloc
            
            # Subdomain enumeration if enabled
            if self.enable_subdomain_enum:
                self.log_signal.emit(f"🔍 Starting subdomain enumeration for {domain}")
                subdomains = await self.enumerate_subdomains(domain)
                if subdomains:
                    self.log_signal.emit(f"🎯 Found {len(subdomains)} subdomains")
            
            # Initialize proxy manager if enabled
            current_proxy = None
            if self.use_proxies:
                try:
                    from core.proxy_manager import ProxyManager
                    self.proxy_manager = ProxyManager()
                    current_proxy = self.proxy_manager.get_next_proxy(self.region_filter)
                    if current_proxy:
                        self.log_signal.emit(f"🌐 Using proxy: {current_proxy.host}:{current_proxy.port} ({current_proxy.country})")
                except ImportError:
                    self.log_signal.emit("⚠️ Proxy manager not available")
            
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=self.headless,
                    args=['--disable-web-security', '--disable-features=VizDisplayCompositor'],
                    proxy={"server": current_proxy.get_proxy_url()} if current_proxy else None
                )
                context = await browser.new_context(
                    user_agent="Mozilla/5.0 (compatible; Galdr/2.0; +https://github.com/yourusername/galdr)",
                    viewport={'width': 1920, 'height': 1080}
                )
                
                page = await context.new_page()
                await self.setup_network_monitoring(page)

                # Start crawling
                self.log_signal.emit(f"🚀 Starting crawl of {self.url}")
                await page.goto(self.url, timeout=30000, wait_until='domcontentloaded')
                self.log_signal.emit(f"✅ Successfully loaded: {self.url}")
                
                # Begin recursive crawl (tech detection happens per-page now)
                await self.recursive_crawl(page, self.url, 0)

                await browser.close()
                
                # Log final statistics
                total_findings = len(self.state.security_findings)
                if total_findings > 0:
                    severity_counts = {}
                    for finding_data in self.state.security_findings:
                        severity = finding_data['finding']['severity']
                        severity_counts[severity] = severity_counts.get(severity, 0) + 1
                    
                    self.log_signal.emit(f"🔍 Security scan completed: {total_findings} findings")
                    for severity, count in severity_counts.items():
                        emoji = {'critical': '🚨', 'high': '🔴', 'medium': '🟡', 'low': '🟢', 'info': 'ℹ️'}.get(severity, '🔍')
                        self.log_signal.emit(f"   {emoji} {severity.title()}: {count}")
                
                # Log technology summary
                if self.state.tech_stack:
                    self.log_signal.emit(f"🔧 Technology summary: {len(self.state.tech_stack)} unique technologies detected")
                    for tech, info in self.state.tech_stack.items():
                        version = info.get('version', 'unknown')
                        self.log_signal.emit(f"   • {tech} v{version}")
                
                self.log_signal.emit(f"✅ Crawl completed - {len(self.state.visited_urls)} pages processed")
                
        except Exception as e:
            self.error_signal.emit(f"Crawl failed: {str(e)}")
            self.logger.error(f"Crawl error: {str(e)}")
        finally:
            self.finished_signal.emit()

    async def recursive_crawl(self, page: Page, current_url: str, current_depth: int):
        """Enhanced recursive crawling with per-page technology detection"""
        if current_depth > self.depth or not self.running:
            return

        try:
            # Wait for page to be fully loaded
            await page.wait_for_load_state('networkidle', timeout=10000)
            
            content = await page.content()
            content_hash = self.generate_page_hash(content, current_url)
            
            if self.state.is_duplicate_content(content_hash):
                self.log_signal.emit(f"⏭️ Skipping duplicate content: {current_url}")
                return

            self.state.visited_urls.add(current_url)
            
            # ✅ ENHANCED: Run technology detection on EVERY page
            try:
                page_tech_data = await self.tech_detector.detect_tech(page)
                if page_tech_data:
                    # Emit technology data with URL context
                    tech_with_url = {
                        'url': current_url,
                        'technologies': page_tech_data,
                        'depth': current_depth
                    }
                    self.tech_signal.emit(tech_with_url)
                    
                    # Update global tech stack
                    new_techs_found = 0
                    for tech, info in page_tech_data.items():
                        if tech not in self.state.tech_stack:
                            self.state.tech_stack[tech] = info
                            new_techs_found += 1
                            # Log new technology discovery
                            version = info.get('version', 'unknown')
                            confidence = info.get('confidence', 0)
                            self.log_signal.emit(f"🔧 New tech: {tech} v{version} ({confidence}%) on {current_url}")
                        else:
                            # Update existing tech info if we found a better version/confidence
                            existing_confidence = self.state.tech_stack[tech].get('confidence', 0)
                            new_confidence = info.get('confidence', 0)
                            if new_confidence > existing_confidence:
                                old_version = self.state.tech_stack[tech].get('version', 'unknown')
                                new_version = info.get('version', 'unknown')
                                self.state.tech_stack[tech] = info
                                if old_version != new_version:
                                    self.log_signal.emit(f"🔧 Updated {tech}: v{old_version} → v{new_version} from {current_url}")
                    
                    if new_techs_found > 0:
                        self.log_signal.emit(f"🔧 Found {new_techs_found} new technologies on {current_url}")
                
            except Exception as e:
                self.log_signal.emit(f"⚠️ Tech detection failed on {current_url}: {str(e)}")
            
            # Extract page data
            page_data = {
                'url': current_url,
                'title': await page.title(),
                'timestamp': int(time.time()),
                'depth': current_depth,
                'content_hash': content_hash,
                'status_code': 200
            }
            
            # Capture screenshot for main pages and important findings
            if self.enable_screenshots and (current_depth == 0 or 'admin' in current_url.lower() or 'login' in current_url.lower()):
                screenshot_path = await self.capture_screenshot(page, current_url)
                if screenshot_path:
                    page_data['screenshot'] = screenshot_path
            
            # ✅ FIXED: Passive security scanning with proper response headers handling
            if self.enable_passive_scan:
                try:
                    # Get response headers from network monitor instead of page.response
                    response_headers = {}
                    
                    # Find the most recent response for this URL
                    for response in reversed(self.network_monitor.responses):
                        if response['url'] == current_url:
                            response_headers = response['headers']
                            break
                    
                    # Fallback: try to get basic headers via JavaScript
                    if not response_headers:
                        try:
                            response_headers = await page.evaluate("""
                                () => {
                                    const headers = {};
                                    if (document.contentType) {
                                        headers['content-type'] = document.contentType;
                                    }
                                    return headers;
                                }
                            """)
                        except:
                            response_headers = {}
                    
                    # Get request headers if available
                    request_headers = {}
                    
                    # Run passive security scan
                    findings = self.passive_scanner.analyze_response(
                        current_url, response_headers, content, request_headers
                    )
                    
                    if findings:
                        # Count findings by severity
                        severity_counts = {}
                        for finding in findings:
                            severity = finding.severity
                            severity_counts[severity] = severity_counts.get(severity, 0) + 1
                        
                        # Log summary
                        severity_summary = ", ".join([f"{count} {severity}" for severity, count in severity_counts.items()])
                        self.log_signal.emit(f"🔍 Security scan: {len(findings)} issues found ({severity_summary})")
                        
                except Exception as e:
                    self.log_signal.emit(f"⚠️ Passive scan error on {current_url}: {str(e)}")
            
            self.update_signal.emit(page_data)
            
            # Progress update
            total_discovered = len(self.state.discovered_urls) + len(self.state.visited_urls)
            self.progress_signal.emit(len(self.state.visited_urls), total_discovered)

            # Enhanced link extraction with better error handling
            try:
                links = await page.query_selector_all('a[href]')
                new_links_found = 0
                
                for link in links:
                    if not self.running:
                        break
                    
                    try:
                        href = await link.get_attribute('href')
                        if href and self.is_valid_url(href):
                            full_url = self.resolve_url(current_url, href)
                            if full_url and self.state.add_discovered_url(full_url):
                                new_links_found += 1
                                try:
                                    # Create new page for each navigation to avoid context issues
                                    new_page = await page.context.new_page()
                                    await self.setup_network_monitoring(new_page)
                                    
                                    await new_page.goto(full_url, timeout=30000, wait_until='domcontentloaded')
                                    await asyncio.sleep(self.delay)
                                    
                                    await self.recursive_crawl(new_page, full_url, current_depth + 1)
                                    await new_page.close()
                                    
                                except Exception as nav_error:
                                    self.state.failed_urls.add(full_url)
                                    self.log_signal.emit(f"❌ Navigation failed for {full_url}: {str(nav_error)}")
                    
                    except Exception as link_error:
                        # Skip individual link errors but continue processing
                        continue

                if new_links_found > 0:
                    self.log_signal.emit(f"🔗 Found {new_links_found} new links on {current_url}")

            except Exception as links_error:
                self.log_signal.emit(f"⚠️ Link extraction failed for {current_url}: {str(links_error)}")

        except Exception as e:
            self.log_signal.emit(f"❌ Error processing {current_url}: {str(e)}")

    def is_valid_url(self, url: str) -> bool:
        """Enhanced URL validation for bug bounty reconnaissance"""
        if not url or url == "None":
            return False
        
        # Skip javascript, mailto, tel, and fragment links
        if url.startswith(('javascript:', 'mailto:', 'tel:', '#', 'data:')):
            return False
        
        # Skip common file extensions that aren't useful for security testing
        skip_extensions = [
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.rar', '.exe',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico',
            '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv',
            '.css', '.js', '.woff', '.woff2', '.ttf', '.eot'
        ]
        if any(url.lower().endswith(ext) for ext in skip_extensions):
            return False
        
        return True

    def resolve_url(self, base_url: str, relative_url: str) -> Optional[str]:
        """Enhanced URL resolution with better validation"""
        if not relative_url or relative_url == "None":
            return None
            
        from urllib.parse import urljoin, urlparse
        
        try:
            resolved = urljoin(base_url, relative_url)
            
            # Only crawl URLs from the same domain (security best practice)
            base_domain = urlparse(base_url).netloc
            resolved_domain = urlparse(resolved).netloc
            
            if base_domain != resolved_domain:
                return None
            
            return resolved
        except Exception:
            return None

    def get_crawl_statistics(self) -> Dict:
        """Get comprehensive crawl statistics for bug bounty reporting"""
        vuln_count = 0
        high_risk_count = 0
        
        for tech, info in self.state.tech_stack.items():
            vulns = info.get('vulnerabilities', [])
            vuln_count += len(vulns)
            if info.get('risk_level') in ['high', 'critical']:
                high_risk_count += 1
        
        # Count security findings by severity
        security_findings_by_severity = {}
        for finding_data in self.state.security_findings:
            severity = finding_data['finding']['severity']
            security_findings_by_severity[severity] = security_findings_by_severity.get(severity, 0) + 1
        
        return {
            'session_id': self.session_id,
            'total_visited': len(self.state.visited_urls),
            'total_discovered': len(self.state.discovered_urls),
            'total_failed': len(self.state.failed_urls),
            'technologies_found': len(self.state.tech_stack),
            'vulnerabilities_found': vuln_count,
            'high_risk_technologies': high_risk_count,
            'security_findings_total': len(self.state.security_findings),
            'security_findings_by_severity': security_findings_by_severity,
            'requests_made': len(self.network_monitor.requests),
            'responses_received': len(self.network_monitor.responses)
        }

    def get_security_summary(self) -> Dict:
        """Generate security-focused summary for bug bounty work"""
        summary = {
            'high_value_endpoints': [],
            'vulnerable_technologies': [],
            'security_findings': [],
            'critical_issues': [],
            'potential_attack_vectors': []
        }
        
        # Analyze discovered URLs for high-value targets
        for url in self.state.visited_urls:
            url_lower = url.lower()
            if any(keyword in url_lower for keyword in ['admin', 'login', 'api', 'upload']):
                summary['high_value_endpoints'].append(url)
        
        # Analyze technologies for vulnerabilities
        for tech, info in self.state.tech_stack.items():
            vulns = info.get('vulnerabilities', [])
            if vulns:
                summary['vulnerable_technologies'].append({
                    'technology': tech,
                    'version': info.get('version'),
                    'vulnerabilities': len(vulns),
                    'risk_level': info.get('risk_level')
                })
        
        # Categorize security findings
        for finding_data in self.state.security_findings:
            finding = finding_data['finding']
            summary['security_findings'].append({
                'url': finding_data['url'],
                'title': finding['title'],
                'severity': finding['severity'],
                'confidence': finding['confidence']
            })
            
            # Track critical issues
            if finding['severity'] in ['critical', 'high']:
                summary['critical_issues'].append({
                    'url': finding_data['url'],
                    'issue': finding['title'],
                    'severity': finding['severity']
                })
        
        return summary

    def stop(self):
        """Stop the crawler gracefully"""
        self.running = False
        self.log_signal.emit("⏹️ Crawler stopping...")

    def run(self):
        """QThread run method"""
        try:
            asyncio.run(self.advanced_crawl())
        except Exception as e:
            self.error_signal.emit(f"Crawler thread error: {str(e)}")
