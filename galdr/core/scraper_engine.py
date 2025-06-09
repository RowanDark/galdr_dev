import re
import asyncio
from typing import Dict, List, Set
from playwright.async_api import Page
from PyQt6.QtCore import QObject, pyqtSignal

class DataScraper(QObject):
    data_found = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.scraped_data = {
            'emails': set(),
            'phone_numbers': set(),
            'social_media': set(),
            'forms': [],
            'comments': [],
            'javascript_vars': {},
            'api_endpoints': set(),
            'subdomains': set()
        }
    
    async def scrape_page(self, page: Page, url: str) -> Dict:
        """Comprehensive data scraping for bug bounty research"""
        content = await page.content()
        
        # Email extraction
        emails = self.extract_emails(content)
        self.scraped_data['emails'].update(emails)
        
        # Phone number extraction
        phones = self.extract_phone_numbers(content)
        self.scraped_data['phone_numbers'].update(phones)
        
        # Social media links
        social = await self.extract_social_media(page)
        self.scraped_data['social_media'].update(social)
        
        # Form analysis
        forms = await self.analyze_forms(page)
        self.scraped_data['forms'].extend(forms)
        
        # JavaScript variables and API endpoints
        js_data = await self.extract_javascript_data(page)
        self.scraped_data['javascript_vars'].update(js_data.get('vars', {}))
        self.scraped_data['api_endpoints'].update(js_data.get('endpoints', []))
        
        # HTML comments (often contain sensitive info)
        comments = self.extract_comments(content)
        self.scraped_data['comments'].extend(comments)
        
        # Emit current findings
        current_data = {
            'url': url,
            'emails': list(emails),
            'phones': list(phones),
            'forms': forms,
            'api_endpoints': list(js_data.get('endpoints', [])),
            'comments': comments
        }
        
        self.data_found.emit(current_data)
        return current_data
    
    def extract_emails(self, content: str) -> Set[str]:
        """Extract email addresses using regex"""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = set(re.findall(email_pattern, content))
        
        # Filter out common false positives
        filtered_emails = set()
        for email in emails:
            if not any(exclude in email.lower() for exclude in ['example.com', 'test.com', 'localhost']):
                filtered_emails.add(email)
        
        return filtered_emails
    
    def extract_phone_numbers(self, content: str) -> Set[str]:
        """Extract phone numbers using multiple patterns"""
        patterns = [
            r'\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}',  # US format
            r'\+?[0-9]{1,4}[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{1,9}',  # International
        ]
        
        phones = set()
        for pattern in patterns:
            matches = re.findall(pattern, content)
            phones.update(matches)
        
        return phones
    
    async def extract_social_media(self, page: Page) -> Set[str]:
        """Extract social media links"""
        social_domains = [
            'facebook.com', 'twitter.com', 'linkedin.com', 'instagram.com',
            'youtube.com', 'github.com', 'discord.gg', 'telegram.me'
        ]
        
        social_links = set()
        links = await page.query_selector_all('a[href]')
        
        for link in links:
            href = await link.get_attribute('href')
            if href:
                for domain in social_domains:
                    if domain in href:
                        social_links.add(href)
                        break
        
        return social_links
    
    async def analyze_forms(self, page: Page) -> List[Dict]:
        """Analyze forms for security testing"""
        forms = []
        form_elements = await page.query_selector_all('form')
        
        for form in form_elements:
            form_data = {
                'action': await form.get_attribute('action') or '',
                'method': await form.get_attribute('method') or 'GET',
                'inputs': [],
                'has_file_upload': False,
                'has_hidden_fields': False
            }
            
            # Analyze input fields
            inputs = await form.query_selector_all('input, textarea, select')
            for input_elem in inputs:
                input_type = await input_elem.get_attribute('type') or 'text'
                input_name = await input_elem.get_attribute('name') or ''
                input_value = await input_elem.get_attribute('value') or ''
                
                form_data['inputs'].append({
                    'type': input_type,
                    'name': input_name,
                    'value': input_value
                })
                
                if input_type == 'file':
                    form_data['has_file_upload'] = True
                if input_type == 'hidden':
                    form_data['has_hidden_fields'] = True
            
            forms.append(form_data)
        
        return forms
    
    async def extract_javascript_data(self, page: Page) -> Dict:
        """Extract JavaScript variables and API endpoints"""
        try:
            # Execute JavaScript to extract global variables
            js_vars = await page.evaluate("""
                () => {
                    const vars = {};
                    const endpoints = [];
                    
                    // Extract global variables
                    for (let key in window) {
                        if (typeof window[key] === 'string' && window[key].includes('api')) {
                            vars[key] = window[key];
                        }
                    }
                    
                    // Look for API endpoints in script tags
                    const scripts = document.querySelectorAll('script');
                    scripts.forEach(script => {
                        const content = script.textContent || '';
                        const apiMatches = content.match(/['"](/api/[^'"]*)['"]/g);
                        if (apiMatches) {
                            apiMatches.forEach(match => {
                                endpoints.push(match.replace(/['"]/g, ''));
                            });
                        }
                    });
                    
                    return { vars, endpoints };
                }
            """)
            return js_vars
        except:
            return {'vars': {}, 'endpoints': []}
    
    def extract_comments(self, content: str) -> List[str]:
        """Extract HTML comments that might contain sensitive information"""
        comment_pattern = r'<!--(.*?)-->'
        comments = re.findall(comment_pattern, content, re.DOTALL)
        
        # Filter out empty or common comments
        filtered_comments = []
        for comment in comments:
            comment = comment.strip()
            if len(comment) > 10 and not comment.lower().startswith('copyright'):
                filtered_comments.append(comment)
        
        return filtered_comments
    
    def get_summary(self) -> Dict:
        """Get summary of all scraped data"""
        return {
            'total_emails': len(self.scraped_data['emails']),
            'total_phones': len(self.scraped_data['phone_numbers']),
            'total_social_links': len(self.scraped_data['social_media']),
            'total_forms': len(self.scraped_data['forms']),
            'total_api_endpoints': len(self.scraped_data['api_endpoints']),
            'total_comments': len(self.scraped_data['comments'])
        }
