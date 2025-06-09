import asyncio
import dns.resolver
from typing import List, Set
from PyQt6.QtCore import QObject, pyqtSignal

class SubdomainEnumerator(QObject):
    subdomain_found = pyqtSignal(str)
    enumeration_complete = pyqtSignal(list)
    
    def __init__(self):
        super().__init__()
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
            'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn',
            'ns3', 'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile',
            'mx', 'static', 'docs', 'beta', 'shop', 'sql', 'secure', 'demo',
            'cp', 'calendar', 'wiki', 'web', 'media', 'email', 'images', 'img',
            'www1', 'intranet', 'portal', 'video', 'sip', 'dns2', 'api', 'cdn',
            'stats', 'dns1', 'ns4', 'www3', 'dns', 'search', 'staging', 'server',
            'mx1', 'chat', 'wap', 'my', 'svn', 'mail1', 'sites', 'proxy',
            'ads', 'host', 'crm', 'cms', 'backup', 'mx2', 'lyncdiscover', 'info',
            'apps', 'download', 'remote', 'db', 'forums', 'store', 'relay',
            'files', 'newsletter', 'app', 'live', 'owa', 'en', 'start', 'sms',
            'office', 'exchange', 'ipv4', 'mail3', 'help', 'blogs', 'helpdesk',
            'web1', 'home', 'library', 'ftp2', 'ntp', 'monitor', 'login',
            'service', 'correo', 'www4', 'moodle', 'it', 'gateway', 'gw',
            'i', 'stat', 'stage', 'ldap', 'tv', 'ssl', 'web2', 'ns5',
            'upload', 'nagios', 'smtp2', 'online', 'ad', 'survey', 'data',
            'radio', 'extranet', 'test2', 'mssql', 'dns3', 'jobs', 'services',
            'panel', 'irc', 'hosting', 'cloud', 'de', 'gmail', 's', 'bbs',
            'cs', 'ww', 'mrtg', 'git', 'image', 'members', 'poczta'
        ]
    
    async def enumerate_subdomains(self, domain: str) -> List[str]:
        """Enumerate subdomains for a given domain"""
        found_subdomains = set()
        
        # Test common subdomains
        tasks = []
        for subdomain in self.common_subdomains:
            full_domain = f"{subdomain}.{domain}"
            tasks.append(self.check_subdomain(full_domain))
        
        # Execute all checks concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for i, result in enumerate(results):
            if result is True:
                subdomain = f"{self.common_subdomains[i]}.{domain}"
                found_subdomains.add(subdomain)
                self.subdomain_found.emit(subdomain)
        
        subdomain_list = list(found_subdomains)
        self.enumeration_complete.emit(subdomain_list)
        return subdomain_list
    
    async def check_subdomain(self, subdomain: str) -> bool:
        """Check if a subdomain exists"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            
            # Try A record
            try:
                resolver.resolve(subdomain, 'A')
                return True
            except:
                pass
            
            # Try CNAME record
            try:
                resolver.resolve(subdomain, 'CNAME')
                return True
            except:
                pass
            
            return False
        except:
            return False
