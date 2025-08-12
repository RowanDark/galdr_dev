import random
from dataclasses import dataclass

@dataclass
class Proxy:
    host: str
    port: int
    country: str

    def get_proxy_url(self) -> str:
        """Returns the proxy URL in a format Playwright can use."""
        return f"http://{self.host}:{self.port}"

class ProxyManager:
    def __init__(self, proxy_file="proxies.txt"):
        self.proxies = []
        self.current_index = 0
        self.load_proxies(proxy_file)

    def load_proxies(self, proxy_file):
        """Loads proxies from a file (format: host:port:country)."""
        try:
            with open(proxy_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split(':')
                        if len(parts) == 3:
                            host, port, country = parts
                            self.proxies.append(Proxy(host=host, port=int(port), country=country))
            if self.proxies:
                random.shuffle(self.proxies)
                print(f"Loaded {len(self.proxies)} proxies.")
            else:
                print("Warning: Proxy file was empty or not found. No proxies loaded.")
        except FileNotFoundError:
            print(f"Warning: Proxy file '{proxy_file}' not found. No proxies loaded.")
        except Exception as e:
            print(f"Error loading proxies: {e}")

    def get_next_proxy(self, region_filter=None) -> Proxy | None:
        """
        Gets the next available proxy, cycling through the list.
        Filters by region if a region_filter is provided.
        """
        if not self.proxies:
            return None

        # Filter proxies if a region filter is applied
        eligible_proxies = self.proxies
        if region_filter and isinstance(region_filter, list):
            region_filter_lower = [r.lower() for r in region_filter]
            eligible_proxies = [p for p in self.proxies if p.country.lower() in region_filter_lower]

        if not eligible_proxies:
            return None

        # Cycle through the eligible proxies
        if self.current_index >= len(eligible_proxies):
            self.current_index = 0

        proxy = eligible_proxies[self.current_index]
        self.current_index += 1
        return proxy
