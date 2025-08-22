from typing import Callable, Any

class PluginAPI:
    """
    The PluginAPI is passed to each plugin upon registration and provides
    methods for the plugin to interact with Galdr.
    """
    def __init__(self, plugin_name: str):
        self.plugin_name = plugin_name
        self._proxy_request_hooks = []
        self._proxy_response_hooks = []
        self._custom_tabs = {}
        self._scanner_checks = []

    def register_scanner_check(self, check_class: Any):
        """Register a custom scanner check."""
        self._scanner_checks.append(check_class)

    def register_proxy_request_hook(self, func: Callable):
        """Register a function to be called on every HTTP request."""
        self._proxy_request_hooks.append(func)

    def register_proxy_response_hook(self, func: Callable):
        """Register a function to be called on every HTTP response."""
        self._proxy_response_hooks.append(func)

    def add_custom_tab(self, name: str, widget_class: Any):
        """Add a custom tab to the main UI."""
        if name in self._custom_tabs:
            print(f"Warning: Custom tab '{name}' already registered. Overwriting.")
        self._custom_tabs[name] = widget_class

class GaldrPlugin:
    """
    The base class for all Galdr plugins.
    Plugins must inherit from this class.
    """
    def __init__(self):
        self.name = "Unnamed Plugin"
        self.version = "0.1.0"
        self.description = "A Galdr plugin."
        self.api: PluginAPI = None

    def register(self, api: PluginAPI):
        """
        This method is called by the PluginManager when the plugin is loaded.
        Plugins should use this method to register their hooks and components.

        :param api: An instance of PluginAPI provided by the manager.
        """
        self.api = api
        print(f"Plugin '{self.name}' registered.")
