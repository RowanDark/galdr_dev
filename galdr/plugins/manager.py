import os
import importlib.util
import inspect
from .api import GaldrPlugin, PluginAPI

class PluginManager:
    def __init__(self, plugin_dir="galdr/plugins"):
        self.plugin_dir = plugin_dir
        self.plugins = []
        self.proxy_request_hooks = []
        self.proxy_response_hooks = []
        self.custom_tabs = {}
        self.scanner_checks = []

    def load_plugins(self):
        """
        Discovers and loads all valid plugins from the plugin directory.
        """
        print(f"Loading plugins from: {self.plugin_dir}")
        if not os.path.exists(self.plugin_dir):
            print(f"Plugin directory not found: {self.plugin_dir}")
            return

        for filename in os.listdir(self.plugin_dir):
            if filename.endswith(".py") and not filename.startswith("__"):
                module_name = filename[:-3]
                file_path = os.path.join(self.plugin_dir, filename)

                try:
                    # Import the module
                    spec = importlib.util.spec_from_file_location(module_name, file_path)
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)

                    # Find GaldrPlugin subclasses in the module
                    for name, obj in inspect.getmembers(module):
                        if inspect.isclass(obj) and issubclass(obj, GaldrPlugin) and obj is not GaldrPlugin:
                            # Instantiate the plugin
                            plugin_instance = obj()

                            # Create an API object for this plugin
                            api = PluginAPI(plugin_name=plugin_instance.name)

                            # Register the plugin
                            plugin_instance.register(api)

                            # Store the plugin and its registered hooks
                            self.plugins.append(plugin_instance)
                            self.proxy_request_hooks.extend(api._proxy_request_hooks)
                            self.proxy_response_hooks.extend(api._proxy_response_hooks)
                            self.custom_tabs.update(api._custom_tabs)
                            self.scanner_checks.extend(api._scanner_checks)
                            print(f"Successfully loaded plugin: {plugin_instance.name}")

                except Exception as e:
                    print(f"Failed to load plugin from {filename}: {e}")

    def get_proxy_request_hooks(self):
        return self.proxy_request_hooks

    def get_proxy_response_hooks(self):
        return self.proxy_response_hooks

    def get_custom_tabs(self):
        return self.custom_tabs

    def get_scanner_checks(self):
        return self.scanner_checks
