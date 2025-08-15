from .api import GaldrPlugin, PluginAPI
from PyQt6.QtWidgets import QWidget, QLabel, QVBoxLayout

# 1. Define a custom widget for our new tab
class ExampleCustomTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        label = QLabel("Hello from the Example Logger Plugin!")
        label.setStyleSheet("font-size: 16px;")
        layout.addWidget(label)
        self.setLayout(layout)

# 2. Define the main plugin class
class ExampleLoggerPlugin(GaldrPlugin):
    def __init__(self):
        super().__init__()
        self.name = "Example Logger"
        self.version = "1.0"
        self.description = "A simple plugin that logs requests and adds a custom tab."

    # 3. Implement the registration method
    def register(self, api: PluginAPI):
        super().register(api)

        # Register our functions to be called on proxy events
        self.api.register_proxy_request_hook(self.log_request)
        self.api.register_proxy_response_hook(self.log_response)

        # Register our custom UI tab
        self.api.add_custom_tab("Example Tab", ExampleCustomTab)

    # 4. Define the hook methods
    def log_request(self, flow_data: dict):
        """This function will be called for every request."""
        url = flow_data.get('url', 'N/A')
        method = flow_data.get('method', 'N/A')
        print(f"[Example Plugin] Request Hook: Saw {method} request to {url}")

    def log_response(self, flow_data: dict):
        """This function will be called for every response."""
        url = flow_data.get('url', 'N/A')
        status = flow_data.get('status', 'N/A')
        print(f"[Example Plugin] Response Hook: Saw response with status {status} for {url}")
