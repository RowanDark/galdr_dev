from .api import GaldrPlugin
from ..scanner.checks.base_check import BaseCheck, CheckResult

class ExampleScannerCheck(BaseCheck):
    """
    An example scanner check that looks for a specific string in the response.
    """
    name = "Example Scanner Check"

    def check(self, request_data):
        response_body = request_data.get("response_body", "")
        if "vulnerable" in response_body.lower():
            self.add_vulnerability(
                url=request_data["url"],
                parameter="response_body",
                evidence="The string 'vulnerable' was found in the response.",
                severity="Low"
            )
        return CheckResult.OK

class ExampleScannerPlugin(GaldrPlugin):
    """
    An example plugin that registers a custom scanner check.
    """
    def __init__(self):
        super().__init__()
        self.name = "Example Scanner Plugin"
        self.version = "1.0"
        self.description = "An example plugin that adds a custom scanner check."

    def register(self, api):
        super().register(api)
        api.register_scanner_check(ExampleScannerCheck)
