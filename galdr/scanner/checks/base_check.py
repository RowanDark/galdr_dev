class BaseCheck:
    def __init__(self, target_url, ai_mode=False, ai_analyzer=None):
        self.target_url = target_url
        self.ai_mode = ai_mode
        self.ai_analyzer = ai_analyzer

    def run(self):
        """
        This method should be overridden by subclasses to perform the actual check.
        It should return a list of findings.
        """
        raise NotImplementedError("Subclasses must implement the 'run' method.")

class Vulnerability:
    def __init__(self, url, check_name, parameter, severity, details):
        self.url = url
        self.check_name = check_name
        self.parameter = parameter
        self.severity = severity
        self.details = details

    def __repr__(self):
        return f"Vulnerability(check='{self.check_name}', url='{self.url}', param='{self.parameter}')"
