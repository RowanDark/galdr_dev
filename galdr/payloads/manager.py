import os

class PayloadManager:
    """
    Manages loading and accessing payload lists from the payloads directory.
    """
    def __init__(self, payload_path="galdr/payloads"):
        self.payload_path = payload_path
        if not os.path.exists(self.payload_path):
            os.makedirs(self.payload_path)

    def get_available_lists(self) -> list[str]:
        """
        Scans the payload directory and returns a list of available payload file names.
        """
        try:
            files = [
                f for f in os.listdir(self.payload_path)
                if os.path.isfile(os.path.join(self.payload_path, f)) and f.endswith(".txt")
            ]
            return sorted(files)
        except FileNotFoundError:
            return []

    def load_payload_list(self, name: str) -> list[str]:
        """
        Loads a specific payload list from a file.

        Args:
            name: The filename of the payload list (e.g., 'xss_payloads.txt').

        Returns:
            A list of strings, where each string is a payload.
            Returns an empty list if the file cannot be found or read.
        """
        filepath = os.path.join(self.payload_path, name)
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                # Read lines and strip any trailing whitespace
                payloads = [line.strip() for line in f if line.strip()]
            return payloads
        except (FileNotFoundError, IOError):
            return []
