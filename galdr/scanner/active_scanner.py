# Galdr Active Vulnerability Scanner
# This module will contain the core logic for managing and running active scan checks.

from galdr.scanner.checks.sqli_check import SqliCheck
from galdr.scanner.checks.xss_check import XssCheck
from galdr.scanner.checks.command_injection_check import CommandInjectionCheck
from galdr.scanner.checks.ssrf_check import SsrfCheck
from galdr.scanner.checks.idor_check import IdorCheck
from PyQt6.QtCore import QObject, pyqtSignal, QThread

class ActiveScanner(QThread):
    vulnerability_found = pyqtSignal(object)
    scan_finished = pyqtSignal(int)

    def __init__(self, targets, ai_mode=False, ai_analyzer=None):
        super().__init__()
        self.targets = targets
        self.ai_mode = ai_mode
        self.ai_analyzer = ai_analyzer
        self.running = False
        self.checks_to_run = [SqliCheck, XssCheck, CommandInjectionCheck, SsrfCheck, IdorCheck] # A list of check classes to run
        print(f"Active Scanner initialized. AI Mode: {self.ai_mode}")

    def run(self):
        self.running = True
        print(f"Starting active scan on {len(self.targets)} targets...")

        total_findings = 0
        for target in self.targets:
            if not self.running:
                print("Scan stopped by user.")
                break

            print(f"Scanning {target}...")
            for check_class in self.checks_to_run:
                # Pass AI parameters to the check instance
                check_instance = check_class(
                    target_url=target,
                    ai_mode=self.ai_mode,
                    ai_analyzer=self.ai_analyzer
                )
                try:
                    findings = check_instance.run()
                    if findings:
                        total_findings += len(findings)
                        for finding in findings:
                            self.vulnerability_found.emit(finding)
                except Exception as e:
                    print(f"Error running check {check_class.__name__} on {target}: {e}")

        print(f"Scan finished. Found a total of {total_findings} potential vulnerabilities.")
        self.running = False
        self.scan_finished.emit(total_findings)

    def stop_scan(self):
        self.running = False
        print("Stopping active scan...")
