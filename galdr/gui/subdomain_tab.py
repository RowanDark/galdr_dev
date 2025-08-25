import json
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QListWidget, QLineEdit,
    QGroupBox, QLabel, QComboBox, QProgressBar, QFileDialog
)
from PyQt6.QtCore import pyqtSlot

from galdr.dns.enumerator import SubdomainEnumerator
from galdr.payloads.manager import PayloadManager

class SubdomainTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.enumerator = None
        self.payload_manager = PayloadManager()
        self.init_ui()
        self.connect_signals()
        self.load_wordlists()

    def init_ui(self):
        layout = QVBoxLayout(self)

        # --- Controls ---
        controls_group = QGroupBox("Enumeration Controls")
        controls_layout = QHBoxLayout(controls_group)

        controls_layout.addWidget(QLabel("Target Domain:"))
        self.target_domain_input = QLineEdit()
        self.target_domain_input.setPlaceholderText("example.com")
        controls_layout.addWidget(self.target_domain_input)

        controls_layout.addWidget(QLabel("Wordlist:"))
        self.wordlist_combo = QComboBox()
        controls_layout.addWidget(self.wordlist_combo)

        self.start_btn = QPushButton("Start")
        controls_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        controls_layout.addWidget(self.stop_btn)

        layout.addWidget(controls_group)

        # --- Results ---
        results_group = QGroupBox("Discovered Subdomains")
        results_layout = QVBoxLayout(results_group)

        self.results_list = QListWidget()
        results_layout.addWidget(self.results_list)

        # Progress Bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        results_layout.addWidget(self.progress_bar)

        # Export Button
        self.export_btn = QPushButton("Export Results")
        self.export_btn.setEnabled(False)
        results_layout.addWidget(self.export_btn, 0, pyqtSlot("AlignmentFlag.AlignRight"))

        layout.addWidget(results_group)

    def connect_signals(self):
        self.start_btn.clicked.connect(self.start_enumeration)
        self.stop_btn.clicked.connect(self.stop_enumeration)
        self.export_btn.clicked.connect(self.export_results)

    def load_wordlists(self):
        """Loads available wordlists into the combo box."""
        # For now, we only load the subdomains list.
        # A more advanced implementation could filter by type.
        available_lists = self.payload_manager.get_available_lists()
        for list_name in available_lists:
            if "subdomain" in list_name:
                self.wordlist_combo.addItem(list_name)

    @pyqtSlot()
    def start_enumeration(self):
        target_domain = self.target_domain_input.text().strip()
        wordlist_name = self.wordlist_combo.currentText()

        if not target_domain or not wordlist_name:
            return

        wordlist = self.payload_manager.load_payload_list(wordlist_name)
        if not wordlist:
            return

        self.results_list.clear()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.export_btn.setEnabled(False)
        self.progress_bar.setValue(0)

        self.enumerator = SubdomainEnumerator(target_domain, wordlist)
        self.enumerator.subdomain_found.connect(self.on_subdomain_found)
        self.enumerator.progress_updated.connect(self.on_progress_updated)
        self.enumerator.enumeration_finished.connect(self.on_enumeration_finished)
        self.enumerator.start()

    @pyqtSlot()
    def stop_enumeration(self):
        if self.enumerator:
            self.enumerator.stop()
        self.stop_btn.setEnabled(False)

    @pyqtSlot(str)
    def on_subdomain_found(self, subdomain):
        self.results_list.addItem(subdomain)

    @pyqtSlot(int, int)
    def on_progress_updated(self, current, total):
        if total > 0:
            self.progress_bar.setMaximum(total)
            self.progress_bar.setValue(current)

    @pyqtSlot()
    def on_enumeration_finished(self):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        if self.results_list.count() > 0:
            self.export_btn.setEnabled(True)
        self.enumerator = None

    @pyqtSlot()
    def export_results(self):
        subdomains = [self.results_list.item(i).text() for i in range(self.results_list.count())]
        if not subdomains:
            return

        filename, selected_filter = QFileDialog.getSaveFileName(
            self,
            "Export Results",
            f"{self.target_domain_input.text()}_subdomains.json",
            "JSON files (*.json);;CSV files (*.csv)"
        )

        if not filename:
            return

        try:
            if selected_filter.startswith("JSON"):
                with open(filename, 'w') as f:
                    json.dump(subdomains, f, indent=4)
            elif selected_filter.startswith("CSV"):
                with open(filename, 'w') as f:
                    f.write("subdomain\n")
                    for domain in subdomains:
                        f.write(f"{domain}\n")
        except Exception as e:
            # A real app would show a message box here
            print(f"Error exporting results: {e}")
