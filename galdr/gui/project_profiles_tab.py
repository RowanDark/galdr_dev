from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QListWidget, QTextEdit, QComboBox, QSpinBox, QCheckBox, QGroupBox,
    QMessageBox, QFileDialog, QDialog, QFormLayout, QDialogButtonBox,
    QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView, QSplitter
)
from PyQt6.QtCore import pyqtSignal, Qt, QTimer
from PyQt6.QtGui import QFont
from core.project_manager import ProjectManager, ProjectProfile, ScanSettings, UserPreferences
import time

class CreateProfileDialog(QDialog):
    def __init__(self, project_manager: ProjectManager, parent=None):
        super().__init__(parent)
        self.project_manager = project_manager
        self.setWindowTitle("Create New Project Profile")
        self.setFixedSize(500, 400)
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Profile basic info
        form_layout = QFormLayout()
        
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("e.g., 'Company XYZ Bug Bounty'")
        form_layout.addRow("Profile Name:", self.name_input)
        
        self.description_input = QTextEdit()
        self.description_input.setPlaceholderText("Description of this project...")
        self.description_input.setMaximumHeight(80)
        form_layout.addRow("Description:", self.description_input)
        
        self.tags_input = QLineEdit()
        self.tags_input.setPlaceholderText("bug-bounty, web-app, api (comma-separated)")
        form_layout.addRow("Tags:", self.tags_input)
        
        layout.addLayout(form_layout)
        
        # Current settings option
        self.use_current_settings = QCheckBox("Use current scan settings")
        self.use_current_settings.setChecked(True)
        layout.addWidget(self.use_current_settings)
        
        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
    
    def get_profile_data(self):
        tags = [tag.strip() for tag in self.tags_input.text().split(',') if tag.strip()]
        return {
            'name': self.name_input.text().strip(),
            'description': self.description_input.toPlainText().strip(),
            'tags': tags,
            'use_current_settings': self.use_current_settings.isChecked()
        }

class ProjectProfilesTab(QWidget):
    profile_loaded = pyqtSignal(dict)  # Emits profile settings to apply
    settings_changed = pyqtSignal(dict)  # Emits when profile settings change
    
    def __init__(self, user_name: str):
        super().__init__()
        self.project_manager = ProjectManager(user_name)
        self.current_profile_name = None
        self.init_ui()
        self.connect_signals()
        self.refresh_profiles_list()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Header
        header = QLabel("📁 Project Profiles Manager")
        header.setStyleSheet("""
            QLabel {
                font-size: 18px;
                font-weight: bold;
                color: #00d4aa;
                padding: 15px;
                background-color: rgba(0, 212, 170, 0.1);
                border-radius: 8px;
                margin-bottom: 20px;
            }
        """)
        layout.addWidget(header)
        
        # Create splitter for profiles list and details
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left side - Profiles list and controls
        left_widget = self.create_profiles_list_widget()
        splitter.addWidget(left_widget)
        
        # Right side - Profile details and settings
        right_widget = self.create_profile_details_widget()
        splitter.addWidget(right_widget)
        
        splitter.setSizes([300, 500])
        layout.addWidget(splitter)
    
    def create_profiles_list_widget(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Search and filter
        search_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search profiles...")
        self.search_input.textChanged.connect(self.filter_profiles)
        search_layout.addWidget(self.search_input)
        
        self.tag_filter = QComboBox()
        self.tag_filter.addItem("All Tags")
        self.tag_filter.currentTextChanged.connect(self.filter_profiles)
        search_layout.addWidget(self.tag_filter)
        layout.addLayout(search_layout)
        
        # Profiles list
        self.profiles_list = QListWidget()
        self.profiles_list.itemClicked.connect(self.on_profile_selected)
        layout.addWidget(self.profiles_list)
        
        # Control buttons
        buttons_layout = QVBoxLayout()
        
        self.create_btn = QPushButton("➕ Create Profile")
        self.create_btn.clicked.connect(self.create_profile)
        buttons_layout.addWidget(self.create_btn)
        
        self.load_btn = QPushButton("📂 Load Profile")
        self.load_btn.clicked.connect(self.load_selected_profile)
        self.load_btn.setEnabled(False)
        buttons_layout.addWidget(self.load_btn)
        
        self.save_btn = QPushButton("💾 Save Current")
        self.save_btn.clicked.connect(self.save_current_settings)
        self.save_btn.setEnabled(False)
        buttons_layout.addWidget(self.save_btn)
        
        self.delete_btn = QPushButton("🗑️ Delete")
        self.delete_btn.clicked.connect(self.delete_selected_profile)
        self.delete_btn.setEnabled(False)
        buttons_layout.addWidget(self.delete_btn)
        
        buttons_layout.addStretch()
        
        self.export_btn = QPushButton("📤 Export")
        self.export_btn.clicked.connect(self.export_profile)
        self.export_btn.setEnabled(False)
        buttons_layout.addWidget(self.export_btn)
        
        self.import_btn = QPushButton("📥 Import")
        self.import_btn.clicked.connect(self.import_profile)
        buttons_layout.addWidget(self.import_btn)
        
        layout.addLayout(buttons_layout)
        
        return widget
    
    def create_profile_details_widget(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Profile info
        self.profile_info = QGroupBox("Profile Information")
        info_layout = QFormLayout(self.profile_info)
        
        self.profile_name_label = QLabel("No profile selected")
        self.profile_name_label.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        info_layout.addRow("Name:", self.profile_name_label)
        
        self.profile_description = QLabel("")
        self.profile_description.setWordWrap(True)
        info_layout.addRow("Description:", self.profile_description)
        
        self.profile_created = QLabel("")
        info_layout.addRow("Created:", self.profile_created)
        
        self.profile_modified = QLabel("")
        info_layout.addRow("Modified:", self.profile_modified)
        
        self.profile_tags = QLabel("")
        info_layout.addRow("Tags:", self.profile_tags)
        
        layout.addWidget(self.profile_info)
        
        # Scan settings
        self.scan_settings_group = QGroupBox("Scan Settings")
        self.scan_settings_group.setEnabled(False)
        settings_layout = QFormLayout(self.scan_settings_group)
        
        self.target_url_input = QLineEdit()
        settings_layout.addRow("Target URL:", self.target_url_input)
        
        self.depth_spin = QSpinBox()
        self.depth_spin.setRange(1, 10)
        settings_layout.addRow("Depth:", self.depth_spin)
        
        self.delay_spin = QSpinBox()
        self.delay_spin.setRange(0, 10)
        self.delay_spin.setSuffix(" sec")
        settings_layout.addRow("Delay:", self.delay_spin)
        
        self.headless_check = QCheckBox("Headless Mode")
        settings_layout.addRow(self.headless_check)
        
        self.screenshots_check = QCheckBox("Enable Screenshots")
        settings_layout.addRow(self.screenshots_check)
        
        self.subdomain_check = QCheckBox("Subdomain Enumeration")
        settings_layout.addRow(self.subdomain_check)
        
        self.passive_scan_check = QCheckBox("Passive Security Scan")
        settings_layout.addRow(self.passive_scan_check)
        
        layout.addWidget(self.scan_settings_group)
        
        # Scan history
        self.scan_history_group = QGroupBox("Scan History")
        history_layout = QVBoxLayout(self.scan_history_group)
        
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(4)
        self.history_table.setHorizontalHeaderLabels(["Date", "Duration", "Pages", "Status"])
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        history_layout.addWidget(self.history_table)
        
        layout.addWidget(self.scan_history_group)
        
        return widget
    
    def connect_signals(self):
        self.project_manager.profile_created.connect(self.refresh_profiles_list)
        self.project_manager.profile_deleted.connect(self.refresh_profiles_list)
        self.project_manager.profile_loaded.connect(self.on_profile_loaded)
    
    def refresh_profiles_list(self):
        self.profiles_list.clear()
        profiles = self.project_manager.list_profiles()
        
        for profile_name in sorted(profiles):
            info = self.project_manager.get_profile_info(profile_name)
            if info:
                display_text = f"{profile_name}"
                if info['target_url']:
                    display_text += f" - {info['target_url']}"
                if info['tags']:
                    display_text += f" [{', '.join(info['tags'])}]"
                
                self.profiles_list.addItem(display_text)
        
        # Update tag filter
        stats = self.project_manager.get_profile_statistics()
        self.tag_filter.clear()
        self.tag_filter.addItem("All Tags")
        for tag in stats['available_tags']:
            self.tag_filter.addItem(tag)
    
    def filter_profiles(self):
        search_text = self.search_input.text().lower()
        tag_filter = self.tag_filter.currentText()
        
        for i in range(self.profiles_list.count()):
            item = self.profiles_list.item(i)
            item_text = item.text().lower()
            
            # Check search text
            text_match = search_text in item_text if search_text else True
            
            # Check tag filter
            tag_match = True
            if tag_filter != "All Tags":
                profile_name = item.text().split(" - ")[0]
                profile_tags = self.project_manager.profiles_cache.get(profile_name, None)
                if profile_tags:
                    tag_match = tag_filter.lower() in [t.lower() for t in profile_tags.tags]
                else:
                    tag_match = False
            
            item.setHidden(not (text_match and tag_match))
    
    def on_profile_selected(self, item):
        profile_name = item.text().split(" - ")[0]
        self.current_profile_name = profile_name
        
        # Enable buttons
        self.load_btn.setEnabled(True)
        self.delete_btn.setEnabled(True)
        self.export_btn.setEnabled(True)
        
        # Load profile details
        profile = self.project_manager.load_profile(profile_name)
        if profile:
            self.display_profile_details(profile)
    
    def display_profile_details(self, profile: ProjectProfile):
        # Update profile info
        self.profile_name_label.setText(profile.profile_name)
        self.profile_description.setText(profile.description or "No description")
        self.profile_created.setText(time.strftime("%Y-%m-%d %H:%M", time.localtime(profile.created_at)))
        self.profile_modified.setText(time.strftime("%Y-%m-%d %H:%M", time.localtime(profile.last_modified)))
        self.profile_tags.setText(", ".join(profile.tags) if profile.tags else "No tags")
        
        # Update scan settings
        settings = profile.scan_settings
        self.target_url_input.setText(settings.target_url)
        self.depth_spin.setValue(settings.depth)
        self.delay_spin.setValue(int(settings.delay))
        self.headless_check.setChecked(settings.headless)
        self.screenshots_check.setChecked(settings.enable_screenshots)
        self.subdomain_check.setChecked(settings.enable_subdomain_enum)
        self.passive_scan_check.setChecked(settings.enable_passive_scan)
        
        self.scan_settings_group.setEnabled(True)
        self.save_btn.setEnabled(True)
        
        # Update scan history
        self.history_table.setRowCount(len(profile.scan_history))
        for i, scan in enumerate(profile.scan_history):
            date_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(scan.timestamp))
            duration_str = f"{scan.duration:.1f}s" if scan.duration > 0 else "N/A"
            pages_str = str(scan.results_summary.get('pages_visited', 'N/A'))
            
            self.history_table.setItem(i, 0, QTableWidgetItem(date_str))
            self.history_table.setItem(i, 1, QTableWidgetItem(duration_str))
            self.history_table.setItem(i, 2, QTableWidgetItem(pages_str))
            self.history_table.setItem(i, 3, QTableWidgetItem(scan.status))
    
    def create_profile(self):
        dialog = CreateProfileDialog(self.project_manager, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            data = dialog.get_profile_data()
            
            if not data['name']:
                QMessageBox.warning(self, "Invalid Input", "Profile name is required")
                return
            
            # Get current settings if requested
            scan_settings = None
            if data['use_current_settings']:
                # This would be populated from the main window's current settings
                # For now, use defaults
                scan_settings = ScanSettings()
            
            success = self.project_manager.create_profile(
                data['name'], data['description'], scan_settings, None, data['tags']
            )
            
            if success:
                QMessageBox.information(self, "Success", f"Profile '{data['name']}' created successfully!")
            else:
                QMessageBox.warning(self, "Error", "Failed to create profile")
    
    def load_selected_profile(self):
        if not self.current_profile_name:
            return
        
        profile = self.project_manager.load_profile(self.current_profile_name)
        if profile:
            # Emit signal with profile settings
            settings_dict = {
                'target_url': profile.scan_settings.target_url,
                'depth': profile.scan_settings.depth,
                'headless': profile.scan_settings.headless,
                'delay': profile.scan_settings.delay,
                'enable_screenshots': profile.scan_settings.enable_screenshots,
                'enable_subdomain_enum': profile.scan_settings.enable_subdomain_enum,
                'enable_passive_scan': profile.scan_settings.enable_passive_scan,
                'theme': profile.user_preferences.theme
            }
            
            self.profile_loaded.emit(settings_dict)
            QMessageBox.information(self, "Profile Loaded", f"Profile '{self.current_profile_name}' loaded successfully!")
    
    def save_current_settings(self):
        if not self.current_profile_name:
            return
        
        # Get settings from UI
        scan_settings = ScanSettings(
            target_url=self.target_url_input.text(),
            depth=self.depth_spin.value(),
            delay=float(self.delay_spin.value()),
            headless=self.headless_check.isChecked(),
            enable_screenshots=self.screenshots_check.isChecked(),
            enable_subdomain_enum=self.subdomain_check.isChecked(),
            enable_passive_scan=self.passive_scan_check.isChecked()
        )
        
        success = self.project_manager.update_current_profile_settings(scan_settings)
        if success:
            QMessageBox.information(self, "Settings Saved", "Profile settings updated successfully!")
        else:
            QMessageBox.warning(self, "Error", "Failed to save settings")
    
    def delete_selected_profile(self):
        if not self.current_profile_name:
            return
        
        reply = QMessageBox.question(
            self, "Delete Profile",
            f"Are you sure you want to delete profile '{self.current_profile_name}'?\n\n"
            "This action cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            success = self.project_manager.delete_profile(self.current_profile_name)
            if success:
                self.current_profile_name = None
                self.scan_settings_group.setEnabled(False)
                self.load_btn.setEnabled(False)
                self.delete_btn.setEnabled(False)
                self.export_btn.setEnabled(False)
                self.save_btn.setEnabled(False)
                QMessageBox.information(self, "Profile Deleted", "Profile deleted successfully!")
    
    def export_profile(self):
        if not self.current_profile_name:
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Profile", f"{self.current_profile_name}.json",
            "JSON Files (*.json)"
        )
        
        if filename:
            success = self.project_manager.export_profile(self.current_profile_name, filename)
            if success:
                QMessageBox.information(self, "Export Successful", f"Profile exported to {filename}")
            else:
                QMessageBox.warning(self, "Export Failed", "Failed to export profile")
    
    def import_profile(self):
        filename, _ = QFileDialog.getOpenFileName(
            self, "Import Profile", "", "JSON Files (*.json)"
        )
        
        if filename:
            success = self.project_manager.import_profile(filename)
            if success:
                QMessageBox.information(self, "Import Successful", "Profile imported successfully!")
            else:
                QMessageBox.warning(self, "Import Failed", "Failed to import profile")
    
    def on_profile_loaded(self, profile_name):
        # Update UI to reflect loaded profile
        pass
    
    def add_scan_to_current_profile(self, scan_id: str, results_summary: dict, duration: float = 0.0):
        """Add a completed scan to the current profile's history"""
        if self.project_manager.current_profile:
            self.project_manager.add_scan_to_history(scan_id, results_summary, duration)
            # Refresh the display if this profile is currently selected
            if (self.current_profile_name and 
                self.current_profile_name == self.project_manager.current_profile.profile_name):
                self.display_profile_details(self.project_manager.current_profile)
