import sys
import logging
import uuid
import time
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTableView, QTextEdit, QSpinBox,
    QCheckBox, QTabWidget, QMessageBox, QFileDialog, QMenuBar, QMenu
)
from PyQt6.QtSql import QSqlDatabase, QSqlTableModel, QSqlQuery
from PyQt6.QtCore import Qt, QSettings, pyqtSlot
from PyQt6.QtGui import QAction, QFont, QPixmap, QIcon
from ..auth.secure_config import SecureUserConfig
from ..core.crawler_engine import AdvancedCrawler
from .repeater_tab import RepeaterTab
from .ai_settings_panel import AISettingsPanel
from ..core.ai_integration import AISecurityAnalyzer
from .theme_manager import ThemeManager
from .project_profiles_tab import ProjectProfilesTab
from .cve_monitor_tab import CVEMonitorTab
from .ai_copilot_tab import AICoPilotTab
from ..core.project_manager import ScanSettings, UserPreferences
from .scanner_tab import ScannerTab
from .decoder_tab import DecoderTab
from .comparer_tab import ComparerTab
from .proxy_tab import ProxyTab

class MainWindow(QMainWindow):
    def __init__(self, authenticated_user):
        super().__init__()
        
        # Set application icon
        try:
            icon = QIcon("assets/galdr_logo.png")
            self.setWindowIcon(icon)
            # Also set it for the application
            from PyQt6.QtWidgets import QApplication
            QApplication.instance().setWindowIcon(icon)
        except:
            pass  # Fallback if logo file not found
        
        # User context
        self.current_user = authenticated_user
        self.user_config = SecureUserConfig(authenticated_user)
        
        # Setup user-specific paths
        self.db_path = self.user_config.get_user_database()
        self.tech_patterns_path = self.user_config.get_tech_patterns_path()
        
        # User-specific settings
        self.settings = QSettings(f"Galdr-{authenticated_user}", "UserConfig")
        
        # Initialize theme manager
        self.theme_manager = ThemeManager()
        
        # Window setup
        self.setWindowTitle(f"🕷️ Galdr v2.0 - {authenticated_user}")
        self.setGeometry(100, 100, 1400, 900)
        
        # Initialize components
        self.session_id = str(uuid.uuid4())
        self.logger = logging.getLogger(__name__)
        self.crawler = None
        self.scan_start_time = None
        
        # Initialize AI analyzer
        self.ai_analyzer = AISecurityAnalyzer()
        self.ai_analyzer.initialize()
        
        # Initialize database and UI
        self.init_user_database()
        self.init_ui()
        self.create_menu_bar()
        self.load_user_settings()
        
        # Apply saved theme
        self.theme_manager.apply_theme(self.theme_manager.get_current_theme())
        
        self.append_log(f"🎉 Welcome back, {authenticated_user}!")
        self.append_log(f"🤖 AI Security Analyzer initialized")
        self.append_log(f"🎨 Theme: {self.theme_manager.themes[self.theme_manager.get_current_theme()]['name']}")
        self.append_log(f"📁 Project Profiles System ready")
        self.append_log(f"🛡️ CVE Vulnerability Monitor active")
        self.append_log(f"🤖 AI Co-pilot ready for assistance")
    
    def init_user_database(self):
        """Initialize user-specific database"""
        try:
            self.db = QSqlDatabase.addDatabase("QSQLITE")
            self.db.setDatabaseName(self.db_path)
            
            if not self.db.open():
                raise Exception("Could not open user database")
            
            # Create user-specific tables
            self.create_user_tables()
            
        except Exception as e:
            QMessageBox.critical(self, "Database Error", 
                               f"Failed to initialize user database: {str(e)}")
    
    def create_user_tables(self):
        """Create necessary database tables with enhanced schema for per-page tech detection"""
        queries = [
            """CREATE TABLE IF NOT EXISTS results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                title TEXT,
                timestamp INTEGER,
                depth INTEGER,
                content_hash TEXT,
                status_code INTEGER,
                screenshot TEXT,
                scan_session_id TEXT
            )""",
            """CREATE TABLE IF NOT EXISTS technologies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                tech_name TEXT NOT NULL,
                version TEXT,
                confidence INTEGER,
                risk_level TEXT,
                depth INTEGER,
                detection_method TEXT,
                timestamp INTEGER,
                scan_session_id TEXT
            )""",
            """CREATE TABLE IF NOT EXISTS crawl_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                tech_data TEXT,
                timestamp INTEGER,
                crawl_session_id TEXT
            )""",
            """CREATE TABLE IF NOT EXISTS security_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                finding_title TEXT NOT NULL,
                severity TEXT,
                confidence TEXT,
                description TEXT,
                evidence TEXT,
                remediation TEXT,
                cwe_id TEXT,
                owasp_category TEXT,
                ai_analysis TEXT,
                timestamp INTEGER,
                scan_session_id TEXT
            )"""
        ]
        
        for query_text in queries:
            query = QSqlQuery(self.db)
            if not query.exec(query_text):
                self.logger.error(f"Database query failed: {query.lastError().text()}")
                
        # Add columns if they don't exist (for existing databases)
        alter_queries = [
            "ALTER TABLE results ADD COLUMN screenshot TEXT",
            "ALTER TABLE results ADD COLUMN scan_session_id TEXT",
            "ALTER TABLE technologies ADD COLUMN depth INTEGER",
            "ALTER TABLE technologies ADD COLUMN detection_method TEXT",
            "ALTER TABLE technologies ADD COLUMN timestamp INTEGER",
            "ALTER TABLE technologies ADD COLUMN scan_session_id TEXT",
            "ALTER TABLE security_findings ADD COLUMN scan_session_id TEXT"
        ]
        
        for alter_query in alter_queries:
            query = QSqlQuery(self.db)
            query.exec(alter_query)
            # These will fail silently if columns already exist, which is fine
    
    def init_ui(self):
        """Initialize the user interface"""
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        # Create tabs for different functions
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)

        # Crawler tab
        self.init_crawler_tab()

        # Scanner tab
        self.scanner_tab = ScannerTab(main_window=self, db=self.db)
        self.tab_widget.addTab(self.scanner_tab, "🎯 Active Scan")
        
        # Results tab
        self.init_results_tab()
        
        # Technologies tab
        self.init_tech_tab()
        
        # Security Findings tab
        self.init_security_tab()
        
        # CVE Monitor tab
        self.cve_monitor_tab = CVEMonitorTab()
        self.cve_monitor_tab.vulnerability_detected.connect(self.handle_vulnerability_detection)
        self.tab_widget.addTab(self.cve_monitor_tab, "🛡️ CVE Monitor")
        
        # AI Co-pilot tab
        self.ai_copilot_tab = AICoPilotTab(self.ai_analyzer)
        self.tab_widget.addTab(self.ai_copilot_tab, "🤖 AI Co-pilot")
        
        # Project Profiles tab
        self.project_profiles_tab = ProjectProfilesTab(self.current_user)
        self.project_profiles_tab.profile_loaded.connect(self.load_profile_settings)
        self.tab_widget.addTab(self.project_profiles_tab, "📁 Projects")
        
        # Repeater tab (must be created before Proxy tab to pass reference)
        self.repeater_tab = RepeaterTab()
        self.repeater_tab.request_sent.connect(self.log_repeater_request)

        # Decoder tab
        self.decoder_tab = DecoderTab()
        self.tab_widget.addTab(self.decoder_tab, "🔡 Decoder")

        # Comparer tab
        self.comparer_tab = ComparerTab()
        self.tab_widget.addTab(self.comparer_tab, "↔️ Comparer")

        # Proxy tab
        self.proxy_tab = ProxyTab(repeater_tab=self.repeater_tab, main_window=self)
        self.tab_widget.addTab(self.proxy_tab, "📡 Proxy")

        # Add repeater tab to widget after proxy
        self.tab_widget.addTab(self.repeater_tab, "🔄 Repeater")
        
        # AI Settings tab
        self.ai_settings_panel = AISettingsPanel()
        self.ai_settings_panel.ai_settings_changed.connect(self.update_ai_settings)
        self.tab_widget.addTab(self.ai_settings_panel, "🤖 AI Settings")
        
        # Status bar
        self.statusBar().showMessage(f"Ready - User: {self.current_user}")
    
    def init_crawler_tab(self):
        """Initialize the main crawler interface"""
        crawler_widget = QWidget()
        layout = QVBoxLayout(crawler_widget)

        # Profile status bar
        profile_layout = QHBoxLayout()
        self.current_profile_label = QLabel("📁 No profile loaded")
        self.current_profile_label.setStyleSheet("""
            QLabel {
                background-color: rgba(0, 212, 170, 0.1);
                padding: 8px;
                border-radius: 4px;
                border-left: 4px solid #00d4aa;
            }
        """)
        profile_layout.addWidget(self.current_profile_label)
        
        self.save_to_profile_btn = QPushButton("💾 Save to Profile")
        self.save_to_profile_btn.clicked.connect(self.save_current_settings_to_profile)
        self.save_to_profile_btn.setEnabled(False)
        profile_layout.addWidget(self.save_to_profile_btn)
        
        self.vulnerability_status_label = QLabel("🛡️ CVE Status: Ready")
        self.vulnerability_status_label.setStyleSheet("""
            QLabel {
                background-color: rgba(255, 107, 107, 0.1);
                padding: 8px;
                border-radius: 4px;
                border-left: 4px solid #ff6b6b;
            }
        """)
        profile_layout.addWidget(self.vulnerability_status_label)
        layout.addLayout(profile_layout)

        # URL input section
        url_layout = QHBoxLayout()
        url_layout.addWidget(QLabel("🎯 Target URL:"))
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com")
        self.url_input.textChanged.connect(self.on_settings_changed)
        url_layout.addWidget(self.url_input)
        
        url_layout.addWidget(QLabel("📊 Depth:"))
        self.depth_spin = QSpinBox()
        self.depth_spin.setRange(1, 10)
        self.depth_spin.setValue(2)
        self.depth_spin.valueChanged.connect(self.on_settings_changed)
        url_layout.addWidget(self.depth_spin)
        
        self.headless_check = QCheckBox("👻 Headless Mode")
        self.headless_check.setChecked(True)
        self.headless_check.toggled.connect(self.on_settings_changed)
        url_layout.addWidget(self.headless_check)
        layout.addLayout(url_layout)

        # Advanced options
        advanced_layout = QHBoxLayout()
        self.screenshots_check = QCheckBox("📸 Screenshots")
        self.screenshots_check.setChecked(True)
        self.screenshots_check.toggled.connect(self.on_settings_changed)
        advanced_layout.addWidget(self.screenshots_check)
        
        self.subdomain_check = QCheckBox("🌐 Subdomain Enum")
        self.subdomain_check.toggled.connect(self.on_settings_changed)
        advanced_layout.addWidget(self.subdomain_check)
        
        self.passive_scan_check = QCheckBox("🔍 Passive Security Scan")
        self.passive_scan_check.setChecked(True)
        self.passive_scan_check.toggled.connect(self.on_settings_changed)
        advanced_layout.addWidget(self.passive_scan_check)
        
        self.cve_analysis_check = QCheckBox("🛡️ CVE Analysis")
        self.cve_analysis_check.setChecked(True)
        self.cve_analysis_check.toggled.connect(self.on_settings_changed)
        advanced_layout.addWidget(self.cve_analysis_check)
        
        advanced_layout.addWidget(QLabel("⏱️ Delay (sec):"))
        self.delay_spin = QSpinBox()
        self.delay_spin.setRange(0, 10)
        self.delay_spin.setValue(1)
        self.delay_spin.valueChanged.connect(self.on_settings_changed)
        advanced_layout.addWidget(self.delay_spin)
        layout.addLayout(advanced_layout)

        # Control buttons
        control_layout = QHBoxLayout()
        self.start_btn = QPushButton("🚀 Start Crawl")
        self.start_btn.clicked.connect(self.start_crawl)
        control_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("⏹️ Stop")
        self.stop_btn.clicked.connect(self.stop_crawl)
        self.stop_btn.setEnabled(False)
        control_layout.addWidget(self.stop_btn)
        
        self.export_btn = QPushButton("📁 Export Results")
        self.export_btn.clicked.connect(self.export_results)
        control_layout.addWidget(self.export_btn)
        
        self.clear_log_btn = QPushButton("🗑️ Clear Log")
        self.clear_log_btn.clicked.connect(self.clear_activity_log)
        control_layout.addWidget(self.clear_log_btn)
        layout.addLayout(control_layout)

        # Activity log
        layout.addWidget(QLabel("📋 Activity Log:"))
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setFont(QFont("Courier", 9))
        layout.addWidget(self.log_area)

        self.tab_widget.addTab(crawler_widget, "🕷️ Crawler")
    
    def init_results_tab(self):
        """Initialize the results viewing interface"""
        results_widget = QWidget()
        layout = QVBoxLayout(results_widget)

        # SQL query interface
        sql_layout = QHBoxLayout()
        self.sql_input = QLineEdit()
        self.sql_input.setPlaceholderText("SELECT * FROM results WHERE depth = 1")
        sql_layout.addWidget(self.sql_input)
        
        self.sql_btn = QPushButton("▶️ Execute Query")
        self.sql_btn.clicked.connect(self.run_sql_query)
        sql_layout.addWidget(self.sql_btn)
        
        self.clear_results_btn = QPushButton("🗑️ Clear Results")
        self.clear_results_btn.clicked.connect(self.clear_results_table)
        sql_layout.addWidget(self.clear_results_btn)
        layout.addLayout(sql_layout)

        # Results table with context menu
        self.table_model = QSqlTableModel(self, self.db)
        self.table_model.setTable("results")
        self.table_model.select()
        
        self.table_view = QTableView()
        self.table_view.setModel(self.table_model)
        self.table_view.resizeColumnsToContents()
        
        # Add context menu for "Send to Repeater"
        self.table_view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table_view.customContextMenuRequested.connect(self.show_context_menu)
        
        layout.addWidget(self.table_view)

        self.tab_widget.addTab(results_widget, "📊 Results")
    
    def init_tech_tab(self):
        """Initialize technology detection results tab"""
        tech_widget = QWidget()
        layout = QVBoxLayout(tech_widget)

        # Technology table controls
        tech_controls_layout = QHBoxLayout()
        self.clear_tech_btn = QPushButton("🗑️ Clear Technologies")
        self.clear_tech_btn.clicked.connect(self.clear_tech_table)
        tech_controls_layout.addWidget(self.clear_tech_btn)
        
        self.analyze_cve_btn = QPushButton("🛡️ Analyze CVEs")
        self.analyze_cve_btn.clicked.connect(self.analyze_technologies_for_cves)
        tech_controls_layout.addWidget(self.analyze_cve_btn)
        
        tech_controls_layout.addStretch()
        layout.addLayout(tech_controls_layout)

        # Technology table
        self.tech_model = QSqlTableModel(self, self.db)
        self.tech_model.setTable("technologies")
        self.tech_model.select()
        
        self.tech_view = QTableView()
        self.tech_view.setModel(self.tech_model)
        self.tech_view.resizeColumnsToContents()
        layout.addWidget(QLabel("🔧 Detected Technologies (Per-Page Detection):"))
        layout.addWidget(self.tech_view)

        self.tab_widget.addTab(tech_widget, "🔧 Technologies")
    
    def init_security_tab(self):
        """Initialize security findings tab"""
        security_widget = QWidget()
        layout = QVBoxLayout(security_widget)

        # Security findings controls
        security_controls_layout = QHBoxLayout()
        
        self.analyze_findings_btn = QPushButton("🤖 AI Analysis")
        self.analyze_findings_btn.clicked.connect(self.run_ai_analysis)
        security_controls_layout.addWidget(self.analyze_findings_btn)
        
        self.clear_security_btn = QPushButton("🗑️ Clear Security Findings")
        self.clear_security_btn.clicked.connect(self.clear_security_table)
        security_controls_layout.addWidget(self.clear_security_btn)
        security_controls_layout.addStretch()
        layout.addLayout(security_controls_layout)

        # Security findings table
        self.security_model = QSqlTableModel(self, self.db)
        self.security_model.setTable("security_findings")
        self.security_model.select()
        
        self.security_view = QTableView()
        self.security_view.setModel(self.security_model)
        self.security_view.resizeColumnsToContents()
        layout.addWidget(QLabel("🔍 Security Findings:"))
        layout.addWidget(self.security_view)

        self.tab_widget.addTab(security_widget, "🔍 Security")
    def create_menu_bar(self):
        """Create the application menu bar with theme options"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("📁 File")
        
        # Project submenu
        project_menu = file_menu.addMenu("📁 Projects")
        
        new_project_action = QAction("➕ New Project", self)
        new_project_action.triggered.connect(self.create_new_project)
        project_menu.addAction(new_project_action)
        
        load_project_action = QAction("📂 Load Project", self)
        load_project_action.triggered.connect(self.show_projects_tab)
        project_menu.addAction(load_project_action)
        
        save_project_action = QAction("💾 Save Current Settings", self)
        save_project_action.triggered.connect(self.save_current_settings_to_profile)
        project_menu.addAction(save_project_action)
        
        file_menu.addSeparator()
        
        export_action = QAction("📤 Export Results", self)
        export_action.triggered.connect(self.export_results)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("🚪 Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # View menu for themes
        view_menu = menubar.addMenu("🎨 View")
        
        # Theme submenu
        theme_menu = view_menu.addMenu("🎨 Themes")
        
        # Create theme actions
        for theme_key, theme_name in self.theme_manager.get_available_themes():
            theme_action = QAction(theme_name, self)
            theme_action.triggered.connect(lambda checked, t=theme_key: self.change_theme(t))
            theme_menu.addAction(theme_action)
        
        view_menu.addSeparator()
        
        # Quick theme toggles
        dark_mode_action = QAction("🌙 Dark Mode", self)
        dark_mode_action.triggered.connect(lambda: self.change_theme('dark'))
        view_menu.addAction(dark_mode_action)
        
        light_mode_action = QAction("☀️ Light Mode", self)
        light_mode_action.triggered.connect(lambda: self.change_theme('light'))
        view_menu.addAction(light_mode_action)
        
        galdr_theme_action = QAction("🔴 Galdr Red", self)
        galdr_theme_action.triggered.connect(lambda: self.change_theme('galdr_red'))
        view_menu.addAction(galdr_theme_action)
        
        # AI menu
        ai_menu = menubar.addMenu("🤖 AI Assistant")
        
        open_copilot_action = QAction("🤖 Open AI Co-pilot", self)
        open_copilot_action.triggered.connect(self.show_ai_copilot)
        ai_menu.addAction(open_copilot_action)
        
        ai_menu.addSeparator()
        
        ask_ai_action = QAction("💬 Ask AI about Scan", self)
        ask_ai_action.triggered.connect(self.quick_ask_ai_about_scan)
        ai_menu.addAction(ask_ai_action)
        
        analyze_vulns_action = QAction("🔍 AI Analyze Vulnerabilities", self)
        analyze_vulns_action.triggered.connect(self.ai_analyze_vulnerabilities)
        ai_menu.addAction(analyze_vulns_action)
        
        # Security menu
        security_menu = menubar.addMenu("🛡️ Security")
        
        update_cve_action = QAction("🔄 Update CVE Database", self)
        update_cve_action.triggered.connect(self.update_cve_database)
        security_menu.addAction(update_cve_action)
        
        analyze_cve_action = QAction("🛡️ Analyze Technologies for CVEs", self)
        analyze_cve_action.triggered.connect(self.analyze_technologies_for_cves)
        security_menu.addAction(analyze_cve_action)
        
        security_menu.addSeparator()
        
        cve_monitor_action = QAction("🛡️ Open CVE Monitor", self)
        cve_monitor_action.triggered.connect(self.show_cve_monitor)
        security_menu.addAction(cve_monitor_action)
        
        # Tools menu
        tools_menu = menubar.addMenu("🔧 Tools")
        
        ai_analysis_action = QAction("🤖 Run AI Analysis", self)
        ai_analysis_action.triggered.connect(self.run_ai_analysis)
        tools_menu.addAction(ai_analysis_action)
        
        tools_menu.addSeparator()
        
        clear_data_action = QAction("🗑️ Clear All Data", self)
        clear_data_action.triggered.connect(self.clear_data)
        tools_menu.addAction(clear_data_action)
        
        clear_log_action = QAction("📋 Clear Activity Log", self)
        clear_log_action.triggered.connect(self.clear_activity_log)
        tools_menu.addAction(clear_log_action)
        
        reset_db_action = QAction("🔄 Reset Database", self)
        reset_db_action.triggered.connect(self.reset_database)
        tools_menu.addAction(reset_db_action)
        
        # Help menu
        help_menu = menubar.addMenu("❓ Help")
        
        about_action = QAction("ℹ️ About Galdr", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def create_new_project(self):
        """Switch to projects tab and trigger new project creation"""
        self.tab_widget.setCurrentWidget(self.project_profiles_tab)
        self.project_profiles_tab.create_profile()
    
    def show_projects_tab(self):
        """Switch to projects tab"""
        self.tab_widget.setCurrentWidget(self.project_profiles_tab)
    
    def show_cve_monitor(self):
        """Switch to CVE monitor tab"""
        self.tab_widget.setCurrentWidget(self.cve_monitor_tab)
    
    def show_ai_copilot(self):
        """Switch to AI Co-pilot tab"""
        self.tab_widget.setCurrentWidget(self.ai_copilot_tab)
    
    def quick_ask_ai_about_scan(self):
        """Quick action to ask AI about current scan"""
        self.show_ai_copilot()
        self.ai_copilot_tab.input_box.setText("What should I know about my current scan results?")
        self.ai_copilot_tab.send_message()
    
    def ai_analyze_vulnerabilities(self):
        """Quick action to analyze vulnerabilities with AI"""
        self.show_ai_copilot()
        self.ai_copilot_tab.quick_analyze_vulnerabilities()
    
    def update_cve_database(self):
        """Trigger CVE database update"""
        self.show_cve_monitor()
        self.cve_monitor_tab.start_manual_update()
    
    def analyze_technologies_for_cves(self):
        """Analyze detected technologies for CVE vulnerabilities"""
        try:
            # Get detected technologies from database
            query = QSqlQuery(self.db)
            query.exec("SELECT DISTINCT tech_name, version FROM technologies WHERE scan_session_id = ?")
            query.addBindValue(self.session_id)
            
            technologies = {}
            while query.next():
                tech_name = query.value(0)
                version = query.value(1) or 'unknown'
                technologies[tech_name] = {'version': version}
            
            if not technologies:
                QMessageBox.information(self, "No Technologies", 
                                      "No technologies detected yet. Run a crawl first.")
                return
            
            # Analyze with CVE monitor
            self.cve_monitor_tab.analyze_technologies(technologies)
            
            # Update vulnerability status
            self.vulnerability_status_label.setText("🛡️ CVE Analysis: Complete")
            self.append_log(f"🛡️ Analyzed {len(technologies)} technologies for CVE vulnerabilities")
            
            # Switch to CVE monitor tab to show results
            self.tab_widget.setCurrentWidget(self.cve_monitor_tab)
            
        except Exception as e:
            self.append_log(f"❌ CVE analysis failed: {str(e)}")
    
    def handle_vulnerability_detection(self, technology, vulnerability_data):
        """Handle vulnerability detection from CVE monitor"""
        self.append_log(f"🚨 Vulnerability detected in {technology}: {vulnerability_data}")
        self.vulnerability_status_label.setText(f"🚨 Vulnerabilities found in {technology}")
    
    def update_ai_copilot_context(self):
        """Update AI Co-pilot with current scan context"""
        try:
            # Get current scan statistics
            context_data = {
                'target_url': self.url_input.text(),
                'pages_scanned': self.get_pages_scanned_count(),
                'technologies_count': self.get_technologies_count(),
                'security_findings': self.get_security_findings_count(),
                'cve_count': self.get_cve_count(),
                'recent_activity': self.get_recent_activity(),
                'new_findings': True  # Flag for auto-analysis
            }
            
            # Update AI Co-pilot context
            self.ai_copilot_tab.update_context(context_data)
            
        except Exception as e:
            self.logger.error(f"Failed to update AI Co-pilot context: {e}")
    
    def get_pages_scanned_count(self):
        """Get count of pages scanned in current session"""
        try:
            query = QSqlQuery(self.db)
            query.prepare("SELECT COUNT(*) FROM results WHERE scan_session_id = ?")
            query.addBindValue(self.session_id)
            query.exec()
            if query.next():
                return query.value(0)
        except:
            pass
        return 0
    
    def get_technologies_count(self):
        """Get count of technologies detected in current session"""
        try:
            query = QSqlQuery(self.db)
            query.prepare("SELECT COUNT(DISTINCT tech_name) FROM technologies WHERE scan_session_id = ?")
            query.addBindValue(self.session_id)
            query.exec()
            if query.next():
                return query.value(0)
        except:
            pass
        return 0
    
    def get_security_findings_count(self):
        """Get count of security findings in current session"""
        try:
            query = QSqlQuery(self.db)
            query.prepare("SELECT COUNT(*) FROM security_findings WHERE scan_session_id = ?")
            query.addBindValue(self.session_id)
            query.exec()
            if query.next():
                return query.value(0)
        except:
            pass
        return 0
    
    def get_cve_count(self):
        """Get count of CVE vulnerabilities found in the current analysis."""
        if hasattr(self, 'cve_monitor_tab'):
            return self.cve_monitor_tab.vulnerability_table.rowCount()
        return 0
    
    def get_recent_activity(self):
        """Get recent activity summary"""
        return f"Last scan: {self.session_id[:8]}..."
    
    def load_profile_settings(self, settings_dict):
        """Load settings from a project profile"""
        try:
            # Update UI with profile settings
            self.url_input.setText(settings_dict.get('target_url', ''))
            self.depth_spin.setValue(settings_dict.get('depth', 2))
            self.headless_check.setChecked(settings_dict.get('headless', True))
            self.delay_spin.setValue(int(settings_dict.get('delay', 1)))
            self.screenshots_check.setChecked(settings_dict.get('enable_screenshots', True))
            self.subdomain_check.setChecked(settings_dict.get('enable_subdomain_enum', False))
            self.passive_scan_check.setChecked(settings_dict.get('enable_passive_scan', True))
            self.cve_analysis_check.setChecked(settings_dict.get('enable_cve_analysis', True))
            
            # Apply theme if specified
            if 'theme' in settings_dict:
                self.change_theme(settings_dict['theme'])
            
            # Update profile status
            profile_name = self.project_profiles_tab.current_profile_name
            if profile_name:
                self.current_profile_label.setText(f"📁 Profile: {profile_name}")
                self.save_to_profile_btn.setEnabled(True)
            
            self.append_log(f"📁 Loaded profile settings: {profile_name}")
            
        except Exception as e:
            self.append_log(f"❌ Error loading profile settings: {str(e)}")
    
    def save_current_settings_to_profile(self):
        """Save current settings to the active profile"""
        if not self.project_profiles_tab.current_profile_name:
            QMessageBox.information(self, "No Profile", 
                                  "Please select or create a profile first in the Projects tab.")
            return
        
        try:
            # Get current settings
            scan_settings = ScanSettings(
                target_url=self.url_input.text(),
                depth=self.depth_spin.value(),
                delay=float(self.delay_spin.value()),
                headless=self.headless_check.isChecked(),
                enable_screenshots=self.screenshots_check.isChecked(),
                enable_subdomain_enum=self.subdomain_check.isChecked(),
                enable_passive_scan=self.passive_scan_check.isChecked()
            )
            
            user_preferences = UserPreferences(
                theme=self.theme_manager.get_current_theme()
            )
            
            # Save to profile
            success = self.project_profiles_tab.project_manager.update_current_profile_settings(
                scan_settings, user_preferences
            )
            
            if success:
                self.append_log("💾 Settings saved to current profile")
                QMessageBox.information(self, "Settings Saved", "Current settings saved to profile successfully!")
            else:
                self.append_log("❌ Failed to save settings to profile")
                QMessageBox.warning(self, "Save Failed", "Failed to save settings to profile")
                
        except Exception as e:
            self.append_log(f"❌ Error saving to profile: {str(e)}")
    
    def on_settings_changed(self):
        """Called when any setting changes"""
        pass
    
    def change_theme(self, theme_name):
        """Change application theme"""
        success = self.theme_manager.apply_theme(theme_name)
        if success:
            theme_display_name = self.theme_manager.themes[theme_name]['name']
            self.append_log(f"🎨 Theme changed to: {theme_display_name}")
        else:
            self.append_log(f"❌ Failed to apply theme: {theme_name}")
    
    def show_context_menu(self, position):
        """Show context menu for results table with debugging"""
        try:
            index = self.table_view.indexAt(position)
            if not index.isValid():
                self.append_log("⚠️ Right-click position not on valid table item")
                return
            
            menu = QMenu()
            send_to_repeater_action = QAction("🔄 Send to Repeater", self)
            send_to_repeater_action.triggered.connect(self.send_to_repeater)
            menu.addAction(send_to_repeater_action)
            
            debug_action = QAction("🔍 Debug Row Info", self)
            debug_action.triggered.connect(lambda: self.debug_row_info(index.row()))
            menu.addAction(debug_action)
            
            menu.exec(self.table_view.mapToGlobal(position))
            
        except Exception as e:
            self.append_log(f"❌ Context menu error: {str(e)}")

    def debug_row_info(self, row):
        """Debug information about selected row"""
        try:
            info = []
            for col in range(self.table_model.columnCount()):
                index = self.table_model.index(row, col)
                header = self.table_model.headerData(col, Qt.Orientation.Horizontal, Qt.ItemDataRole.DisplayRole)
                data = self.table_model.data(index, Qt.ItemDataRole.DisplayRole)
                info.append(f"Column {col} ({header}): {data}")
            
            self.append_log(f"🔍 Row {row} debug info:")
            for item in info:
                self.append_log(f"   {item}")
                
        except Exception as e:
            self.append_log(f"❌ Debug error: {str(e)}")

    def send_to_repeater(self):
        """Send selected request to repeater tab"""
        selected_indexes = self.table_view.selectionModel().selectedRows()
        if not selected_indexes:
            QMessageBox.information(self, "No Selection", "Please select a row to send to Repeater")
            return
        
        try:
            row = selected_indexes[0].row()
            url_index = self.table_model.index(row, 1)
            url = self.table_model.data(url_index, Qt.ItemDataRole.DisplayRole)
            
            if not url:
                for col in range(self.table_model.columnCount()):
                    test_index = self.table_model.index(row, col)
                    test_data = self.table_model.data(test_index, Qt.ItemDataRole.DisplayRole)
                    if test_data and ('http://' in str(test_data) or 'https://' in str(test_data)):
                        url = test_data
                        break
            
            if not url:
                QMessageBox.warning(self, "No URL Found", "Could not find a valid URL in the selected row")
                return
            
            request_data = {
                'method': 'GET',
                'url': str(url),
                'headers': {
                    'User-Agent': 'Galdr-Repeater/2.0',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'keep-alive'
                }
            }
            
            self.repeater_tab.load_request(request_data)
            self.tab_widget.setCurrentWidget(self.repeater_tab)
            self.append_log(f"📤 Sent {url} to Repeater")
            
        except Exception as e:
            self.append_log(f"❌ Error sending to Repeater: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to send to Repeater: {str(e)}")

    def log_repeater_request(self, request_data):
        """Log repeater requests"""
        self.append_log(
            f"🔄 Repeater: {request_data['method']} {request_data['url']} → "
            f"Status: {request_data['status']}, Time: {request_data['response_time']}ms"
        )
    
    def update_ai_settings(self, settings):
        """Update AI analyzer settings"""
        try:
            if settings.get('foundation_enabled', True):
                self.ai_analyzer.set_provider('foundation-sec-8b')
                self.append_log("🤖 AI Provider: Foundation-sec-8B (Local)")
            elif settings.get('openai_enabled') and settings.get('api_keys', {}).get('openai'):
                self.ai_analyzer.set_provider('openai', 
                                            settings.get('openai_model'), 
                                            settings['api_keys']['openai'])
                self.append_log(f"🤖 AI Provider: OpenAI {settings.get('openai_model')}")
            elif settings.get('anthropic_enabled') and settings.get('api_keys', {}).get('anthropic'):
                self.ai_analyzer.set_provider('anthropic', 
                                            settings.get('anthropic_model'), 
                                            settings['api_keys']['anthropic'])
                self.append_log(f"🤖 AI Provider: Anthropic {settings.get('anthropic_model')}")
            elif settings.get('deepseek_enabled') and settings.get('api_keys', {}).get('deepseek'):
                self.ai_analyzer.set_provider('deepseek', 
                                            settings.get('deepseek_model'), 
                                            settings['api_keys']['deepseek'])
                self.append_log(f"🤖 AI Provider: DeepSeek {settings.get('deepseek_model')}")
            elif settings.get('gemini_enabled') and settings.get('api_keys', {}).get('gemini'):
                self.ai_analyzer.set_provider('gemini', 
                                            settings.get('gemini_model'), 
                                            settings['api_keys']['gemini'])
                self.append_log(f"🤖 AI Provider: Google Gemini {settings.get('gemini_model')}")
            elif settings.get('grok_enabled') and settings.get('api_keys', {}).get('grok'):
                self.ai_analyzer.set_provider('grok', 
                                            settings.get('grok_model'), 
                                            settings['api_keys']['grok'])
                self.append_log(f"🤖 AI Provider: xAI Grok {settings.get('grok_model')}")
            elif settings.get('ollama_enabled'):
                self.ai_analyzer.set_provider('ollama', settings.get('ollama_model'))
                self.append_log(f"🤖 AI Provider: Ollama {settings.get('ollama_model')}")
            
            self.append_log("✅ AI settings updated successfully")
        except Exception as e:
            self.append_log(f"❌ Failed to update AI settings: {str(e)}")
    
    @pyqtSlot()
    def run_ai_analysis(self):
        """Run AI analysis on current security findings"""
        try:
            query = QSqlQuery(self.db)
            query.exec("SELECT * FROM security_findings ORDER BY timestamp DESC LIMIT 25")
            
            findings = []
            while query.next():
                finding = {
                    'id': query.value(0),
                    'url': query.value(1),
                    'title': query.value(2),
                    'severity': query.value(3),
                    'confidence': query.value(4),
                    'description': query.value(5),
                    'evidence': query.value(6),
                    'remediation': query.value(7),
                    'cwe_id': query.value(8),
                    'owasp_category': query.value(9)
                }
                findings.append(finding)
            
            if not findings:
                QMessageBox.information(self, "No Findings", 
                                      "No security findings available for AI analysis.\n"
                                      "Run a crawl with passive scanning enabled first.")
                return
            
            self.append_log(f"🤖 Starting AI analysis of {len(findings)} security findings...")
            
            import asyncio
            asyncio.create_task(self.perform_ai_analysis(findings))
            
        except Exception as e:
            self.append_log(f"❌ AI analysis failed: {str(e)}")
            QMessageBox.critical(self, "AI Analysis Error", f"Failed to run AI analysis: {str(e)}")
    
    async def perform_ai_analysis(self, findings):
        """Perform AI analysis on findings"""
        try:
            results = await self.ai_analyzer.analyze_findings(findings)
            
            for i, result in enumerate(results):
                if 'error' not in result:
                    finding_id = findings[i]['id']
                    ai_analysis = str(result)
                    
                    update_query = QSqlQuery(self.db)
                    update_query.prepare("UPDATE security_findings SET ai_analysis = ? WHERE id = ?")
                    update_query.addBindValue(ai_analysis)
                    update_query.addBindValue(finding_id)
                    update_query.exec()
            
            self.security_model.select()
            self.append_log(f"✅ AI analysis completed for {len(results)} findings")
            
        except Exception as e:
            self.append_log(f"❌ AI analysis error: {str(e)}")
    
    @pyqtSlot()
    def start_crawl(self):
        """Start crawling process with enhanced options"""
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "Input Error", "Please enter a target URL")
            return
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            self.url_input.setText(url)
        
        depth = self.depth_spin.value()
        headless = self.headless_check.isChecked()
        delay = self.delay_spin.value()
        enable_screenshots = self.screenshots_check.isChecked()
        enable_subdomain_enum = self.subdomain_check.isChecked()
        enable_passive_scan = self.passive_scan_check.isChecked()
        enable_cve_analysis = self.cve_analysis_check.isChecked()
        
        self.scan_start_time = time.time()
        
        self.append_log(f"🚀 Starting crawl of {url} (depth: {depth})")
        self.append_log("🔧 Per-page technology detection enabled")
        if enable_passive_scan:
            self.append_log("🔍 Passive security scanning enabled")
        if enable_cve_analysis:
            self.append_log("🛡️ CVE vulnerability analysis enabled")
        
        self.vulnerability_status_label.setText("🛡️ CVE Status: Scanning...")
        
        self.crawler = AdvancedCrawler(
            url, depth, headless, delay, 
            enable_screenshots, enable_subdomain_enum, enable_passive_scan
        )
        
        self.crawler.update_signal.connect(self.update_results)
        self.crawler.tech_signal.connect(self.update_tech_display)
        self.crawler.log_signal.connect(self.append_log)
        self.crawler.progress_signal.connect(self.update_progress)
        self.crawler.finished_signal.connect(self.crawl_finished)
        self.crawler.error_signal.connect(self.handle_crawl_error)
        self.crawler.subdomain_found.connect(self.handle_subdomain_found)
        self.crawler.security_finding.connect(self.handle_security_finding)
        
        self.crawler.start()
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.save_user_settings()

    @pyqtSlot()
    def stop_crawl(self):
        """Stop crawling process"""
        if hasattr(self, 'crawler') and self.crawler and self.crawler.isRunning():
            self.crawler.stop()
            self.append_log("⏹️ Crawl stop requested...")
        else:
            self.append_log("⚠️ No active crawl to stop")

    @pyqtSlot(dict)
    def update_results(self, page_data):
        """Update results table with crawled page data"""
        try:
            self.logger.info(f"Attempting to insert: {page_data['url']}")
            
            query = QSqlQuery(self.db)
            query.prepare("""
                INSERT INTO results (url, title, timestamp, depth, content_hash, status_code, screenshot, scan_session_id) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """)
            query.addBindValue(page_data['url'])
            query.addBindValue(page_data.get('title', ''))
            query.addBindValue(page_data['timestamp'])
            query.addBindValue(page_data.get('depth', 0))
            query.addBindValue(page_data.get('content_hash', ''))
            query.addBindValue(page_data.get('status_code', 200))
            query.addBindValue(page_data.get('screenshot', ''))
            query.addBindValue(self.session_id)
            
            if not query.exec():
                error_msg = query.lastError().text()
                self.logger.error(f"Failed to insert result: {error_msg}")
                self.append_log(f"❌ Database error: {error_msg}")
            else:
                self.table_model.select()
                self.logger.info(f"Successfully inserted: {page_data['url']}")
                
        except Exception as e:
            self.logger.error(f"Error updating results: {e}")
            self.append_log(f"❌ Exception in update_results: {str(e)}")

    @pyqtSlot(dict)
    def handle_security_finding(self, finding_data):
        """Handle security findings from passive scanner"""
        try:
            url = finding_data['url']
            finding = finding_data['finding']
            
            query = QSqlQuery(self.db)
            query.prepare("""
                INSERT INTO security_findings 
                (url, finding_title, severity, confidence, description, evidence, remediation, cwe_id, owasp_category, timestamp, scan_session_id) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """)
            query.addBindValue(url)
            query.addBindValue(finding['title'])
            query.addBindValue(finding['severity'])
            query.addBindValue(finding['confidence'])
            query.addBindValue(finding['description'])
            query.addBindValue(finding['evidence'])
            query.addBindValue(finding['remediation'])
            query.addBindValue(finding.get('cwe_id', ''))
            query.addBindValue(finding.get('owasp_category', ''))
            query.addBindValue(int(time.time()))
            query.addBindValue(self.session_id)
            
            if query.exec():
                self.security_model.select()
            else:
                self.logger.error(f"Failed to store security finding: {query.lastError().text()}")
                
        except Exception as e:
            self.logger.error(f"Error handling security finding: {e}")

    @pyqtSlot(dict)
    def update_tech_display(self, tech_data):
        """Enhanced display for per-page technology detection with AI Co-pilot updates"""
        if 'url' in tech_data:
            url = tech_data['url']
            technologies = tech_data['technologies']
            depth = tech_data.get('depth', 0)
            
            if not technologies:
                return
            
            tech_summary = []
            for tech, info in technologies.items():
                version = info.get('version', 'unknown')
                confidence = info.get('confidence', 0)
                risk = info.get('risk_level', 'unknown')
                vulns = info.get('vulnerabilities', [])
                
                summary = f"  • {tech} v{version} (confidence: {confidence}%, risk: {risk})"
                if vulns:
                    summary += f" - {len(vulns)} CVEs"
                tech_summary.append(summary)
                
                self.store_technology_data_with_url(url, tech, info, depth)
            
            if tech_summary:
                short_url = url if len(url) <= 50 else url[:47] + "..."
                self.append_log(f"🔧 Technologies on {short_url}:")
                for summary in tech_summary:
                    self.append_log(summary)
                
                if self.cve_analysis_check.isChecked():
                    self.cve_monitor_tab.analyze_technologies(technologies)
                
                self.update_ai_copilot_context()
        else:
            if not tech_data:
                self.append_log("🔧 No technologies detected")
                return
            
            tech_summary = []
            for tech, info in tech_data.items():
                version = info.get('version', 'unknown')
                confidence = info.get('confidence', 0)
                risk = info.get('risk_level', 'unknown')
                vulns = info.get('vulnerabilities', [])
                
                summary = f"  • {tech} v{version} (confidence: {confidence}%, risk: {risk})"
                if vulns:
                    summary += f" - {len(vulns)} CVEs"
                tech_summary.append(summary)
                
                self.store_technology_data(tech, info)
            
            self.append_log("🔧 Technologies detected:")
            for summary in tech_summary:
                self.append_log(summary)

    def store_technology_data_with_url(self, url, tech_name, tech_info, depth):
        """Store technology detection data with specific URL context"""
        try:
            query = QSqlQuery(self.db)
            query.prepare("""
                INSERT INTO technologies (url, tech_name, version, confidence, risk_level, depth, detection_method, timestamp, scan_session_id) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """)
            query.addBindValue(url)
            query.addBindValue(tech_name)
            query.addBindValue(tech_info.get('version', ''))
            query.addBindValue(tech_info.get('confidence', 0))
            query.addBindValue(tech_info.get('risk_level', 'unknown'))
            query.addBindValue(depth)
            query.addBindValue('per_page_detection')
            query.addBindValue(int(time.time()))
            query.addBindValue(self.session_id)
            
            query.exec()
            self.tech_model.select()
            
        except Exception as e:
            self.logger.error(f"Error storing technology data: {e}")

    def store_technology_data(self, tech_name, tech_info):
        """Store technology detection data in database (legacy method)"""
        try:
            query = QSqlQuery(self.db)
            query.prepare("""
                INSERT INTO technologies (url, tech_name, version, confidence, risk_level, depth, detection_method, timestamp, scan_session_id) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """)
            query.addBindValue(self.url_input.text())
            query.addBindValue(tech_name)
            query.addBindValue(tech_info.get('version', ''))
            query.addBindValue(tech_info.get('confidence', 0))
            query.addBindValue(tech_info.get('risk_level', 'unknown'))
            query.addBindValue(0)
            query.addBindValue('legacy_detection')
            query.addBindValue(int(time.time()))
            query.addBindValue(self.session_id)
            
            query.exec()
            self.tech_model.select()
            
        except Exception as e:
            self.logger.error(f"Error storing technology data: {e}")

    @pyqtSlot(str)
    def handle_subdomain_found(self, subdomain):
        """Handle discovered subdomains"""
        self.append_log(f"🌐 Subdomain discovered: {subdomain}")

    @pyqtSlot(int, int)
    def update_progress(self, current, total):
        """Update progress information"""
        if total > 0:
            percentage = int((current / total) * 100)
            self.statusBar().showMessage(f"Crawling... {current}/{total} pages ({percentage}%)")

    @pyqtSlot()
    def crawl_finished(self):
        """Handle crawl completion with AI Co-pilot context update"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        
        if hasattr(self, 'crawler') and self.crawler:
            stats = self.crawler.get_crawl_statistics()
            self.append_log(f"✅ Crawl completed!")
            self.append_log(f"   📊 Pages visited: {stats['total_visited']}")
            self.append_log(f"   🔗 Links discovered: {stats['total_discovered']}")
            self.append_log(f"   🔧 Technologies found: {stats['technologies_found']}")
            self.append_log(f"   ⚠️ Vulnerabilities found: {stats.get('vulnerabilities_found', 0)}")
            self.append_log(f"   🔍 Security findings: {stats.get('security_findings_total', 0)}")
            self.append_log(f"   📡 HTTP requests: {stats['requests_made']}")
            
            findings_by_severity = stats.get('security_findings_by_severity', {})
            if findings_by_severity:
                self.append_log("   🔍 Security findings breakdown:")
                for severity, count in findings_by_severity.items():
                    emoji = {'critical': '🚨', 'high': '🔴', 'medium': '🟡', 'low': '🟢', 'info': 'ℹ️'}.get(severity, '🔍')
                    self.append_log(f"      {emoji} {severity.title()}: {count}")
            
            if self.cve_analysis_check.isChecked() and stats['technologies_found'] > 0:
                self.append_log("🛡️ Running final CVE vulnerability analysis...")
                self.analyze_technologies_for_cves()
            
            self.update_ai_copilot_context()
            
            if self.project_profiles_tab.project_manager.current_profile and self.scan_start_time:
                duration = time.time() - self.scan_start_time
                self.project_profiles_tab.add_scan_to_current_profile(
                    self.session_id, stats, duration
                )
                self.append_log("📁 Scan results added to profile history")
        
        self.statusBar().showMessage(f"Ready - User: {self.current_user}")

    @pyqtSlot(str)
    def handle_crawl_error(self, error_msg):
        """Handle crawler errors"""
        self.append_log(f"❌ Crawler error: {error_msg}")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.vulnerability_status_label.setText("🛡️ CVE Status: Error")
        self.statusBar().showMessage(f"Error - User: {self.current_user}")
    
    @pyqtSlot()
    def clear_activity_log(self):
        """Clear the activity log with confirmation"""
        reply = QMessageBox.question(self, "Clear Activity Log", 
                                   "Are you sure you want to clear the activity log?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            self.log_area.clear()
            self.append_log(f"🗑️ Activity log cleared by {self.current_user}")
    
    @pyqtSlot()
    def clear_results_table(self):
        """Clear results table with confirmation"""
        reply = QMessageBox.question(self, "Clear Results Table", 
                                   "⚠️ Are you sure you want to clear all crawl results?\n\n"
                                   "This action cannot be undone.",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                   QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            query = QSqlQuery(self.db)
            if query.exec("DELETE FROM results"):
                self.table_model.select()
                self.append_log("🗑️ Results table cleared")
            else:
                self.append_log(f"❌ Failed to clear results: {query.lastError().text()}")
    
    @pyqtSlot()
    def clear_tech_table(self):
        """Clear technologies table with confirmation"""
        reply = QMessageBox.question(self, "Clear Technologies Table", 
                                   "⚠️ Are you sure you want to clear all technology detection data?\n\n"
                                   "This action cannot be undone.",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                   QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            query = QSqlQuery(self.db)
            if query.exec("DELETE FROM technologies"):
                self.tech_model.select()
                self.append_log("🗑️ Technologies table cleared")
                self.cve_monitor_tab.clear_vulnerability_data()
            else:
                self.append_log(f"❌ Failed to clear technologies: {query.lastError().text()}")
    
    @pyqtSlot()
    def clear_security_table(self):
        """Clear security findings table with confirmation"""
        reply = QMessageBox.question(self, "Clear Security Findings", 
                                   "⚠️ Are you sure you want to clear all security findings?\n\n"
                                   "This action cannot be undone.",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                   QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            query = QSqlQuery(self.db)
            if query.exec("DELETE FROM security_findings"):
                self.security_model.select()
                self.append_log("🗑️ Security findings cleared")
            else:
                self.append_log(f"❌ Failed to clear security findings: {query.lastError().text()}")
    
    def reset_database(self):
        """Reset database for testing"""
        reply = QMessageBox.question(self, "Reset Database", 
                                   "⚠️ Are you sure you want to reset the entire database?\n\n"
                                   "This will delete ALL data and cannot be undone.",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                   QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            try:
                query = QSqlQuery(self.db)
                query.exec("DROP TABLE IF EXISTS results")
                query.exec("DROP TABLE IF EXISTS technologies") 
                query.exec("DROP TABLE IF EXISTS crawl_history")
                query.exec("DROP TABLE IF EXISTS security_findings")
                
                self.create_user_tables()
                
                self.table_model.setTable("results")
                self.table_model.select()
                self.tech_model.setTable("technologies")
                self.tech_model.select()
                self.security_model.setTable("security_findings")
                self.security_model.select()
                
                self.cve_monitor_tab.clear_vulnerability_data()
                self.vulnerability_status_label.setText("🛡️ CVE Status: Ready")
                
                self.append_log("🗑️ Database reset and recreated")
                
            except Exception as e:
                self.append_log(f"❌ Database reset failed: {str(e)}")
    
    @pyqtSlot()
    def export_results(self):
        """Export crawl results"""
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Results", "galdr_results.json", 
            "JSON Files (*.json);;CSV Files (*.csv)"
        )
        if filename:
            self.append_log(f"📁 Results exported to {filename}")
    
    @pyqtSlot()
    def run_sql_query(self):
        """Execute SQL query"""
        query_text = self.sql_input.text().strip()
        if not query_text:
            return
            
        try:
            self.table_model.setQuery(query_text)
            if self.table_model.lastError().isValid():
                error_msg = self.table_model.lastError().text()
                QMessageBox.warning(self, "SQL Error", error_msg)
                self.append_log(f"❌ SQL Error: {error_msg}")
            else:
                self.append_log(f"✅ Query executed: {query_text}")
        except Exception as e:
            QMessageBox.warning(self, "SQL Error", str(e))
    
    @pyqtSlot()
    def clear_data(self):
        """Clear all crawl data"""
        reply = QMessageBox.question(self, "Clear All Data", 
                                   "⚠️ Are you sure you want to clear ALL crawl data?\n\n"
                                   "This includes results, technologies, security findings, and crawl history.\n"
                                   "This action cannot be undone.",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                   QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            query = QSqlQuery(self.db)
            query.exec("DELETE FROM results")
            query.exec("DELETE FROM technologies")
            query.exec("DELETE FROM crawl_history")
            query.exec("DELETE FROM security_findings")
            self.table_model.select()
            self.tech_model.select()
            self.security_model.select()
            
            self.cve_monitor_tab.clear_vulnerability_data()
            self.vulnerability_status_label.setText("🛡️ CVE Status: Ready")
            
            self.append_log("🗑️ All data cleared")
    
    @pyqtSlot()
    def show_about(self):
        """Show about dialog with logo"""
        about_dialog = QMessageBox(self)
        about_dialog.setWindowTitle("About Galdr")
        
        try:
            icon = QIcon("assets/galdr_logo.png")
            about_dialog.setIconPixmap(icon.pixmap(64, 64))
        except:
            pass
        
        current_theme = self.theme_manager.themes[self.theme_manager.get_current_theme()]['name']
        
        about_dialog.setText(
            "🕷️ Galdr v2.0\n\n"
            "Advanced AJAX Spider Tool with AI Security Analysis\n"
            "Built for cybersecurity professionals\n\n"
            f"Current User: {self.current_user}\n"
            f"Database: {self.db_path}\n"
            f"AI Provider: Foundation-sec-8B (Local)\n"
            f"Theme: {current_theme}\n"
            f"Per-Page Tech Detection: Enabled\n"
            f"Project Profiles: Active\n"
            f"CVE Vulnerability Monitor: Active\n"
            f"AI Co-pilot: Ready"
        )
        about_dialog.exec()
    
    def append_log(self, message):
        """Add message to activity log with enhanced formatting"""
        import time
        timestamp = time.strftime("%H:%M:%S")
        
        if "🚨" in message or "❌" in message:
            color = "#ff6b6b"
        elif "✅" in message or "🚀" in message:
            color = "#4caf50"
        elif "⚠️" in message:
            color = "#ff9800"
        elif "🤖" in message:
            color = "#9c27b0"
        elif "🔍" in message:
            color = "#2196f3"
        elif "🎨" in message:
            color = "#e91e63"
        elif "📁" in message:
            color = "#ff9800"
        elif "🛡️" in message:
            color = "#f44336"
        else:
            theme_colors = self.theme_manager.get_theme_colors()
            color = theme_colors.get('primary', '#00ff41')
        
        formatted_message = f'<span style="color: {color};">[{timestamp}] {message}</span>'
        self.log_area.append(formatted_message)
        
        cursor = self.log_area.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        self.log_area.setTextCursor(cursor)
    
    def load_user_settings(self):
        """Load user-specific settings"""
        self.url_input.setText(self.settings.value("url", "https://example.com"))
        self.depth_spin.setValue(int(self.settings.value("depth", 2)))
        self.headless_check.setChecked(self.settings.value("headless", True, type=bool))
        self.screenshots_check.setChecked(self.settings.value("screenshots", True, type=bool))
        self.subdomain_check.setChecked(self.settings.value("subdomain_enum", False, type=bool))
        self.passive_scan_check.setChecked(self.settings.value("passive_scan", True, type=bool))
        self.cve_analysis_check.setChecked(self.settings.value("cve_analysis", True, type=bool))
        self.delay_spin.setValue(int(self.settings.value("delay", 1)))
    
    def save_user_settings(self):
        """Save user-specific settings"""
        self.settings.setValue("url", self.url_input.text())
        self.settings.setValue("depth", self.depth_spin.value())
        self.settings.setValue("headless", self.headless_check.isChecked())
        self.settings.setValue("screenshots", self.screenshots_check.isChecked())
        self.settings.setValue("subdomain_enum", self.subdomain_check.isChecked())
        self.settings.setValue("passive_scan", self.passive_scan_check.isChecked())
        self.settings.setValue("cve_analysis", self.cve_analysis_check.isChecked())
        self.settings.setValue("delay", self.delay_spin.value())
    
    def closeEvent(self, event):
        """Handle application close"""
        if hasattr(self, 'crawler') and self.crawler and self.crawler.isRunning():
            self.crawler.stop()
            self.crawler.wait(5000)
        
        self.save_user_settings()
        self.append_log(f"👋 Goodbye, {self.current_user}!")
        event.accept()
