from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QGroupBox,
    QProgressBar, QTextEdit, QTabWidget, QMessageBox, QSplitter
)
from PyQt6.QtCore import pyqtSignal, Qt, QTimer
from PyQt6.QtGui import QFont
from core.cve_updater import CVEManager
import time

class CVEMonitorTab(QWidget):
    vulnerability_detected = pyqtSignal(str, dict)  # technology, vulnerability_data
    
    def __init__(self):
        super().__init__()
        self.cve_manager = CVEManager()
        self.init_ui()
        self.connect_signals()
        self.refresh_database_info()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Header
        header = QLabel("🛡️ CVE Vulnerability Monitor")
        header.setStyleSheet("""
            QLabel {
                font-size: 18px;
                font-weight: bold;
                color: #ff6b6b;
                padding: 15px;
                background-color: rgba(255, 107, 107, 0.1);
                border-radius: 8px;
                margin-bottom: 20px;
            }
        """)
        layout.addWidget(header)
        
        # Create splitter for database info and vulnerabilities
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left side - Database info and controls
        left_widget = self.create_database_info_widget()
        splitter.addWidget(left_widget)
        
        # Right side - Vulnerability details
        right_widget = self.create_vulnerability_widget()
        splitter.addWidget(right_widget)
        
        splitter.setSizes([400, 600])
        layout.addWidget(splitter)
    
    def create_database_info_widget(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Database status
        db_group = QGroupBox("📊 CVE Database Status")
        db_layout = QVBoxLayout(db_group)
        
        self.db_stats_label = QLabel("Loading database information...")
        db_layout.addWidget(self.db_stats_label)
        
        self.last_update_label = QLabel("Last Update: Never")
        db_layout.addWidget(self.last_update_label)
        
        layout.addWidget(db_group)
        
        # Update controls
        update_group = QGroupBox("🔄 Database Updates")
        update_layout = QVBoxLayout(update_group)
        
        self.update_btn = QPushButton("🔄 Update CVE Database")
        self.update_btn.clicked.connect(self.start_manual_update)
        update_layout.addWidget(self.update_btn)
        
        self.update_progress = QProgressBar()
        self.update_progress.setVisible(False)
        update_layout.addWidget(self.update_progress)
        
        self.update_status = QLabel("")
        update_layout.addWidget(self.update_status)
        
        layout.addWidget(update_group)
        
        # Auto-update settings
        auto_group = QGroupBox("⚙️ Auto-Update Settings")
        auto_layout = QVBoxLayout(auto_group)
        
        auto_info = QLabel("Automatic updates run daily to keep vulnerability data current.")
        auto_info.setWordWrap(True)
        auto_layout.addWidget(auto_info)
        
        layout.addWidget(auto_group)
        
        layout.addStretch()
        
        return widget
    
    def create_vulnerability_widget(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Vulnerability summary
        summary_group = QGroupBox("⚠️ Vulnerability Summary")
        summary_layout = QVBoxLayout(summary_group)
        
        self.vulnerability_summary = QLabel("No vulnerabilities analyzed yet")
        self.vulnerability_summary.setWordWrap(True)
        summary_layout.addWidget(self.vulnerability_summary)
        
        layout.addWidget(summary_group)
        
        # Vulnerability table
        table_group = QGroupBox("🔍 Detected Vulnerabilities")
        table_layout = QVBoxLayout(table_group)
        
        self.vulnerability_table = QTableWidget()
        self.vulnerability_table.setColumnCount(6)
        self.vulnerability_table.setHorizontalHeaderLabels([
            "Technology", "CVE ID", "CVSS", "Severity", "Exploitable", "Description"
        ])
        
        header = self.vulnerability_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        
        table_layout.addWidget(self.vulnerability_table)
        layout.addWidget(table_group)
        
        return widget
    
    def connect_signals(self):
        self.cve_manager.cve_data_updated.connect(self.on_database_updated)
        self.cve_manager.vulnerability_alert.connect(self.on_vulnerability_alert)
    
    def start_manual_update(self):
        """Start manual CVE database update"""
        success = self.cve_manager.start_manual_update()
        if success:
            self.update_btn.setEnabled(False)
            self.update_progress.setVisible(True)
            self.update_progress.setValue(0)
            self.update_status.setText("Starting CVE database update...")
        else:
            QMessageBox.information(self, "Update In Progress", 
                                  "CVE database update is already in progress.")
    
    def refresh_database_info(self):
        """Refresh database information display"""
        try:
            info = self.cve_manager.get_database_info()
            
            stats_text = f"""
            📊 Total CVEs: {info['total_cves']:,}
            🔧 Technologies Covered: {info['technologies_covered']:,}
            💥 Exploitable CVEs: {info['exploitable_cves']:,}
            """
            
            self.db_stats_label.setText(stats_text)
            
            if info['last_updated'] > 0:
                last_update = time.strftime("%Y-%m-%d %H:%M", 
                                          time.localtime(info['last_updated']))
                self.last_update_label.setText(f"Last Update: {last_update}")
            else:
                self.last_update_label.setText("Last Update: Never")
                
        except Exception as e:
            self.db_stats_label.setText(f"Error loading database info: {str(e)}")
    
    def on_database_updated(self, stats):
        """Handle database update completion"""
        self.update_btn.setEnabled(True)
        self.update_progress.setVisible(False)
        
        message = f"✅ CVE database updated successfully!\n"
        message += f"📊 Total CVEs: {stats['total_cves']:,}\n"
        message += f"🆕 Newly Updated: {stats['newly_updated']:,}"
        
        self.update_status.setText(message)
        self.refresh_database_info()
        
        # Auto-clear status after 10 seconds
        QTimer.singleShot(10000, lambda: self.update_status.setText(""))
    
    def on_vulnerability_alert(self, technology, critical_cves):
        """Handle critical vulnerability alert"""
        alert_msg = f"🚨 CRITICAL VULNERABILITIES DETECTED!\n\n"
        alert_msg += f"Technology: {technology}\n"
        alert_msg += f"Critical CVEs: {len(critical_cves)}\n\n"
        
        for cve in critical_cves[:3]:  # Show first 3
            alert_msg += f"• {cve.cve_id} (CVSS: {cve.cvss_score})\n"
        
        if len(critical_cves) > 3:
            alert_msg += f"... and {len(critical_cves) - 3} more"
        
        QMessageBox.warning(self, "Critical Vulnerabilities", alert_msg)
    
    def analyze_technologies(self, technologies_dict):
        """Analyze detected technologies for vulnerabilities"""
        try:
            summary = self.cve_manager.get_vulnerability_summary(technologies_dict)
            
            # Update summary display
            summary_text = f"""
            🔍 Vulnerability Analysis Results:
            
            📊 Total Vulnerabilities: {summary['total_vulnerabilities']}
            🚨 Critical: {summary['critical_count']}
            🔴 High: {summary['high_count']}
            🟡 Medium: {summary['medium_count']}
            🟢 Low: {summary['low_count']}
            💥 Exploitable: {summary['exploitable_count']}
            """
            
            self.vulnerability_summary.setText(summary_text)
            
            # Update vulnerability table
            self.populate_vulnerability_table(summary['technology_risks'])
            
        except Exception as e:
            self.vulnerability_summary.setText(f"Error analyzing vulnerabilities: {str(e)}")
    
    def populate_vulnerability_table(self, technology_risks):
        """Populate the vulnerability table with detected issues"""
        # Clear existing data
        self.vulnerability_table.setRowCount(0)
        
        row = 0
        for tech_name, risk_data in technology_risks.items():
            for cve_data in risk_data['cves']:
                self.vulnerability_table.insertRow(row)
                
                # Technology
                self.vulnerability_table.setItem(row, 0, QTableWidgetItem(tech_name))
                
                # CVE ID
                cve_item = QTableWidgetItem(cve_data['cve_id'])
                if cve_data['cvss_score'] >= 9.0:
                    cve_item.setBackground(Qt.GlobalColor.red)
                elif cve_data['cvss_score'] >= 7.0:
                    cve_item.setBackground(Qt.GlobalColor.yellow)
                self.vulnerability_table.setItem(row, 1, cve_item)
                
                # CVSS Score
                cvss_item = QTableWidgetItem(f"{cve_data['cvss_score']:.1f}")
                self.vulnerability_table.setItem(row, 2, cvss_item)
                
                # Severity
                severity_item = QTableWidgetItem(cve_data['severity'])
                self.vulnerability_table.setItem(row, 3, severity_item)
                
                # Exploitable
                exploit_item = QTableWidgetItem("Yes" if cve_data['exploit_available'] else "No")
                if cve_data['exploit_available']:
                    exploit_item.setBackground(Qt.GlobalColor.red)
                self.vulnerability_table.setItem(row, 4, exploit_item)
                
                # Description (truncated)
                desc = cve_data['description'][:100] + "..." if len(cve_data['description']) > 100 else cve_data['description']
                self.vulnerability_table.setItem(row, 5, QTableWidgetItem(desc))
                
                row += 1
    
    def clear_vulnerability_data(self):
        """Clear vulnerability analysis data"""
        self.vulnerability_summary.setText("No vulnerabilities analyzed yet")
        self.vulnerability_table.setRowCount(0)
