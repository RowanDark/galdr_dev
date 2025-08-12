import sys
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout, QLineEdit, 
    QPushButton, QLabel, QTabWidget, QWidget, QMessageBox, QCheckBox
)
from PyQt6.QtCore import Qt, pyqtSlot
from PyQt6.QtGui import QFont, QPixmap, QIcon
from ..auth.user_manager import UserManager
from ..auth.secure_config import SecureUserConfig

class LoginDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔐 Galdr Authentication")
        self.setFixedSize(450, 600)
        
        # Set window icon
        try:
            icon = QIcon("assets/galdr_logo.png")
            self.setWindowIcon(icon)
        except:
            pass
        
        self.user_manager = UserManager()
        self.authenticated_user = None
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Logo and Header
        header_layout = QVBoxLayout()
        
        # Add logo
        try:
            logo_label = QLabel()
            pixmap = QPixmap("assets/galdr_logo.png")
            scaled_pixmap = pixmap.scaled(120, 120, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
            logo_label.setPixmap(scaled_pixmap)
            logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            header_layout.addWidget(logo_label)
        except:
            pass  # Fallback if logo not found
        
        title = QLabel("Galdr")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("""
            QLabel {
                font-size: 28px; 
                font-weight: bold; 
                color: #c53030;
                margin: 10px;
            }
        """)
        header_layout.addWidget(title)
        
        subtitle = QLabel("RowanDark © 2025")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet("color: #666; font-size: 14px; margin-bottom: 20px;")
        header_layout.addWidget(subtitle)
        
        layout.addLayout(header_layout)
        
        # Tabbed interface for login/register
        self.tab_widget = QTabWidget()
        
        # Login tab
        login_tab = self.create_login_tab()
        self.tab_widget.addTab(login_tab, "🔑 Login")
        
        # Register tab
        register_tab = self.create_register_tab()
        self.tab_widget.addTab(register_tab, "📝 Register")
        
        layout.addWidget(self.tab_widget)
    
    def create_login_tab(self):
        """Create login tab with local authentication"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Login form
        form_layout = QFormLayout()
        
        self.login_username = QLineEdit()
        self.login_username.setPlaceholderText("Enter your username")
        self.login_username.setStyleSheet("padding: 8px; border-radius: 4px;")
        form_layout.addRow("👤 Username:", self.login_username)
        
        self.login_password = QLineEdit()
        self.login_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.login_password.setPlaceholderText("Enter your password")
        self.login_password.setStyleSheet("padding: 8px; border-radius: 4px;")
        self.login_password.returnPressed.connect(self.login)
        form_layout.addRow("🔑 Password:", self.login_password)
        
        layout.addLayout(form_layout)
        
        # Remember me checkbox
        self.remember_me = QCheckBox("Remember me")
        layout.addWidget(self.remember_me)
        
        # Login button
        self.login_btn = QPushButton("🚀 Login")
        self.login_btn.clicked.connect(self.login)
        self.login_btn.setStyleSheet("""
            QPushButton {
                background-color: #c53030;
                color: white;
                border: none;
                padding: 12px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #a02626;
            }
        """)
        layout.addWidget(self.login_btn)
        
        return widget
    
    def create_register_tab(self):
        """Create registration tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Registration form
        form_layout = QFormLayout()
        
        self.reg_username = QLineEdit()
        self.reg_username.setPlaceholderText("Choose a username")
        self.reg_username.setStyleSheet("padding: 8px; border-radius: 4px;")
        form_layout.addRow("👤 Username:", self.reg_username)
        
        self.reg_email = QLineEdit()
        self.reg_email.setPlaceholderText("your.email@domain.com")
        self.reg_email.setStyleSheet("padding: 8px; border-radius: 4px;")
        form_layout.addRow("📧 Email:", self.reg_email)
        
        self.reg_password = QLineEdit()
        self.reg_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.reg_password.setPlaceholderText("Create a strong password")
        self.reg_password.setStyleSheet("padding: 8px; border-radius: 4px;")
        form_layout.addRow("🔑 Password:", self.reg_password)
        
        self.reg_confirm = QLineEdit()
        self.reg_confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self.reg_confirm.setPlaceholderText("Confirm your password")
        self.reg_confirm.setStyleSheet("padding: 8px; border-radius: 4px;")
        self.reg_confirm.returnPressed.connect(self.register)
        form_layout.addRow("🔑 Confirm:", self.reg_confirm)
        
        layout.addLayout(form_layout)
        
        # Register button
        self.register_btn = QPushButton("📝 Create Account")
        self.register_btn.clicked.connect(self.register)
        self.register_btn.setStyleSheet("""
            QPushButton {
                background-color: #4caf50;
                color: white;
                border: none;
                padding: 12px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        layout.addWidget(self.register_btn)
        
        return widget
    
    @pyqtSlot()
    def login(self):
        """Handle local login"""
        username = self.login_username.text().strip()
        password = self.login_password.text()
        
        if not username or not password:
            QMessageBox.warning(self, "Login Failed", "Please enter both username and password")
            return
        
        if self.user_manager.authenticate(username, password):
            self.authenticated_user = username
            self.accept()
        else:
            QMessageBox.warning(self, "Authentication Failed", 
                              "Invalid username or password")
            self.login_password.clear()
    
    @pyqtSlot()
    def register(self):
        """Handle user registration"""
        username = self.reg_username.text().strip()
        email = self.reg_email.text().strip()
        password = self.reg_password.text()
        confirm = self.reg_confirm.text()
        
        # Validation
        if not all([username, email, password, confirm]):
            QMessageBox.warning(self, "Registration Failed", "Please fill in all fields")
            return
        
        if password != confirm:
            QMessageBox.warning(self, "Registration Failed", "Passwords do not match")
            return
        
        if len(password) < 8:
            QMessageBox.warning(self, "Registration Failed", 
                              "Password must be at least 8 characters long")
            return
        
        if '@' not in email:
            QMessageBox.warning(self, "Registration Failed", "Please enter a valid email address")
            return
        
        try:
            self.user_manager.create_user(username, password, email)
            QMessageBox.information(self, "Registration Successful", 
                                  f"Account created for {username}!\nYou can now log in.")
            self.tab_widget.setCurrentIndex(0)  # Switch to login tab
            self.login_username.setText(username)
        except ValueError as e:
            QMessageBox.warning(self, "Registration Failed", str(e))
        except Exception as e:
            QMessageBox.critical(self, "Registration Error", f"Failed to create account: {str(e)}")
