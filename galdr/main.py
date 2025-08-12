import sys
import logging
from PyQt6.QtWidgets import QApplication, QMessageBox
from PyQt6.QtCore import Qt
from .gui.login_dialog import LoginDialog
from .gui.main_window import MainWindow

def setup_application_logging():
    """Setup application-wide logging"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('galdr.log'),
            logging.StreamHandler()
        ]
    )

def main():
    # Setup application
    app = QApplication(sys.argv)
    app.setApplicationName("Galdr")
    app.setApplicationVersion("2.0")
    app.setOrganizationName("CyberSec Tools")
    
    # Setup logging
    setup_application_logging()
    logger = logging.getLogger(__name__)
    
    # Apply global dark theme
    app.setStyleSheet("""
        QWidget {
            background-color: #2b2b2b;
            color: #ffffff;
        }
        QDialog {
            background-color: #2b2b2b;
        }
        QLineEdit {
            background-color: #3c3c3c;
            border: 1px solid #555;
            padding: 8px;
            border-radius: 4px;
        }
        QLineEdit:focus {
            border-color: #00d4aa;
        }
        QTabWidget::pane {
            border: 1px solid #555;
            background-color: #2b2b2b;
        }
        QTabBar::tab {
            background-color: #3c3c3c;
            color: #ffffff;
            padding: 8px 16px;
            margin-right: 2px;
        }
        QTabBar::tab:selected {
            background-color: #00d4aa;
            color: #000000;
        }
    """)
    
    try:
        # Show authentication dialog
        login_dialog = LoginDialog()
        
        if login_dialog.exec() == LoginDialog.DialogCode.Accepted:
            authenticated_user = login_dialog.authenticated_user
            logger.info(f"User authenticated: {authenticated_user}")
            
            # Launch main application with user context
            window = MainWindow(authenticated_user)
            window.show()
            
            return app.exec()
        else:
            logger.info("User cancelled authentication")
            return 0
            
    except Exception as e:
        logger.error(f"Application startup failed: {e}")
        QMessageBox.critical(None, "Startup Error", 
                           f"Failed to start Galdr: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
