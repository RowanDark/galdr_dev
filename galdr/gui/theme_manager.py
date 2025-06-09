from PyQt6.QtCore import QObject, pyqtSignal, QSettings
from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QPalette, QColor

class ThemeManager(QObject):
    theme_changed = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.settings = QSettings("Galdr", "ThemeSettings")
        self.current_theme = self.settings.value("theme", "dark")
        self.themes = self.setup_themes()
    
    def setup_themes(self):
        return {
            "dark": {
                "name": "Dark Professional",
                "background": "#1e1e1e",
                "surface": "#2d2d2d", 
                "surface_variant": "#3c3c3c",
                "primary": "#c53030",  # Galdr logo red
                "primary_variant": "#a02626",
                "secondary": "#ff6b6b",
                "text": "#ffffff",
                "text_secondary": "#b0b0b0",
                "border": "#555555",
                "success": "#4caf50",
                "warning": "#ff9800",
                "error": "#f44336"
            },
            "light": {
                "name": "Light Professional", 
                "background": "#ffffff",
                "surface": "#f5f5f5",
                "surface_variant": "#e0e0e0", 
                "primary": "#c53030",  # Galdr logo red
                "primary_variant": "#a02626",
                "secondary": "#ff6b6b",
                "text": "#333333",
                "text_secondary": "#666666",
                "border": "#cccccc",
                "success": "#2e7d32",
                "warning": "#f57c00", 
                "error": "#c62828"
            },
            "galdr_red": {
                "name": "Galdr Red Theme",
                "background": "#1a0a0a",
                "surface": "#2a1515",
                "surface_variant": "#3a2020",
                "primary": "#c53030",
                "primary_variant": "#a02626", 
                "secondary": "#ff4444",
                "text": "#ffffff",
                "text_secondary": "#ffcccc",
                "border": "#664444",
                "success": "#4caf50",
                "warning": "#ff9800",
                "error": "#ff1744"
            },
            "cyberpunk": {
                "name": "Cyberpunk",
                "background": "#0d1117",
                "surface": "#161b22", 
                "surface_variant": "#21262d",
                "primary": "#00d4aa",
                "primary_variant": "#00b899",
                "secondary": "#79c0ff",
                "text": "#f0f6fc",
                "text_secondary": "#8b949e",
                "border": "#30363d",
                "success": "#3fb950",
                "warning": "#d29922",
                "error": "#f85149"
            }
        }
    
    def apply_theme(self, theme_name):
        """Apply theme to application"""
        if theme_name not in self.themes:
            return False
        
        theme = self.themes[theme_name]
        self.current_theme = theme_name
        
        # Save theme preference
        self.settings.setValue("theme", theme_name)
        
        # Generate stylesheet
        stylesheet = self.generate_stylesheet(theme)
        
        # Apply to application
        QApplication.instance().setStyleSheet(stylesheet)
        
        # Emit signal
        self.theme_changed.emit(theme_name)
        
        return True
    
    def generate_stylesheet(self, theme):
        """Generate complete application stylesheet"""
        return f"""
        /* Main Application Styling */
        QMainWindow {{
            background-color: {theme['background']};
            color: {theme['text']};
        }}
        
        QWidget {{
            background-color: {theme['background']};
            color: {theme['text']};
            selection-background-color: {theme['primary']};
            selection-color: {theme['background']};
        }}
        
        /* Tab Widget */
        QTabWidget::pane {{
            border: 1px solid {theme['border']};
            background-color: {theme['surface']};
            border-radius: 8px;
        }}
        
        QTabBar::tab {{
            background-color: {theme['surface_variant']};
            color: {theme['text_secondary']};
            padding: 12px 20px;
            margin-right: 2px;
            border-radius: 6px 6px 0px 0px;
            border: 1px solid {theme['border']};
            min-width: 80px;
        }}
        
        QTabBar::tab:selected {{
            background-color: {theme['primary']};
            color: {theme['background']};
            font-weight: bold;
        }}
        
        QTabBar::tab:hover:!selected {{
            background-color: {theme['primary_variant']};
            color: {theme['text']};
        }}
        
        /* Buttons */
        QPushButton {{
            background-color: {theme['primary']};
            color: {theme['background']};
            border: none;
            padding: 10px 20px;
            border-radius: 8px;
            font-weight: bold;
            font-size: 13px;
            min-height: 20px;
        }}
        
        QPushButton:hover {{
            background-color: {theme['primary_variant']};
        }}
        
        QPushButton:pressed {{
            background-color: {theme['primary_variant']};
            transform: translateY(1px);
        }}
        
        QPushButton:disabled {{
            background-color: {theme['text_secondary']};
            color: {theme['text_secondary']};
        }}
        
        /* Input Fields */
        QLineEdit, QTextEdit, QSpinBox {{
            background-color: {theme['surface']};
            color: {theme['text']};
            border: 2px solid {theme['border']};
            border-radius: 6px;
            padding: 8px 12px;
            font-size: 13px;
        }}
        
        QLineEdit:focus, QTextEdit:focus, QSpinBox:focus {{
            border-color: {theme['primary']};
            background-color: {theme['surface_variant']};
        }}
        
        /* Tables */
        QTableView {{
            background-color: {theme['surface']};
            alternate-background-color: {theme['surface_variant']};
            color: {theme['text']};
            border: 1px solid {theme['border']};
            border-radius: 6px;
            gridline-color: {theme['border']};
        }}
        
        QTableView::item {{
            padding: 8px;
            border-bottom: 1px solid {theme['border']};
        }}
        
        QTableView::item:selected {{
            background-color: {theme['primary']};
            color: {theme['background']};
        }}
        
        QHeaderView::section {{
            background-color: {theme['surface_variant']};
            color: {theme['text']};
            padding: 10px;
            border: none;
            border-right: 1px solid {theme['border']};
            font-weight: bold;
        }}
        
        /* Menu Bar */
        QMenuBar {{
            background-color: {theme['surface']};
            color: {theme['text']};
            border-bottom: 1px solid {theme['border']};
        }}
        
        QMenuBar::item {{
            padding: 8px 16px;
            background-color: transparent;
        }}
        
        QMenuBar::item:selected {{
            background-color: {theme['primary']};
            color: {theme['background']};
        }}
        
        QMenu {{
            background-color: {theme['surface']};
            color: {theme['text']};
            border: 1px solid {theme['border']};
            border-radius: 6px;
        }}
        
        QMenu::item {{
            padding: 8px 20px;
        }}
        
        QMenu::item:selected {{
            background-color: {theme['primary']};
            color: {theme['background']};
        }}
        
        /* Checkboxes */
        QCheckBox {{
            color: {theme['text']};
            spacing: 8px;
        }}
        
        QCheckBox::indicator {{
            width: 18px;
            height: 18px;
            border: 2px solid {theme['border']};
            border-radius: 4px;
            background-color: {theme['surface']};
        }}
        
        QCheckBox::indicator:checked {{
            background-color: {theme['primary']};
            border-color: {theme['primary']};
        }}
        
        /* ComboBox */
        QComboBox {{
            background-color: {theme['surface']};
            color: {theme['text']};
            border: 2px solid {theme['border']};
            border-radius: 6px;
            padding: 8px 12px;
            min-width: 100px;
        }}
        
        QComboBox:focus {{
            border-color: {theme['primary']};
        }}
        
        QComboBox::drop-down {{
            border: none;
            width: 20px;
        }}
        
        QComboBox::down-arrow {{
            image: none;
            border-left: 5px solid transparent;
            border-right: 5px solid transparent;
            border-top: 5px solid {theme['text']};
        }}
        
        QComboBox QAbstractItemView {{
            background-color: {theme['surface']};
            color: {theme['text']};
            border: 1px solid {theme['border']};
            border-radius: 6px;
            selection-background-color: {theme['primary']};
        }}
        
        /* Progress Bar */
        QProgressBar {{
            background-color: {theme['surface']};
            border: 1px solid {theme['border']};
            border-radius: 6px;
            text-align: center;
            color: {theme['text']};
        }}
        
        QProgressBar::chunk {{
            background-color: {theme['primary']};
            border-radius: 5px;
        }}
        
        /* Status Bar */
        QStatusBar {{
            background-color: {theme['surface']};
            color: {theme['text']};
            border-top: 1px solid {theme['border']};
        }}
        
        /* Group Box */
        QGroupBox {{
            color: {theme['text']};
            border: 2px solid {theme['border']};
            border-radius: 8px;
            margin-top: 10px;
            font-weight: bold;
        }}
        
        QGroupBox::title {{
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 8px 0 8px;
            background-color: {theme['background']};
        }}
        
        /* Scrollbars */
        QScrollBar:vertical {{
            background-color: {theme['surface']};
            width: 12px;
            border-radius: 6px;
        }}
        
        QScrollBar::handle:vertical {{
            background-color: {theme['primary']};
            border-radius: 6px;
            min-height: 20px;
        }}
        
        QScrollBar::handle:vertical:hover {{
            background-color: {theme['primary_variant']};
        }}
        """
    
    def get_available_themes(self):
        """Get list of available themes"""
        return [(key, theme['name']) for key, theme in self.themes.items()]
    
    def get_current_theme(self):
        """Get current theme name"""
        return self.current_theme
    
    def get_theme_colors(self, theme_name=None):
        """Get theme color palette"""
        theme_name = theme_name or self.current_theme
        return self.themes.get(theme_name, self.themes['dark'])
