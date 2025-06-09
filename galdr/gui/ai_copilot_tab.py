import asyncio
import time
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QLineEdit, 
    QPushButton, QLabel, QSplitter, QGroupBox, QComboBox,
    QCheckBox, QScrollArea, QFrame
)
from PyQt6.QtCore import Qt, pyqtSlot, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QTextCursor
from core.ai_integration import AISecurityAnalyzer

class AIResponseThread(QThread):
    response_ready = pyqtSignal(str)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, ai_analyzer, prompt, context=None):
        super().__init__()
        self.ai_analyzer = ai_analyzer
        self.prompt = prompt
        self.context = context or {}
    
    def run(self):
        try:
            # Simulate AI response generation
            # In production, this would call the actual AI API
            response = self.generate_ai_response(self.prompt, self.context)
            self.response_ready.emit(response)
        except Exception as e:
            self.error_occurred.emit(str(e))
    
    def generate_ai_response(self, prompt, context):
        """Generate AI response based on prompt and context"""
        # This is a simulation - in production, use actual AI API
        if "vulnerability" in prompt.lower():
            return """🔍 **Vulnerability Analysis**

Based on your query about vulnerabilities, here's my analysis:

**Key Considerations:**
• Severity assessment is crucial for prioritization
• Check for authentication bypass possibilities
• Look for input validation issues
• Consider privilege escalation vectors

**Recommended Actions:**
1. Verify the vulnerability manually
2. Create a proof-of-concept
3. Document the impact clearly
4. Check for similar issues in the codebase

**Bug Bounty Tips:**
• Focus on business logic flaws for higher payouts
• Chain vulnerabilities for maximum impact
• Always follow responsible disclosure

Would you like me to analyze specific findings from your current scan?"""
        
        elif "technology" in prompt.lower() or "tech" in prompt.lower():
            return """🔧 **Technology Analysis**

I can help you analyze the detected technologies:

**Common Security Issues by Technology:**
• **WordPress**: Plugin vulnerabilities, weak admin credentials
• **Apache**: Version-specific CVEs, misconfigurations
• **React**: XSS via dangerouslySetInnerHTML, client-side routing issues
• **Angular**: Template injection, CSP bypasses

**Reconnaissance Tips:**
1. Check version numbers against CVE databases
2. Look for default configurations
3. Enumerate plugins/modules
4. Test for known exploits

**Next Steps:**
• Run CVE analysis on detected technologies
• Check for outdated versions
• Look for technology-specific attack vectors

What specific technologies did you discover?"""
        
        elif "scan" in prompt.lower() or "crawl" in prompt.lower():
            return """🚀 **Scan Optimization**

Here's how to optimize your reconnaissance:

**Crawl Strategy:**
• Increase depth for complex applications
• Enable subdomain enumeration for broader coverage
• Use screenshots to identify interesting pages
• Monitor for rate limiting

**Security Scanning:**
• Enable passive security scanning
• Run CVE analysis on discovered technologies
• Look for sensitive information disclosure
• Check security headers

**Bug Bounty Focus:**
• Target admin panels and API endpoints
• Look for file upload functionality
• Test authentication mechanisms
• Check for business logic flaws

**Performance Tips:**
• Adjust delay based on target responsiveness
• Use headless mode for faster scanning
• Save profiles for repeat testing

How can I help optimize your current scan?"""
        
        else:
            return f"""🤖 **AI Co-pilot Response**

I'm here to help with your cybersecurity reconnaissance and bug bounty work!

**I can assist with:**
• Vulnerability analysis and prioritization
• Technology stack assessment
• Scan optimization and strategy
• Bug bounty methodology
• Security finding interpretation
• Attack vector identification

**Your query:** "{prompt}"

**Suggestions:**
• Ask about specific vulnerabilities you've found
• Request analysis of detected technologies
• Get advice on scan configuration
• Discuss bug bounty strategies

What would you like to explore further?"""

class AICoPilotTab(QWidget):
    def __init__(self, ai_analyzer):
        super().__init__()
        self.ai_analyzer = ai_analyzer
        self.chat_history = []
        self.current_context = {}
        self.init_ui()
        self.add_welcome_message()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Header
        header = QLabel("🤖 AI Security Co-pilot")
        header.setStyleSheet("""
            QLabel {
                font-size: 18px;
                font-weight: bold;
                color: #9c27b0;
                padding: 15px;
                background-color: rgba(156, 39, 176, 0.1);
                border-radius: 8px;
                margin-bottom: 10px;
            }
        """)
        layout.addWidget(header)
        
        # Create splitter for chat and context
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left side - Chat interface
        chat_widget = self.create_chat_widget()
        splitter.addWidget(chat_widget)
        
        # Right side - Context and quick actions
        context_widget = self.create_context_widget()
        splitter.addWidget(context_widget)
        
        splitter.setSizes([600, 300])
        layout.addWidget(splitter)
    
    def create_chat_widget(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Chat display area
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        self.chat_display.setFont(QFont("Segoe UI", 10))
        self.chat_display.setStyleSheet("""
            QTextEdit {
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        layout.addWidget(self.chat_display)
        
        # Input area
        input_frame = QFrame()
        input_frame.setStyleSheet("""
            QFrame {
                background-color: #ffffff;
                border: 2px solid #9c27b0;
                border-radius: 8px;
                padding: 5px;
            }
        """)
        input_layout = QVBoxLayout(input_frame)
        
        # Quick action buttons
        quick_actions_layout = QHBoxLayout()
        
        self.analyze_vulns_btn = QPushButton("🔍 Analyze Vulnerabilities")
        self.analyze_vulns_btn.clicked.connect(self.quick_analyze_vulnerabilities)
        quick_actions_layout.addWidget(self.analyze_vulns_btn)
        
        self.analyze_tech_btn = QPushButton("🔧 Analyze Technologies")
        self.analyze_tech_btn.clicked.connect(self.quick_analyze_technologies)
        quick_actions_layout.addWidget(self.analyze_tech_btn)
        
        self.scan_tips_btn = QPushButton("🚀 Scan Tips")
        self.scan_tips_btn.clicked.connect(self.quick_scan_tips)
        quick_actions_layout.addWidget(self.scan_tips_btn)
        
        input_layout.addLayout(quick_actions_layout)
        
        # Text input
        text_input_layout = QHBoxLayout()
        
        self.input_box = QLineEdit()
        self.input_box.setPlaceholderText("Ask the AI Co-pilot about vulnerabilities, technologies, or scanning strategies...")
        self.input_box.returnPressed.connect(self.send_message)
        self.input_box.setStyleSheet("""
            QLineEdit {
                border: none;
                padding: 8px;
                font-size: 12px;
                background-color: transparent;
            }
        """)
        text_input_layout.addWidget(self.input_box)
        
        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.send_message)
        self.send_button.setStyleSheet("""
            QPushButton {
                background-color: #9c27b0;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #7b1fa2;
            }
        """)
        text_input_layout.addWidget(self.send_button)
        
        input_layout.addLayout(text_input_layout)
        layout.addWidget(input_frame)
        
        return widget
    
    def create_context_widget(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Context information
        context_group = QGroupBox("📊 Current Context")
        context_layout = QVBoxLayout(context_group)
        
        self.context_display = QTextEdit()
        self.context_display.setMaximumHeight(150)
        self.context_display.setReadOnly(True)
        self.context_display.setPlainText("No scan data available yet.\nRun a crawl to populate context.")
        context_layout.addWidget(self.context_display)
        
        layout.addWidget(context_group)
        
        # AI Settings
        settings_group = QGroupBox("⚙️ Co-pilot Settings")
        settings_layout = QVBoxLayout(settings_group)
        
        self.auto_analyze = QCheckBox("Auto-analyze new findings")
        self.auto_analyze.setChecked(True)
        settings_layout.addWidget(self.auto_analyze)
        
        self.detailed_responses = QCheckBox("Detailed responses")
        self.detailed_responses.setChecked(True)
        settings_layout.addWidget(self.detailed_responses)
        
        self.bug_bounty_mode = QCheckBox("Bug bounty focus")
        self.bug_bounty_mode.setChecked(True)
        settings_layout.addWidget(self.bug_bounty_mode)
        
        layout.addWidget(settings_group)
        
        # Suggested questions
        suggestions_group = QGroupBox("💡 Suggested Questions")
        suggestions_layout = QVBoxLayout(suggestions_group)
        
        suggestions = [
            "What vulnerabilities should I prioritize?",
            "How can I optimize my scan settings?",
            "What attack vectors should I test?",
            "How do I write a good bug report?",
            "What technologies are high-risk?"
        ]
        
        for suggestion in suggestions:
            btn = QPushButton(suggestion)
            btn.clicked.connect(lambda checked, text=suggestion: self.send_suggested_question(text))
            btn.setStyleSheet("""
                QPushButton {
                    text-align: left;
                    padding: 8px;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                    background-color: #f8f9fa;
                }
                QPushButton:hover {
                    background-color: #e9ecef;
                }
            """)
            suggestions_layout.addWidget(btn)
        
        layout.addWidget(suggestions_group)
        
        layout.addStretch()
        return widget
    
    def add_welcome_message(self):
        """Add welcome message to chat"""
        welcome_msg = """🤖 **Welcome to AI Security Co-pilot!**

I'm here to assist you with:
• **Vulnerability Analysis** - Prioritize and understand security findings
• **Technology Assessment** - Analyze detected tech stacks for risks
• **Scan Optimization** - Improve your reconnaissance strategy
• **Bug Bounty Guidance** - Maximize your hunting effectiveness

**Quick Start:**
• Use the quick action buttons above
• Ask questions about your scan results
• Get real-time security advice

How can I help you today?"""
        
        self.append_chat_message("AI Co-pilot", welcome_msg, is_system=True)
    
    def append_chat_message(self, sender, message, is_system=False):
        """Add message to chat display with formatting"""
        timestamp = time.strftime("%H:%M:%S")
        
        if sender == "User":
            color = "#007bff"
            icon = "👤"
        elif is_system:
            color = "#28a745"
            icon = "🤖"
        else:
            color = "#9c27b0"
            icon = "🤖"
        
        formatted_message = f"""
        <div style="margin: 10px 0; padding: 10px; background-color: {'#e3f2fd' if sender == 'User' else '#f3e5f5'}; border-radius: 8px; border-left: 4px solid {color};">
            <span style="color: {color}; font-weight: bold;">{icon} {sender}</span>
            <span style="color: #666; font-size: 11px; float: right;">{timestamp}</span>
            <div style="margin-top: 5px; line-height: 1.4;">{message}</div>
        </div>
        """
        
        self.chat_display.append(formatted_message)
        
        # Auto-scroll to bottom
        cursor = self.chat_display.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.chat_display.setTextCursor(cursor)
        
        # Store in history
        self.chat_history.append({
            'sender': sender,
            'message': message,
            'timestamp': timestamp,
            'is_system': is_system
        })
    
    @pyqtSlot()
    def send_message(self):
        """Send user message and get AI response"""
        user_text = self.input_box.text().strip()
        if not user_text:
            return
        
        self.append_chat_message("User", user_text)
        self.input_box.clear()
        
        # Show typing indicator
        self.append_chat_message("AI Co-pilot", "🤔 Thinking...", is_system=True)
        
        # Generate AI response in background thread
        self.ai_thread = AIResponseThread(self.ai_analyzer, user_text, self.current_context)
        self.ai_thread.response_ready.connect(self.handle_ai_response)
        self.ai_thread.error_occurred.connect(self.handle_ai_error)
        self.ai_thread.start()
    
    def send_suggested_question(self, question):
        """Send a suggested question"""
        self.input_box.setText(question)
        self.send_message()
    
    def handle_ai_response(self, response):
        """Handle AI response"""
        # Remove typing indicator (last message)
        if self.chat_history and self.chat_history[-1]['message'] == "🤔 Thinking...":
            self.chat_history.pop()
            # Clear and rebuild chat display
            self.rebuild_chat_display()
        
        self.append_chat_message("AI Co-pilot", response)
    
    def handle_ai_error(self, error):
        """Handle AI error"""
        error_msg = f"❌ Sorry, I encountered an error: {error}\n\nPlease try again or rephrase your question."
        self.append_chat_message("AI Co-pilot", error_msg, is_system=True)
    
    def rebuild_chat_display(self):
        """Rebuild chat display from history"""
        self.chat_display.clear()
        for msg in self.chat_history:
            self.append_chat_message(msg['sender'], msg['message'], msg['is_system'])
    
    def quick_analyze_vulnerabilities(self):
        """Quick action: Analyze vulnerabilities"""
        self.input_box.setText("Analyze the vulnerabilities found in my current scan and prioritize them by severity and exploitability")
        self.send_message()
    
    def quick_analyze_technologies(self):
        """Quick action: Analyze technologies"""
        self.input_box.setText("What security risks should I be aware of with the technologies detected in my scan?")
        self.send_message()
    
    def quick_scan_tips(self):
        """Quick action: Get scan tips"""
        self.input_box.setText("How can I optimize my current scan configuration for better vulnerability discovery?")
        self.send_message()
    
    def update_context(self, context_data):
        """Update context information from scan results"""
        self.current_context = context_data
        
        context_text = f"""**Current Scan Context:**

🎯 **Target:** {context_data.get('target_url', 'Not set')}
📊 **Pages Scanned:** {context_data.get('pages_scanned', 0)}
🔧 **Technologies:** {context_data.get('technologies_count', 0)}
🔍 **Security Findings:** {context_data.get('security_findings', 0)}
🛡️ **CVE Vulnerabilities:** {context_data.get('cve_count', 0)}

**Recent Activity:**
{context_data.get('recent_activity', 'No recent activity')}"""
        
        self.context_display.setPlainText(context_text)
        
        # Auto-analyze if enabled
        if self.auto_analyze.isChecked() and context_data.get('new_findings', False):
            self.auto_analyze_new_findings(context_data)
    
    def auto_analyze_new_findings(self, context_data):
        """Automatically analyze new findings"""
        if context_data.get('new_vulnerabilities'):
            auto_msg = f"🔍 I noticed {len(context_data['new_vulnerabilities'])} new vulnerabilities were found. Would you like me to analyze them?"
            self.append_chat_message("AI Co-pilot", auto_msg, is_system=True)
        
        if context_data.get('new_technologies'):
            auto_msg = f"🔧 Detected {len(context_data['new_technologies'])} new technologies. I can help assess their security risks."
            self.append_chat_message("AI Co-pilot", auto_msg, is_system=True)
    
    def clear_chat(self):
        """Clear chat history"""
        self.chat_history = []
        self.chat_display.clear()
        self.add_welcome_message()
    
    def export_chat(self):
        """Export chat history"""
        # TODO: Implement chat export functionality
        pass
