from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
    QPushButton, QComboBox, QMessageBox, QGroupBox, QTextEdit,
    QCheckBox, QTabWidget, QFormLayout
)
from PyQt6.QtCore import pyqtSignal, Qt
from PyQt6.QtGui import QFont
from ..core.ai_integration import AISecurityAnalyzer

class AISettingsPanel(QWidget):
    ai_settings_changed = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.ai_analyzer = AISecurityAnalyzer()
        self.api_keys = {}
        self.init_ui()
        self.load_available_providers()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Header
        header = QLabel("🤖 Enhanced AI Security Analysis Configuration")
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
        
        # Create tabs for different AI providers
        self.tab_widget = QTabWidget()
        
        # Local AI tab
        local_tab = self.create_local_ai_tab()
        self.tab_widget.addTab(local_tab, "🏠 Local AI")
        
        # Cloud AI tab
        cloud_tab = self.create_cloud_ai_tab()
        self.tab_widget.addTab(cloud_tab, "☁️ Cloud AI")
        
        # Advanced settings tab
        advanced_tab = self.create_advanced_tab()
        self.tab_widget.addTab(advanced_tab, "⚙️ Advanced")
        
        layout.addWidget(self.tab_widget)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        self.test_btn = QPushButton("🧪 Test AI Connection")
        self.test_btn.clicked.connect(self.test_ai_connection)
        self.test_btn.setStyleSheet("""
            QPushButton {
                background-color: #4caf50;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        button_layout.addWidget(self.test_btn)
        
        self.save_btn = QPushButton("💾 Save Settings")
        self.save_btn.clicked.connect(self.save_settings)
        self.save_btn.setStyleSheet("""
            QPushButton {
                background-color: #00d4aa;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #00b899;
            }
        """)
        button_layout.addWidget(self.save_btn)
        
        layout.addLayout(button_layout)
    
    def create_local_ai_tab(self):
        """Create local AI configuration tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Foundation-sec-8B section
        foundation_group = QGroupBox("🔒 Foundation-sec-8B (Recommended)")
        foundation_layout = QVBoxLayout(foundation_group)
        
        description = QLabel("""
        <b>Cisco Foundation-sec-8B</b> - Open source security-focused AI model<br>
        ✅ Completely free and private<br>
        ✅ Runs locally on your machine<br>
        ✅ Specialized for cybersecurity analysis<br>
        ✅ No API keys or internet required
        """)
        description.setWordWrap(True)
        foundation_layout.addWidget(description)
        
        self.foundation_enabled = QCheckBox("Enable Foundation-sec-8B (Default)")
        self.foundation_enabled.setChecked(True)
        foundation_layout.addWidget(self.foundation_enabled)
        
        layout.addWidget(foundation_group)
        
        # Ollama section
        ollama_group = QGroupBox("🦙 Ollama Integration")
        ollama_layout = QFormLayout(ollama_group)
        
        self.ollama_enabled = QCheckBox("Enable Ollama")
        ollama_layout.addRow(self.ollama_enabled)
        
        self.ollama_endpoint = QLineEdit("http://localhost:11434")
        ollama_layout.addRow("Ollama Endpoint:", self.ollama_endpoint)
        
        self.ollama_model = QComboBox()
        self.ollama_model.addItems(['qwen2.5:7b', 'llama3.1:8b', 'codellama:7b', 'mistral:7b'])
        ollama_layout.addRow("Model:", self.ollama_model)
        
        layout.addWidget(ollama_group)
        
        layout.addStretch()
        return widget
    
    def create_cloud_ai_tab(self):
        """Create cloud AI configuration tab with enhanced providers"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # OpenAI section
        openai_group = QGroupBox("🔥 OpenAI")
        openai_layout = QFormLayout(openai_group)
        
        self.openai_enabled = QCheckBox("Enable OpenAI")
        openai_layout.addRow(self.openai_enabled)
        
        self.openai_api_key = QLineEdit()
        self.openai_api_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.openai_api_key.setPlaceholderText("sk-...")
        openai_layout.addRow("API Key:", self.openai_api_key)
        
        self.openai_model = QComboBox()
        self.openai_model.addItems(['gpt-4o', 'gpt-4-turbo', 'gpt-3.5-turbo'])
        openai_layout.addRow("Model:", self.openai_model)
        
        layout.addWidget(openai_group)
        
        # Anthropic section
        anthropic_group = QGroupBox("🧠 Anthropic Claude")
        anthropic_layout = QFormLayout(anthropic_group)
        
        self.anthropic_enabled = QCheckBox("Enable Anthropic")
        anthropic_layout.addRow(self.anthropic_enabled)
        
        self.anthropic_api_key = QLineEdit()
        self.anthropic_api_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.anthropic_api_key.setPlaceholderText("sk-ant-...")
        anthropic_layout.addRow("API Key:", self.anthropic_api_key)
        
        self.anthropic_model = QComboBox()
        self.anthropic_model.addItems(['claude-3-5-sonnet-20241022', 'claude-3-opus-20240229'])
        anthropic_layout.addRow("Model:", self.anthropic_model)
        
        layout.addWidget(anthropic_group)
        
        # DeepSeek section
        deepseek_group = QGroupBox("🔍 DeepSeek")
        deepseek_layout = QFormLayout(deepseek_group)
        
        self.deepseek_enabled = QCheckBox("Enable DeepSeek")
        deepseek_layout.addRow(self.deepseek_enabled)
        
        self.deepseek_api_key = QLineEdit()
        self.deepseek_api_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.deepseek_api_key.setPlaceholderText("sk-...")
        deepseek_layout.addRow("API Key:", self.deepseek_api_key)
        
        self.deepseek_model = QComboBox()
        self.deepseek_model.addItems(['deepseek-chat', 'deepseek-coder'])
        deepseek_layout.addRow("Model:", self.deepseek_model)
        
        layout.addWidget(deepseek_group)
        
        # ✅ NEW: Gemini section
        gemini_group = QGroupBox("🌟 Google Gemini")
        gemini_layout = QFormLayout(gemini_group)
        
        self.gemini_enabled = QCheckBox("Enable Gemini")
        gemini_layout.addRow(self.gemini_enabled)
        
        self.gemini_api_key = QLineEdit()
        self.gemini_api_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.gemini_api_key.setPlaceholderText("AIza...")
        gemini_layout.addRow("API Key:", self.gemini_api_key)
        
        self.gemini_model = QComboBox()
        self.gemini_model.addItems(['gemini-1.5-pro', 'gemini-1.5-flash', 'gemini-1.0-pro'])
        gemini_layout.addRow("Model:", self.gemini_model)
        
        gemini_info = QLabel("🌟 Google's most advanced AI model with excellent security analysis capabilities")
        gemini_info.setWordWrap(True)
        gemini_info.setStyleSheet("color: #666; font-size: 11px; margin-top: 5px;")
        gemini_layout.addRow(gemini_info)
        
        layout.addWidget(gemini_group)
        
        # ✅ NEW: Grok section
        grok_group = QGroupBox("🤖 xAI Grok")
        grok_layout = QFormLayout(grok_group)
        
        self.grok_enabled = QCheckBox("Enable Grok")
        grok_layout.addRow(self.grok_enabled)
        
        self.grok_api_key = QLineEdit()
        self.grok_api_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.grok_api_key.setPlaceholderText("xai-...")
        grok_layout.addRow("API Key:", self.grok_api_key)
        
        self.grok_model = QComboBox()
        self.grok_model.addItems(['grok-beta', 'grok-vision-beta'])
        grok_layout.addRow("Model:", self.grok_model)
        
        grok_info = QLabel("🤖 Elon Musk's xAI model with real-time knowledge and unique perspective")
        grok_info.setWordWrap(True)
        grok_info.setStyleSheet("color: #666; font-size: 11px; margin-top: 5px;")
        grok_layout.addRow(grok_info)
        
        layout.addWidget(grok_group)
        
        layout.addStretch()
        return widget
    
    def create_advanced_tab(self):
        """Create advanced AI settings tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Analysis settings
        analysis_group = QGroupBox("🔬 Analysis Settings")
        analysis_layout = QFormLayout(analysis_group)
        
        self.auto_analyze = QCheckBox("Auto-analyze findings during crawl")
        self.auto_analyze.setChecked(True)
        analysis_layout.addRow(self.auto_analyze)
        
        self.confidence_threshold = QComboBox()
        self.confidence_threshold.addItems(['0.5', '0.6', '0.7', '0.8', '0.9'])
        self.confidence_threshold.setCurrentText('0.7')
        analysis_layout.addRow("Confidence Threshold:", self.confidence_threshold)
        
        self.max_findings_per_batch = QComboBox()
        self.max_findings_per_batch.addItems(['10', '25', '50', '100'])
        self.max_findings_per_batch.setCurrentText('25')
        analysis_layout.addRow("Max Findings per Batch:", self.max_findings_per_batch)
        
        # ✅ NEW: AI Provider Priority
        self.provider_priority = QComboBox()
        self.provider_priority.addItems([
            'Foundation-sec-8B (Local)',
            'OpenAI GPT-4o',
            'Anthropic Claude',
            'Google Gemini',
            'xAI Grok',
            'DeepSeek',
            'Ollama'
        ])
        analysis_layout.addRow("Primary AI Provider:", self.provider_priority)
        
        # ✅ NEW: Analysis Mode
        self.analysis_mode = QComboBox()
        self.analysis_mode.addItems([
            'Standard Analysis',
            'Deep Security Analysis',
            'Bug Bounty Mode',
            'Penetration Testing Mode',
            'Compliance Assessment'
        ])
        analysis_layout.addRow("Analysis Mode:", self.analysis_mode)
        
        layout.addWidget(analysis_group)
        
        # Enhanced prompts section
        prompt_group = QGroupBox("📝 Custom Analysis Prompts")
        prompt_layout = QVBoxLayout(prompt_group)
        
        prompt_layout.addWidget(QLabel("Custom Security Analysis Prompt:"))
        self.custom_prompt = QTextEdit()
        self.custom_prompt.setPlaceholderText(
            "Enter custom prompt for AI security analysis...\n"
            "Use {finding_title}, {finding_severity}, {url}, {technology} as placeholders\n\n"
            "Example: Analyze this {finding_severity} security finding '{finding_title}' "
            "found on {url} running {technology}. Provide exploitation steps and remediation."
        )
        self.custom_prompt.setMaximumHeight(120)
        prompt_layout.addWidget(self.custom_prompt)
        
        # ✅ NEW: Preset prompts
        preset_layout = QHBoxLayout()
        preset_layout.addWidget(QLabel("Quick Presets:"))
        
        self.bug_bounty_preset = QPushButton("🎯 Bug Bounty")
        self.bug_bounty_preset.clicked.connect(self.load_bug_bounty_preset)
        preset_layout.addWidget(self.bug_bounty_preset)
        
        self.pentest_preset = QPushButton("🔍 Pentest")
        self.pentest_preset.clicked.connect(self.load_pentest_preset)
        preset_layout.addWidget(self.pentest_preset)
        
        self.compliance_preset = QPushButton("📋 Compliance")
        self.compliance_preset.clicked.connect(self.load_compliance_preset)
        preset_layout.addWidget(self.compliance_preset)
        
        preset_layout.addStretch()
        prompt_layout.addLayout(preset_layout)
        
        layout.addWidget(prompt_group)
        
        layout.addStretch()
        return widget
    
    def load_bug_bounty_preset(self):
        """Load bug bounty focused prompt"""
        prompt = """As a bug bounty expert, analyze this {finding_severity} security finding: '{finding_title}'

Target: {url}
Technology: {technology}

Provide:
1. Exploitability assessment (1-10 scale)
2. Potential impact on business
3. Step-by-step exploitation guide
4. Proof-of-concept payload
5. Estimated bounty value range
6. Similar CVEs or public exploits
7. Remediation priority (Critical/High/Medium/Low)

Focus on practical exploitation and business impact for bug bounty submission."""
        self.custom_prompt.setPlainText(prompt)
    
    def load_pentest_preset(self):
        """Load penetration testing focused prompt"""
        prompt = """As a penetration tester, analyze this {finding_severity} security finding: '{finding_title}'

Target: {url}
Technology: {technology}

Provide:
1. Attack vector analysis
2. Privilege escalation potential
3. Lateral movement opportunities
4. Data exfiltration possibilities
5. Persistence mechanisms
6. Detection evasion techniques
7. Remediation steps with timeline

Focus on comprehensive security assessment and risk quantification."""
        self.custom_prompt.setPlainText(prompt)
    
    def load_compliance_preset(self):
        """Load compliance focused prompt"""
        prompt = """As a compliance auditor, analyze this {finding_severity} security finding: '{finding_title}'

Target: {url}
Technology: {technology}

Provide:
1. Regulatory impact (GDPR, SOX, HIPAA, PCI-DSS)
2. Compliance violations identified
3. Risk rating for audit purposes
4. Required remediation timeline
5. Documentation requirements
6. Stakeholder notification needs
7. Audit trail recommendations

Focus on regulatory compliance and governance requirements."""
        self.custom_prompt.setPlainText(prompt)
    
    def load_available_providers(self):
        """Load available AI providers"""
        try:
            providers = self.ai_analyzer.get_available_providers()
            # Update UI with available providers
        except Exception as e:
            QMessageBox.warning(self, "Provider Loading Error", f"Failed to load providers: {str(e)}")
    
    def test_ai_connection(self):
        """Test AI connection"""
        try:
            # Test the currently selected AI provider
            if self.foundation_enabled.isChecked():
                success = self.ai_analyzer.initialize()
                if success:
                    QMessageBox.information(self, "Test Successful", 
                                          "✅ Foundation-sec-8B is working correctly!")
                else:
                    QMessageBox.warning(self, "Test Failed", 
                                      "❌ Foundation-sec-8B failed to initialize")
            elif self.gemini_enabled.isChecked() and self.gemini_api_key.text():
                QMessageBox.information(self, "Test Info", 
                                      "🌟 Gemini connection test - API key configured")
            elif self.grok_enabled.isChecked() and self.grok_api_key.text():
                QMessageBox.information(self, "Test Info", 
                                      "🤖 Grok connection test - API key configured")
            else:
                QMessageBox.information(self, "Test Info", 
                                      "Please configure and enable an AI provider first")
        except Exception as e:
            QMessageBox.critical(self, "Test Error", f"AI test failed: {str(e)}")
    
    def save_settings(self):
        """Save AI settings"""
        settings = {
            'foundation_enabled': self.foundation_enabled.isChecked(),
            'ollama_enabled': self.ollama_enabled.isChecked(),
            'ollama_endpoint': self.ollama_endpoint.text(),
            'ollama_model': self.ollama_model.currentText(),
            'openai_enabled': self.openai_enabled.isChecked(),
            'openai_model': self.openai_model.currentText(),
            'anthropic_enabled': self.anthropic_enabled.isChecked(),
            'anthropic_model': self.anthropic_model.currentText(),
            'deepseek_enabled': self.deepseek_enabled.isChecked(),
            'deepseek_model': self.deepseek_model.currentText(),
            # ✅ NEW: Gemini settings
            'gemini_enabled': self.gemini_enabled.isChecked(),
            'gemini_model': self.gemini_model.currentText(),
            # ✅ NEW: Grok settings
            'grok_enabled': self.grok_enabled.isChecked(),
            'grok_model': self.grok_model.currentText(),
            # Advanced settings
            'auto_analyze': self.auto_analyze.isChecked(),
            'confidence_threshold': float(self.confidence_threshold.currentText()),
            'max_findings_per_batch': int(self.max_findings_per_batch.currentText()),
            'provider_priority': self.provider_priority.currentText(),
            'analysis_mode': self.analysis_mode.currentText(),
            'custom_prompt': self.custom_prompt.toPlainText()
        }
        
        # Store API keys securely
        api_keys = {}
        if self.openai_api_key.text():
            api_keys['openai'] = self.openai_api_key.text()
        if self.anthropic_api_key.text():
            api_keys['anthropic'] = self.anthropic_api_key.text()
        if self.deepseek_api_key.text():
            api_keys['deepseek'] = self.deepseek_api_key.text()
        if self.gemini_api_key.text():
            api_keys['gemini'] = self.gemini_api_key.text()
        if self.grok_api_key.text():
            api_keys['grok'] = self.grok_api_key.text()
        
        settings['api_keys'] = api_keys
        
        # Emit settings change signal
        self.ai_settings_changed.emit(settings)
        
        QMessageBox.information(self, "Settings Saved", 
                              "✅ Enhanced AI settings have been saved successfully!\n\n"
                              f"🤖 Providers configured: {len([k for k, v in settings.items() if k.endswith('_enabled') and v])}\n"
                              f"🔑 API keys stored: {len(api_keys)}")
