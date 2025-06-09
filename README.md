# 🕷️ Galdr v2.0
### Advanced AJAX Spider Tool with AI Security Analysis

![Galdr Logo](assets/galdr_logo.png)

> A comprehensive web security crawler designed for cybersecurity professionals and bug bounty hunters, featuring AI-powered vulnerability analysis, real-time CVE monitoring, and intelligent reconnaissance capabilities.

## 🌟 Features

### Core Functionality
- **🔧 Per-Page Technology Detection** - Comprehensive tech stack analysis on every crawled page
- **🔍 Passive Security Scanning** - Real-time vulnerability detection during crawls
- **📸 Screenshot Capture** - Visual documentation of discovered pages
- **🌐 Subdomain Enumeration** - Automated subdomain discovery for broader attack surface mapping
- **🎯 Advanced URL Filtering** - Smart crawling with duplicate detection and content analysis

### AI-Powered Analysis
- **🤖 Foundation-sec-8B Integration** - Local AI security analysis (no API required)
- **☁️ Multi-Provider Support** - OpenAI, Anthropic, DeepSeek, Google Gemini, xAI Grok
- **🧠 AI Co-pilot Chat** - Interactive security guidance and vulnerability analysis
- **📊 Intelligent Prioritization** - AI-powered risk assessment and remediation guidance

### Security Intelligence
- **🛡️ CVE Vulnerability Monitor** - Real-time vulnerability database updates
- **📈 Risk Assessment** - Automated CVSS scoring and exploit availability tracking
- **🚨 Critical Alerts** - Instant notifications for high-risk vulnerabilities
- **📋 Compliance Reporting** - GDPR, SOX, HIPAA, PCI-DSS compliance analysis

### Project Management
- **📁 Project Profiles** - Save and manage multiple target configurations
- **📊 Scan History** - Comprehensive tracking of reconnaissance activities
- **🎨 Professional Themes** - Multiple UI themes including custom Galdr branding
- **👥 Multi-User Support** - Isolated workspaces for team collaboration

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- Virtual environment (recommended)

### Setup Instructions

1. **Clone the repository:**
git clone https://github.com/yourusername/galdr.git
cd galdr

text

2. **Create and activate virtual environment:**
python3 -m venv galdr-env
source galdr-env/bin/activate # On Windows: galdr-env\Scripts\activate

text

3. **Install dependencies:**
pip install -r requirements.txt

text

4. **Install Playwright browsers:**
python -m playwright install chromium

text

5. **Run Galdr:**
python main.py

text

## 📋 Requirements

PyQt6>=6.4.0
playwright>=1.30.0
beautifulsoup4>=4.11.0
requests>=2.28.0
pyyaml>=6.0
cryptography>=3.4.8
aiohttp>=3.12.0

text

## 🎯 Usage

### Basic Crawling
1. Launch Galdr and create a user account
2. Enter target URL in the crawler tab
3. Configure scan depth and options
4. Enable desired features (screenshots, subdomain enum, passive scanning)
5. Click "Start Crawl" to begin reconnaissance

### AI-Powered Analysis
1. Navigate to AI Settings tab
2. Configure your preferred AI provider (Foundation-sec-8B enabled by default)
3. Use the AI Co-pilot for real-time security guidance
4. Run AI analysis on discovered vulnerabilities

### Project Management
1. Create project profiles for different targets
2. Save scan configurations and results
3. Track scan history and progress
4. Export results for reporting

### CVE Monitoring
1. Access CVE Monitor tab for vulnerability intelligence
2. Update CVE database for latest threat information
3. Analyze detected technologies for known vulnerabilities
4. Receive alerts for critical security issues

## 🔧 Configuration

### AI Providers Setup
- **Foundation-sec-8B**: No configuration required (local model)
- **OpenAI**: Add API key in AI Settings
- **Google Gemini**: Configure API key for enhanced analysis
- **xAI Grok**: Set up API access for unique AI perspective

### Advanced Options
- **Scan Depth**: 1-10 levels (default: 2)
- **Request Delay**: 0-10 seconds between requests
- **Screenshot Quality**: Full-page captures for documentation
- **Proxy Support**: Route traffic through proxy servers

## 🛡️ Security Features

### Vulnerability Detection
- **Passive Scanning**: Non-intrusive security analysis
- **CVE Correlation**: Match technologies to known vulnerabilities
- **OWASP Mapping**: Categorize findings by OWASP Top 10
- **CWE Classification**: Detailed weakness categorization

### AI Security Analysis
- **Severity Assessment**: Intelligent risk prioritization
- **Exploit Prediction**: Likelihood of successful exploitation
- **Attack Vector Analysis**: Comprehensive threat modeling
- **Remediation Guidance**: Actionable security recommendations

## 📊 Output Formats

- **Interactive UI**: Real-time results in professional interface
- **Database Storage**: SQLite backend for data persistence
- **Export Options**: JSON, CSV formats for external analysis
- **Screenshot Archive**: Visual documentation of discoveries
- **AI Reports**: Detailed security analysis and recommendations

## 🤝 Contributing

We welcome contributions to Galdr! Please see our contributing guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Cisco Foundation-sec-8B** - Open source security AI model
- **Playwright Team** - Excellent browser automation framework
- **PyQt6** - Professional desktop application framework
- **Security Community** - Continuous feedback and improvements

## 📞 Contact & Support

- **GitHub Issues**: [Report bugs and feature requests](https://github.com/rowandark/galdr/issues)
- **Documentation**: [Full documentation](https://github.com/rowandark/galdr/wiki)
- **Security**: For security vulnerabilities, please email security@galdr.dev

## 🔄 Version History

- **v2.0** - AI integration, CVE monitoring, project profiles
- **v1.5** - Enhanced technology detection, passive scanning
- **v1.0** - Initial release with basic crawling functionality

---

**Built for cybersecurity professionals by cybersecurity professionals** 🛡️

*Galdr - Advanced reconnaissance for the modern security researcher*
