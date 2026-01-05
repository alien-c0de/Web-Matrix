# 🕸️ Web Matrix

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/alien-c0de/web-matrix/graphs/commit-activity)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg)](https://github.com/alien-c0de/web-matrix)

**Unveil the Secrets of Your Website: Secure, Analyze, Optimize.**

Web Matrix is a comprehensive Python-based website analysis tool that uncovers security vulnerabilities, analyzes configurations, and provides actionable insights to optimize your web presence. From SSL certificates to NMAP vulnerability scans, get a complete 360° view of any website's security posture.

[Web Matrix Demo and Reports](https://alien-c0de.github.io/Web-Matrix/)

---

## 📋 Table of Contents

- [🌟 Overview](#-overview)
  - [Why Web Matrix?](#why-web-matrix)
- [✨ Key Features](#-key-features)
  - [🚀 Performance](#-performance)
  - [📊 Comprehensive Analysis](#-comprehensive-analysis)
  - [🛡️ Security-Focused](#️-security-focused)
  - [🎨 Professional Reporting](#-professional-reporting)
  - [🔧 Flexible Options](#-flexible-options)
- [🔍 Analysis Modules](#-analysis-modules)
  - [🔐 Security & Certificates](#-security--certificates-6-modules)
  - [🌐 DNS & Network](#-dns--network-7-modules)
  - [🖥️ Server & Infrastructure](#️-server--infrastructure-6-modules)
  - [🔒 Security Scanning](#-security-scanning-8-modules)
  - [📊 Analytics & Metadata](#-analytics--metadata-9-modules)
- [📸 Screenshots](#-screenshots)
- [📋 Prerequisites](#-prerequisites)
  - [Required Software](#required-software)
  - [API Keys Required](#api-keys-required)
- [🚀 Installation](#-installation)
  - [Step 1: Install Python Dependencies](#step-1-install-python-dependencies)
  - [Step 2: Install NMAP](#step-2-install-nmap-optional-but-recommended)
- [⚙️ Configuration](#️-configuration)
  - [API Keys Setup](#api-keys-setup)
- [💻 Usage](#-usage)
  - [Analysis Without NMAP](#analysis-without-nmap-fast-mode)
  - [Analysis With NMAP](#analysis-with-nmap-deep-scan-mode)
  - [Command-Line Options](#command-line-options)
- [📊 Output](#-output)
  - [Report Files](#report-files)
  - [Report Structure](#report-structure)
- [🎨 Report Features](#-report-features)
  - [Health Score Calculation](#health-score-calculation)
  - [Visual Indicators](#visual-indicators)
  - [Dashboard Features](#dashboard-features)
- [🚀 Advanced Features](#-advanced-features)
  - [NMAP Integration](#nmap-integration)
- [🔧 Troubleshooting](#-troubleshooting)
  - [Common Issues and Solutions](#common-issues-and-solutions)
- [🗺️ Roadmap](#️-roadmap)
- [📄 License](#-license)
- [👤 Author](#-author)
- [🙏 Acknowledgments](#-acknowledgments)
- [⭐ Star History](#-star-history)
- [📊 Statistics](#-statistics)

---

## 🌟 Overview

Web Matrix is designed to help security professionals, web developers, and system administrators perform comprehensive website analysis. The tool collects, organizes, and presents a wide range of open data about any website, helping identify:

- 🔒 Security vulnerabilities and misconfigurations
- 🛡️ SSL/TLS implementation issues
- 🌐 DNS and mail server configurations
- 🔥 Firewall and WAF detection
- 🎯 Technology stack and server details
- 📊 Website health and performance metrics
- ⚠️ Malware and phishing indicators
- 🔍 Open ports and potential attack vectors

### Why Web Matrix?

**The Challenge:**
- Website security assessment requires checking dozens of different aspects
- Using multiple tools is time-consuming and inefficient
- Consolidating findings into actionable reports is tedious
- Many tools lack comprehensive coverage

**The Solution:**
- ✅ **36+ Analysis Modules** in a single tool
- ✅ **Asynchronous Processing** for lightning-fast results
- ✅ **Professional HTML Reports** with visual health metrics
- ✅ **Optional NMAP Integration** for deep vulnerability scanning
- ✅ **Health Score Calculation** based on all modules
- ✅ **Cross-Platform Support** (Windows & Linux)

---

## ✨ Key Features

### 🚀 Performance
- **Asynchronous Architecture**: Modules run in parallel for maximum speed
- **Concurrent Processing**: Multiple checks execute simultaneously
- **Optimized Queries**: Efficient API calls and data collection
- **Fast Results**: Complete analysis in minutes, not hours

### 📊 Comprehensive Analysis
- **36+ Security Modules**: From SSL to NMAP vulnerability scans
- **Health Score**: Automated percentage calculation per module
- **Overall Rating**: Aggregate health score across all modules
- **Visual Dashboard**: Professional HTML reports with charts

### 🛡️ Security-Focused
- **Vulnerability Detection**: NMAP integration for CVE scanning
- **Malware Detection**: Checks against known malware databases
- **Firewall Analysis**: Identifies WAF and security controls
- **SSL/TLS Assessment**: Certificate validation and cipher analysis

### 🎨 Professional Reporting
- **HTML Dashboard**: Interactive, responsive design
- **Color-Coded Results**: Green (secure), Orange (warning), Red (critical)
- **Detailed Findings**: In-depth analysis for each module
- **Export Ready**: Share reports with stakeholders easily

### 🔧 Flexible Options
- **Standard Mode**: Quick analysis without NMAP
- **Deep Scan Mode**: Includes NMAP vulnerability assessments
- **Command-Line Interface**: Easy integration into workflows
- **Configurable**: Customizable via config file

---

## 🔍 Analysis Modules

Web Matrix currently supports **36 comprehensive modules**:

### 🔐 Security & Certificates (6 modules)
1. **SSL Certificates** - Validity, issuer, expiration analysis
2. **TLS Cipher Suites** - Encryption strength assessment
3. **HTTP Security Features** - Security headers analysis
4. **DNS Security Extensions** - DNSSEC validation
5. **Security.txt** - Security policy disclosure
6. **Firewall Detection** - WAF and firewall identification

### 🌐 DNS & Network (7 modules)
7. **DNS Records** - A, AAAA, CNAME, MX records
8. **TXT Records** - SPF, DKIM, DMARC validation
9. **DNS Server** - Name server information
10. **Mail Configuration** - Email server setup analysis
11. **Associated Hosts** - Related domains and subdomains
12. **Server Location** - Geo-location and hosting details
13. **Open Ports** - Port scanning and service detection

### 🖥️ Server & Infrastructure (6 modules)
14. **Server Info** - Web server type and version
15. **Server Status** - Uptime and availability
16. **Tech Stack** - Technologies and frameworks detected
17. **Whois Lookup** - Domain registration details
18. **Redirect Chain** - HTTP redirect analysis
19. **Crawl Rules** - robots.txt analysis

### 🔒 Security Scanning (8 modules)
20. **Malware & Phishing Detection** - Threat database checks
21. **Block Detection** - Blacklist status verification
22. **NMAP OS Detect** - Operating system fingerprinting
23. **NMAP Port Scan** - Comprehensive port analysis
24. **NMAP HTTP Vulnerability** - Web server CVE scanning
25. **NMAP SQL Injection** - SQLi vulnerability checks
26. **NMAP XSS Vulnerability** - Cross-site scripting tests
27. **NMAP ShellShock** - Bash vulnerability detection

### 📊 Analytics & Metadata (9 modules)
28. **Cookies** - Cookie analysis and security
29. **Headers** - HTTP response headers
30. **Social Tags** - Open Graph and Twitter cards
31. **Site Features** - Technology features detected
32. **Archive History** - Wayback Machine integration
33. **Global Ranking** - Traffic and popularity metrics
34. **Carbon Footprint** - Environmental impact analysis
35. **NMAP RCE Exploit** - Remote code execution checks
36. **NMAP Web Server Check** - Server misconfiguration detection

**More modules coming soon!** 🚀

---

## 📸 Screenshots

### Terminal Input
<img width="802" height="951" alt="Terminal_Input" src="https://github.com/user-attachments/assets/ae576c61-4bdc-4cad-a176-f74b8d85c063" />

*Command-line interface showing the analysis in progress*

### HTML Summary Report
<img width="1825" height="964" alt="Summary_Report" src="https://github.com/user-attachments/assets/f7994498-3a91-49a1-9343-81efce8c08c2" />

*Professional dashboard with health metrics and module scores*

### Detailed Analysis Report
<img width="1280" height="963" alt="Analysis_report" src="https://github.com/user-attachments/assets/989b8575-4a99-4c3c-9378-db3a18f05269" />

*Comprehensive breakdown of all 36 modules with findings*

---

## 📋 Prerequisites

### Required Software

- **Python 3.10 or higher**
- **pip** (Python package manager)
- **NMAP** (Optional, for vulnerability scanning)
  - Windows: Download from [nmap.org](https://nmap.org/download.html)
  - Linux: `sudo apt-get install nmap`
  - Verify: `nmap --version`

### API Keys Required

Web Matrix uses several free APIs to enhance analysis. Sign up for free accounts:

1. **VirusTotal API** - [Get API Key](https://www.virustotal.com/gui/join-us)
2. **BuiltWith API** - [Get API Key](https://api.builtwith.com)

---

## 🚀 Installation

### Step 1: Install Python Dependencies

```bash
pip install -r requirements.txt
```

Or install packages individually:

```bash
pip install python-whois requests asyncio aiohttp configparser colorama dnspython scapy beautifulsoup4 pybase64 tldextract pyfiglet pyOpenSSL python3-nmap
```

### Step 2: Install NMAP (Optional but Recommended)

**Windows:**
1. Download installer from [nmap.org/download.html](https://nmap.org/download.html)
2. Run installer with default options
3. Verify installation: `nmap --version`

**Linux (Ubuntu/Debian):**
```bash
sudo apt-get update
sudo apt-get install nmap
nmap --version
```

**macOS:**
```bash
brew install nmap
nmap --version
```

---

## ⚙️ Configuration

### API Keys Setup

1. Navigate to the config directory:

```bash
cd config
```

2. Open the configuration file and add your API keys:

**File: `config/config.ini`**

```ini
[VIRUS_TOTAL]
ENDPOINT_URL = https://www.virustotal.com/api/v3/urls/
API_KEY = Your_VirusTotal_API_Key_Here

[BUILTWITH]
ENDPOINT_URL = https://api.builtwith.com/free1/api.json?KEY={apiKey}&LOOKUP={url}
API_KEY = Your_BuiltWith_API_Key_Here
```

3. **Important Notes:**
   - Replace `Your_VirusTotal_API_Key_Here` with your actual VirusTotal API key
   - Replace `Your_BuiltWith_API_Key_Here` with your actual BuiltWith API key
   - Keep the configuration file secure and never commit it to public repositories
   - Free tier API keys have rate limits - check provider documentation

4. **Verify Configuration:**

```bash
python main.py --version
```

If configuration is correct, you'll see the Web Matrix version and no errors.

---

## 💻 Usage

### Analysis Without NMAP (Fast Mode)

Perform a quick analysis without vulnerability scanning:

```bash
python main.py -s https://example.com-m 1
```

**Use Case:** Quick security check, regular monitoring, automated scans

**Typical Duration:** 30-60 Seconds

### Analysis With NMAP (Deep Scan Mode)

Perform comprehensive analysis including vulnerability scanning:

```bash
python main.py -sn https://example.com -m 1
```

**Use Case:** Penetration testing, security audits, compliance checks

**Typical Duration:** 3 - 9 minutes

⚠️ **Note:** NMAP scanning may require administrator/root (sudo) privileges

### Command-Line Options

```bash
usage: main.py [-h] [-s URL] [-sn URL] [-m 1] [-v]

Web Matrix - Comprehensive Website Security Analysis

optional arguments:
  -h,        --help            Show this help message and exit
  -s  URL,   --scan      URL   Analyze website without NMAP
  -sn URL,   --scan-nmap URL   Analyze website with NMAP vulnerability scanning
  -m,        --mode 0 or 1     0 for Light and 1 for Dark Mode
  -v,        --version         Show program version and exit
```

### Usage Examples

**Basic Scan:**
```bash
python main.py -s https://example.com -m 1
```

**Deep Scan with NMAP:**
```bash
python main.py -sn https://example.com -m 1
```

**Check Version:**
```bash
python main.py --version
```

**Help Information:**
```bash
python main.py --help
```

---

## 📊 Output

### Report Files

All reports are generated in the `./output` directory:

```
output/
├── WebMatrix_example.com_15Dec2025_14-30-45.html      # Summary Report
└── Analysis_example.com_15Dec2025_14-30-45.html       # Health Analysis Report
```

### Report Structure

Each HTML report contains:

#### 1. **Executive Summary**
   - Overall health score (0-100%)
   - Quick status indicators
   - Critical findings highlight
   - At-a-glance security posture

#### 2. **Module Scores Dashboard**
   - Individual module performance
   - Color-coded health indicators (🟢🟡🔴)
   - Pass/Fail/Warning status
   - Interactive progress bars

#### 3. **Detailed Analysis**
   - Complete findings for each module
   - Technical details and evidence
   - Security implications
   - Proof of findings

#### 4. **Recommendations**
   - Prioritized action items
   - Security improvement suggestions
   - Configuration optimization tips
   - Remediation steps

---

## 🎨 Report Features

### Health Score Calculation

Web Matrix calculates health scores at two levels:

**Module-Level Score:**
```
Module Score = (Passed Checks / Total Checks) × 100%
```

**Overall Health Score:**
```
Overall Score = (Sum of All Module Scores / Number of Modules) × 100%
```

### Visual Indicators

Reports use intuitive color coding:

| Score Range | Color | Status | Meaning |
|-------------|-------|--------|---------|
| 80-100% | 🟢 Green | Excellent | Highly secure, well-configured |
| 60-79% | 🟡 Yellow | Moderate | Minor issues, generally secure |
| 40-59% | 🔴 Red | Poor | Several issues need attention |
| Below 40% | 🔴 Critical | Critical | Immediate action required |


### Dashboard Features

- **Responsive Design**: Works perfectly on desktop, tablet, and mobile devices
- **Interactive Charts**: Visual representation of module scores and trends
- **Collapsible Sections**: Organize large amounts of data efficiently
- **Dark/Light Mode**: Professional themes for different preferences
- **Print-Friendly**: Optimized layouts for PDF export
- **Fast Loading**: Optimized HTML/CSS for quick rendering

---

## 🚀 Advanced Features

### NMAP Integration

Web Matrix includes 8 specialized NMAP scanning modules:

#### 1. **OS Detection**
Fingerprints the target operating system using TCP/IP stack analysis.

#### 2. **Comprehensive Port Scanning**
Scans common and uncommon ports to identify open services.

#### 3. **HTTP Vulnerability Scanning**
Tests web servers for known CVEs and misconfigurations.

#### 4. **SQL Injection Testing**
Automated detection of SQL injection vulnerabilities.

#### 5. **XSS Vulnerability Detection**
Cross-site scripting vulnerability assessment.

#### 6. **ShellShock Detection**
Tests for Bash vulnerability (CVE-2014-6271).

#### 7. **RCE Exploit Detection**
Checks for remote code execution vulnerabilities.

#### 8. **Web Server Misconfiguration**
Identifies common server security misconfigurations.

**Benefits:**
- ⚡ Parallel execution for 10x faster scanning
- 🔄 Efficient resource utilization
- 📊 Real-time progress updates
- 🛡️ Graceful error handling
- 📝 Detailed vulnerability reports

**Performance:**
- Traditional sequential NMAP: ~30-45 minutes
- Web Matrix parallel NMAP: ~10-15 minutes
- **Speed improvement: 3x faster**

---

## 🔧 Troubleshooting

### Common Issues and Solutions

#### 1. NMAP Not Found

**Error:** `nmap: command not found` or `NMAP executable not found`

**Solutions:**

**Windows:**
```bash
# Add NMAP to PATH
set PATH=%PATH%;C:\Program Files (x86)\Nmap

# Or reinstall NMAP
# Download from: https://nmap.org/download.html
```

**Linux:**
```bash
# Install NMAP
sudo apt-get update
sudo apt-get install nmap

# Verify installation
nmap --version
```

**macOS:**
```bash
# Install via Homebrew
brew install nmap

# Verify installation
nmap --version
```

#### 2. Permission Denied (NMAP)

**Error:** `Permission denied when running NMAP scans` or `Operation not permitted`

**Solutions:**

**Linux:**
```bash
# Option 1: Run with sudo (recommended for testing)
sudo python main.py -sn https://example.com -m 1

# Option 2: Grant capabilities (permanent solution)
sudo setcap cap_net_raw,cap_net_admin=eip $(which nmap)

# Verify capabilities
getcap $(which nmap)
```

**Windows:**
```bash
# Run Command Prompt or PowerShell as Administrator
# Right-click > "Run as administrator"
python main.py -sn https://example.com -m 1
```

#### 3. Module Import Errors

**Error:** `ModuleNotFoundError: No module named 'xyz'`

**Solutions:**
```bash
# Reinstall all requirements
pip install -r requirements.txt --force-reinstall

# Or install missing module individually
pip install <module_name>

# Verify Python version
python --version  # Should be 3.10 or higher
```

#### 4. API Rate Limiting

**Error:** `API rate limit exceeded` or `403 Forbidden`

**Solutions:**
- Wait for the rate limit to reset (usually 1 hour)
- Upgrade to paid API tier for higher limits
- Use different API keys for different scans
- Implement delays between scans

#### 5. Timeout Errors

**Error:** `Request timeout` or `Connection timeout`

**Solutions:**
```bash
# Increase timeout in configuration
# Edit config file to extend timeout values

# Check network connectivity
ping google.com

# Try again with stable internet connection
```

#### 6. Report Generation Failed

**Error:** `Failed to generate report` or `Permission denied: output/`

**Solutions:**
```bash
# Create output directory manually
mkdir output

# Check write permissions
ls -la output/

# Grant write permissions (Linux/macOS)
chmod 755 output/
```

#### 7. Unicode/Encoding Errors

**Error:** `UnicodeDecodeError` or encoding issues

**Solutions:**
```bash
# Set environment encoding (Linux/macOS)
export PYTHONIOENCODING=utf-8

# Windows
set PYTHONIOENCODING=utf-8

# Or add to Python script
# -*- coding: utf-8 -*-
```

### Getting Help

If you encounter issues not listed here:

1. **Check Documentation**: Review the [Wiki](https://github.com/alien-c0de/web-matrix/wiki)
2. **Search Issues**: Look through [existing issues](https://github.com/alien-c0de/web-matrix/issues)
3. **Create Issue**: Open a [new issue](https://github.com/alien-c0de/web-matrix/issues/new) with:
   - Error message
   - Steps to reproduce
   - System information (OS, Python version)
   - Screenshots if applicable

---

## 🗺️ Roadmap

- [ ] Add new analysis modules
- [ ] JSON export format support
- [ ] PDF report generation
- [ ] Batch scanning capability
- [ ] Historical comparison reports

---

## 📄 License

This project is licensed under the MIT License.
---

## 👤 Author

**Alien C00de** - *Security Researcher & Developer*

- 🌐 Website: [alien-c0de.github.io](https://alien-c0de.github.io)
- 💼 GitHub: [@alien-c0de](https://github.com/alien-c0de)
- 💼 LinkedIn: [santosh-susveerkar](https://linkedin.com/in/santosh-susveerkar/)
- 📧 Email: [alien.c00de@gmail.com](mailto:alien.c00de@gmail.com)

### Support the Project

If you find this project helpful:
- ⭐ Star the repository
- 🐛 Report bugs and issues
- 💡 Suggest new features
- 🔧 Contribute code
- 📢 Share with others
<!-- - ☕ [Buy me a coffee](https://buymeacoffee.com/alienc00de) -->

---

## 🙏 Acknowledgments

Special thanks to the amazing open-source community and tools that made this project possible:

### Security Tools
- **NMAP** - Gordon Lyon and the NMAP Development Team for the incredible port scanning tool
- **OWASP** - For comprehensive security guidelines and best practices
- **VirusTotal** - For malware detection API and threat intelligence
- **Google Safe Browsing** - For phishing protection database

### Python Libraries
- **python-whois** - Domain registration information
- **asyncio/aiohttp** - Asynchronous HTTP requests
- **dnspython** - DNS query functionality
- **beautifulsoup4** - HTML parsing
- **scapy** - Network packet manipulation
- **colorama** - Terminal color support

### Design & UI
- **Font Awesome** - Beautiful icons
- **Google Fonts** - Inter typography
- **Shields.io** - Professional badges

### Community
- All open-source contributors who made this possible
- The cybersecurity community for continuous feedback
- Beta testers and early adopters
- Everyone who reported bugs and suggested features

### Special Mentions
- **Python Software Foundation** - For the amazing Python language
- **GitHub** - For hosting and collaboration tools
- **Stack Overflow** - For countless solutions and help

---

## ⭐ Star History

If you find Web Matrix useful, please consider giving it a star! ⭐

[![Star History Chart](https://api.star-history.com/svg?repos=alien-c0de/web-matrix&type=Date)](https://star-history.com/#alien-c0de/web-matrix&Date)

---

## 📊 Statistics

![GitHub stars](https://img.shields.io/github/stars/alien-c0de/web-matrix?style=social)
![GitHub forks](https://img.shields.io/github/forks/alien-c0de/web-matrix?style=social)
![GitHub watchers](https://img.shields.io/github/watchers/alien-c0de/web-matrix?style=social)
![GitHub issues](https://img.shields.io/github/issues/alien-c0de/web-matrix)
![GitHub pull requests](https://img.shields.io/github/issues-pr/alien-c0de/web-matrix)
![GitHub last commit](https://img.shields.io/github/last-commit/alien-c0de/web-matrix)
![GitHub code size](https://img.shields.io/github/languages/code-size/alien-c0de/web-matrix)
![GitHub contributors](https://img.shields.io/github/contributors/alien-c0de/web-matrix)

---

## 📚 Additional Resources

### Documentation
- [Wiki](https://github.com/alien-c0de/web-matrix/wiki) - Comprehensive documentation
- [API Reference](https://github.com/alien-c0de/web-matrix/wiki/API) - Module API details
- [Configuration Guide](https://github.com/alien-c0de/web-matrix/wiki/Configuration) - Advanced settings

### Community
- [Discussions](https://github.com/alien-c0de/web-matrix/discussions) - Q&A and ideas
- [Issue Tracker](https://github.com/alien-c0de/web-matrix/issues) - Bug reports
- [Security Policy](SECURITY.md) - Report vulnerabilities

### Related Projects
- [Web Matrix CLI](https://github.com/alien-c0de/web-matrix-cli) - Enhanced CLI version
- [Web Matrix Dashboard](https://github.com/alien-c0de/web-matrix-dashboard) - Web interface
- [Web Matrix Docker](https://github.com/alien-c0de/web-matrix-docker) - Docker image

---

<div align="center">

**🕸️ Made with ❤️ for the Web Security Community**

[Documentation](https://github.com/alien-c0de/web-matrix/wiki) · [Report Bug](https://github.com/alien-c0de/web-matrix/issues) · [Request Feature](https://github.com/alien-c0de/web-matrix/issues) · [Discuss](https://github.com/alien-c0de/web-matrix/discussions)

---

### Quick Links

[⬆️ Back to Top](#️-web-matrix) | [📖 Documentation](https://github.com/alien-c0de/web-matrix/wiki) | [🐛 Issues](https://github.com/alien-c0de/web-matrix/issues) | [💡 Discussions](https://github.com/alien-c0de/web-matrix/discussions)

---

**🚀 Happy Website Analysis! 🚀**

*Secure today, protected tomorrow.*

</div>

---

## 📝 Changelog

See [CHANGELOG.md](CHANGELOG.md) for a detailed history of changes.

### Latest Release: v2.0.0 (December 2025)
- ✨ Added 36 comprehensive security modules
- ⚡ Implemented async/await for parallel processing
- 🎨 New professional HTML reports with dark/light themes
- 🔒 Enhanced NMAP integration with 8 vulnerability scans
- 📊 Improved health score calculation
- 🐛 Fixed multiple bugs and improved stability

---

<div align="center">

**Copyright © 2025 Alien C00de. All rights reserved.**

</div>
