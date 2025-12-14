# 🕸️ Web Matrix

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/yourusername/web-matrix/graphs/commit-activity)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg)](https://github.com/yourusername/web-matrix)

**Unveil the Secrets of Your Website: Secure, Analyze, Optimize.**

Web Matrix is a comprehensive Python-based website analysis tool that uncovers security vulnerabilities, analyzes configurations, and provides actionable insights to optimize your web presence. From SSL certificates to NMAP vulnerability scans, get a complete 360° view of any website's security posture.

![Web Matrix Banner](https://via.placeholder.com/800x200/667eea/ffffff?text=Web+Matrix+%7C+Complete+Website+Security+Analysis)

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [Analysis Modules](#-analysis-modules)
- [Screenshots](#-screenshots)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Output](#-output)
- [Report Features](#-report-features)
- [Advanced Features](#-advanced-features)
- [Troubleshooting](#-troubleshooting)
- [Roadmap](#-roadmap)
- [License](#-license)
- [Author](#-author)
- [Acknowledgments](#-acknowledgments)

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

### 🚀 **Performance**
- **Asynchronous Architecture**: Modules run in parallel for maximum speed
- **Concurrent Processing**: Multiple checks execute simultaneously
- **Optimized Queries**: Efficient API calls and data collection
- **Fast Results**: Complete analysis in minutes, not hours

### 📊 **Comprehensive Analysis**
- **36+ Security Modules**: From SSL to NMAP vulnerability scans
- **Health Score**: Automated percentage calculation per module
- **Overall Rating**: Aggregate health score across all modules
- **Visual Dashboard**: Professional HTML reports with charts

### 🛡️ **Security-Focused**
- **Vulnerability Detection**: NMAP integration for CVE scanning
- **Malware Detection**: Checks against known malware databases
- **Firewall Analysis**: Identifies WAF and security controls
- **SSL/TLS Assessment**: Certificate validation and cipher analysis

### 🎨 **Professional Reporting**
- **HTML Dashboard**: Interactive, responsive design
- **Color-Coded Results**: Green (secure), Orange (warning), Red (critical)
- **Detailed Findings**: In-depth analysis for each module
- **Export Ready**: Share reports with stakeholders easily

### 🔧 **Flexible Options**
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
![Terminal Input](https://github.com/user-attachments/assets/44bf5af3-13aa-4b29-9636-fc3d5010bc3a)

*Command-line interface showing the analysis in progress*

### HTML Summary Report
![Summary Report Dashboard](https://github.com/user-attachments/assets/2d1b28cb-9294-472c-9363-5ea33406d3cd)

*Professional dashboard with health metrics and module scores*

### Detailed Analysis Report
![Detailed Analysis](https://github.com/user-attachments/assets/7d8bc306-a43f-4714-9140-a6b2b71f3e49)

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
2. **Stack behind any website API** - [Get API Key](https://api.builtwith.com)

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

---

## ⚙️ Configuration

### API Keys Setup

1. Navigate to the config directory:
```bash
cd config
```

2. Add your API keys:

```bash
[VIRUS_TOTAL]
ENDPOINT_URL = https://www.virustotal.com/api/v3/urls/
API_KEY = Your_API_key

[BUILTWITH]
ENDPOINT_URL = https://api.builtwith.com/free1/api.json?KEY={apiKey}&LOOKUP={url}
API_KEY = API_KEY = Your_API_key
```
---

## 💻 Usage

### Analysis Without NMAP (Fast Mode)

```bash
python main.py -s https://example.com
```

### Analysis With NMAP (Deep Scan Mode)

```bash
python main.py -sn https://example.com
```

### Command-Line Options

```bash
usage: main.py [-h] [-s URL] [-sn URL] [-b FILE] [-o OUTPUT] [-v]

Web Matrix - Comprehensive Website Security Analysis

optional arguments:
  -h, --help                  Show this help message and exit
  -s URL, --scan URL          Analyze website without NMAP
  -sn URL, --scan-nmap URL    Analyze website with NMAP vulnerability scanning
  -v, --version               Show program version
  
```

---

## 📊 Output

### Report Files

All reports are generated in the `./output` directory:

```
output/
├── WebMatrix_test.com_15Dec2025_14-30-45.html
└── Analysis_test.com_15Dec2025_14-30-45.html
```

### Report Structure

Each HTML report contains:

1. **Executive Summary**
   - Overall health score (0-100%)
   - Quick status indicators
   - Critical findings highlight

2. **Module Scores**
   - Individual module performance
   - Color-coded health indicators
   - Pass/Fail/Warning status

3. **Detailed Analysis**
   - Complete findings for each module
   - Technical details and recommendations
   - Evidence and proof of findings

4. **Recommendations**
   - Prioritized action items
   - Security improvement suggestions
   - Configuration optimization tips

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
| 90-100% | 🟢 Green | Excellent | Highly secure, well-configured |
| 70-89% | 🟡 Yellow | Good | Minor issues, generally secure |
| 50-69% | 🟠 Orange | Fair | Several issues need attention |
| 30-49% | 🔴 Red | Poor | Significant security concerns |
| 0-29% | 🔴 Critical | Critical | Immediate action required |

### Dashboard Features

- **Responsive Design**: Works on desktop, tablet, and mobile
- **Interactive Charts**: Visual representation of module scores
- **Collapsible Sections**: Organize large amounts of data
- **Search Functionality**: Quick find within reports
- **Export Options**: Print or save as PDF

---

## 🚀 Advanced Features

### NMAP Integration

Web Matrix includes 6 specialized NMAP scanning modules:

#### 1. OS Detection
#### 2. Port Scanning
#### 3. HTTP Vulnerability Scanning
#### 4. SQL Injection Testing
#### 5. XSS Vulnerability Detection
#### 6. ShellShock Detection

**Benefits:**
- ⚡ 10x faster than sequential execution
- 🔄 Efficient resource utilization
- 📊 Real-time progress updates
- 🛡️ Graceful error handling

---

## 🔧 Troubleshooting

### Common Issues and Solutions

#### 1. NMAP Not Found

**Error:** `nmap: command not found`

**Solution:**
```bash
# Windows: Ensure NMAP is in PATH
set PATH=%PATH%;C:\Program Files (x86)\Nmap

# Linux: Install NMAP
sudo apt-get install nmap

# Verify installation
nmap --version
```

#### 2. Permission Denied (NMAP)

**Error:** `Permission denied when running NMAP scans`

**Solution:**
```bash
# Linux: Run with sudo
sudo python main.py -sn https://example.com

# Or grant capabilities
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/nmap
```

#### 2. Module Import Errors

**Error:** `ModuleNotFoundError: No module named 'xyz'`

**Solution:**
```bash
pip install -r requirements.txt --force-reinstall
```

---

## 🗺️ Roadmap

### Version 2.1 
- [ ] Add 10 more analysis modules
- [ ] JSON export format
- [ ] Scheduled scanning
- [ ] Email notifications
- [ ] Slack/Teams integration

---

## 📄 License

This project is licensed under the MIT License.

## 👤 Author

**Alien C00de**

- GitHub: [https://github.com/alien-c0de](https://github.com/alien-c0de)
- LinkedIn: [https://linkedin.com/in/santosh-susveerkar](https://linkedin.com/in/santosh-susveerkar/)
- Email: alien.c00de@gmail.com


---

## 🙏 Acknowledgments

Special thanks to:

- **NMAP** team for the incredible port scanning tool
- **OWASP** for security guidelines and best practices
- **VirusTotal** for malware detection API
- **Google DNS** for phishing protection
- All open-source contributors who made this possible
- The cybersecurity community for continuous feedback

---

## ⭐ Star History

If you find Web Matrix useful, please consider giving it a star! ⭐

[![Star History Chart](https://api.star-history.com/svg?repos=yourusername/web-matrix&type=Date)](https://star-history.com/#yourusername/web-matrix&Date)

---

## 📊 Statistics

![GitHub stars](https://img.shields.io/github/stars/yourusername/web-matrix?style=social)
![GitHub forks](https://img.shields.io/github/forks/yourusername/web-matrix?style=social)
![GitHub watchers](https://img.shields.io/github/watchers/yourusername/web-matrix?style=social)
![GitHub issues](https://img.shields.io/github/issues/yourusername/web-matrix)
![GitHub pull requests](https://img.shields.io/github/issues-pr/yourusername/web-matrix)

---

<div align="center">

**🕸️ Made with ❤️ for the Web Security Community**

[Documentation](https://github.com/alien-c0de/web-matrix/wiki) · [Report Bug](https://github.com/alien-c0de/web-matrix/issues) · [Request Feature](https://github.com/alien-c0de/web-matrix/issues) · [Discuss](https://github.com/alien-c0de/web-matrix/discussions)

**🚀 Happy Website Analysis! 🚀**

</div>