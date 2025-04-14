# Golden Web Vulnerability Scanner - Ultimate Edition V1.0

![Golden Scanner Banner](https://i.imgur.com/example.png)

A powerful web vulnerability scanner with stealth capabilities for comprehensive security assessments.

**Developer**: ✨آلَمًهّيَبً✨  
**TikTok**: [m_m_h_b1](https://www.tiktok.com/@m_m_h_b1)  
**Telegram**: [@GUP_89](https://t.me/GUP_89)

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Scanning Options](#scanning-options)
- [Examples](#examples)
- [Requirements](#requirements)
- [Disclaimer](#disclaimer)
- [License](#license)

## Features

- **Comprehensive Scanning**: Multiple scanning techniques in one tool
- **Stealth Mode**: Randomized delays and headers to avoid detection
- **Admin Page Discovery**: Advanced detection of admin interfaces (200+ common paths)
- **Vulnerability Detection**: XSS, SQLi, LFI, RCE, IDOR, XXE, SSRF, CSRF
- **Technology Identification**: Detect CMS, frameworks, and server technologies
- **Port Scanning**: Check for common open ports
- **DNS Reconnaissance**: Gather DNS records about the target
- **Email Extraction**: Find email addresses in website content
- **Security Headers Check**: Verify important security headers
- **Comprehensive Reports**: JSON output with all findings

## Installation

1. Clone the repository:
```bash
https://github.com/HN1A/Web_Researcher.git
cd Web_Researcher
```
2. Install requirements:
```bash
pip install -r requirements.txt
```
3. Running the tool
```
python Golden_Scanner.py
```
## Usage

Basic command:
```bash
python Golden_Scanner.py -u https://example.com
```

Advanced options:
```bash
python Golden_Scanner.py -u https://example.com --stealth -w custom_wordlist.txt -o scan_results.json
```
## Examples


2. Full stealth scan with custom wordlist:
```bash
python Golden_Scanner.py -u https://example.com --stealth -w wordlist.txt
```

3. Fast scan (no delays):
```bash
python Golden_Scanner.py -u https://example.com --fast
```

