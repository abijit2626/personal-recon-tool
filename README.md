# Recon

A modular Bash-based reconnaissance framework for CTFs, Hack The Box, and penetration testing labs.

> ⚠️ This tool is intended for **authorized security testing, CTFs, labs, and educational purposes only.**

---

## Features

### Core Recon

- TCP service discovery (Nmap)
- Service version detection
- Ping reachability check
- HTTP header collection
- Website title extraction
- robots.txt retrieval
- WhatWeb fingerprinting
- Automatic timestamped output directories

---

### Optional Modules

- UDP Top-50 scan
- Nmap NSE vulnerability scan
- DNS reconnaissance
- Web screenshots
- Custom directory brute forcing

---

### Service Enumeration

Automatically performs additional enumeration based on detected services.

Supported services include:

- SMB
- FTP
- SSH
- SNMP
- MySQL
- Redis
- MongoDB
- RPC

---

### Web Recon

- Directory brute forcing
- Nikto
- SSL/TLS analysis
- URL collection
- HTML reporting

---

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/recon.git
cd recon
```

Run the installer:

```bash
chmod +x install.sh
./install.sh
```

---

## Usage

Basic scan:

```bash
recon scanme.nmap.org
```

Interactive shell:

```bash
recon
```

Example options:

```bash
recon --udp --vuln scanme.nmap.org
```

```bash
recon --dns example.com
```

---

## Output

Each scan creates its own timestamped directory.

Example:

```
recon_output/
└── recon_scanme_20260702_120000/
    ├── report.txt
    ├── report.html
    ├── scan.nmap
    ├── scan.xml
    ├── web/
    ├── dns/
    ├── screenshots/
    └── ...
```

---

## Requirements

Some features depend on external tools.

Examples include:

- nmap
- curl
- dig
- whatweb
- nikto
- ffuf
- gobuster
- feroxbuster
- sslscan
- gowitness
- aquatone
- enum4linux
- smbmap
- smbclient
- onesixtyone
- snmpwalk

Missing tools are skipped automatically.

---

## Disclaimer

This software is provided for educational purposes and authorized security assessments only.

The author is not responsible for misuse or damage caused by this tool.

Always obtain permission before scanning systems you do not own.

---

