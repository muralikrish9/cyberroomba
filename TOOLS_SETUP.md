# 🔧 Required Tools Setup

To see live reconnaissance and vulnerability scanning, you need to install these tools:

## 🛠️ Reconnaissance Tools

### 1. Subfinder
```bash
# Install via Go
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Or download binary from GitHub
# https://github.com/projectdiscovery/subfinder/releases
```

### 2. Amass
```bash
# Install via Go
go install -v github.com/owasp-amass/amass/v4/...@master

# Or download binary from GitHub
# https://github.com/owasp-amass/amass/releases
```

### 3. httpx
```bash
# Install via Go
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Or download binary from GitHub
# https://github.com/projectdiscovery/httpx/releases
```

## 🚨 Vulnerability Scanning Tools

### 4. Nuclei
```bash
# Install via Go
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Or download binary from GitHub
# https://github.com/projectdiscovery/nuclei/releases
```

### 5. Nmap
```bash
# Windows (via Chocolatey)
choco install nmap

# Or download from official site
# https://nmap.org/download.html
```

## ⚔️ Attack Tools (Nuclei Templates)

### 6. Nuclei Templates (For Attacks)
```bash
# Nuclei is already installed from vulnerability scanning
# Update templates to latest version
nuclei -update-templates

# Verify templates are installed
ls nuclei-templates/
```

**Nuclei templates include:**
- **SQL Injection attacks** (vulnerabilities/sql/)
- **XSS attacks** (vulnerabilities/xss/)
- **Authentication bypass** (vulnerabilities/auth/)
- **Path discovery** (exposures/)
- **Default credentials** (vulnerabilities/default-login/)
- **And 5000+ more attack templates!**

## ✅ Verify Installation

Run these commands to verify tools are installed:

```bash
# Reconnaissance tools
subfinder -version
amass version
httpx -version

# Vulnerability scanning tools
nuclei -version
nmap --version

# Attack tools (Nuclei templates)
nuclei -version
ls nuclei-templates/ | head -10
```

## 🎯 What You'll See

With these tools installed, when you run:

- `npm run recon:run` - You'll see live subdomain discovery, HTTP probing, and tech detection
- `npm run vuln:run` - You'll see live vulnerability scanning with Nuclei and Nmap
- `npm run attacks:run` - You'll see live Nuclei attack templates including SQL injection, XSS, auth bypass, and path discovery

## 📁 Output Files

All tool outputs are saved to:
- `data/recon/raw/[job-id]/` - Reconnaissance results
- `data/vuln/raw/[job-id]/` - Vulnerability scan results
