# CyberRoomba 🚀

**Automated Bug Bounty Reconnaissance & Attack Platform**

CyberRoomba is a powerful, parallel-processing bug bounty automation platform that combines reconnaissance, vulnerability scanning, and attack execution in a single, scalable system. Built with TypeScript and MongoDB, it's designed for professional bug bounty hunters and security researchers.

## 🌟 Features

### 🎯 **5-Stage Pipeline**
1. **Scope Intake** - Automated collection from Bugcrowd, HackerOne, Intigriti
2. **Reconnaissance** - Parallel subdomain discovery and technology detection
3. **Vulnerability Scanning** - Nuclei-based vulnerability assessment
4. **Attack Execution** - Multi-vector attack testing with Nuclei templates
5. **Reporting & Alerts** - Discord notifications and structured reports

### ⚡ **Parallel Processing**
- **Reconnaissance**: 15 concurrent workers
- **Attacks**: 20 concurrent workers
- **Real-time progress tracking**
- **Resource-aware scaling**

### 🔧 **Security Tools Integration**
- **Subfinder** - Subdomain discovery
- **Httpx** - HTTP probing and technology detection
- **Nuclei** - Vulnerability scanning and attack templates
- **MongoDB** - Data persistence and analysis

### 📊 **Attack Vectors**
- **General Attacks** - Comprehensive vulnerability scanning
- **XSS Attacks** - Cross-site scripting detection
- **Path Discovery** - Directory and file enumeration
- **Authentication Bypass** - Auth vulnerability testing
- **SSRF/XXE** - Server-side request forgery and XML external entity
- **Injection Attacks** - SQL, NoSQL, LDAP, Command injection

## 🚀 Quick Start

### Prerequisites

1. **Node.js 18+** and npm
2. **MongoDB** (local or cloud)
3. **Security Tools** (see [TOOLS_SETUP.md](TOOLS_SETUP.md))

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd cyberroomba

# Install dependencies
npm install

# Build the project
npm run build

# Set up environment variables
cp .env.example .env.local
# Edit .env.local with your configuration
```

### Environment Configuration

Create `.env.local` with:

```env
# MongoDB
MONGODB_URI=mongodb://127.0.0.1:27017/cyberroomba

# Bug Bounty Platform APIs (optional)
BUGCROWD_API_KEY=your_bugcrowd_key
HACKERONE_API_KEY=your_hackerone_key
INTIGRITI_API_KEY=your_intigriti_key

# Discord Webhooks (optional)
DISCORD_WEBHOOK_REPORTS=https://discord.com/api/webhooks/...
DISCORD_WEBHOOK_LOW=https://discord.com/api/webhooks/...
DISCORD_WEBHOOK_MEDIUM=https://discord.com/api/webhooks/...
DISCORD_WEBHOOK_HIGH=https://discord.com/api/webhooks/...
```

## 🎮 Usage

### Individual Pipeline Stages

```bash
# 1. Scope Intake - Collect bug bounty targets
npm run scope:run

# 2. Reconnaissance - Discover subdomains and technologies
npm run recon:run

# 3. Vulnerability Scanning - Scan for vulnerabilities
npm run vuln:run

# 4. Attack Execution - Launch attack campaigns
npm run attacks:run

# 5. Report Generation - Generate reports and notifications
npm run reports:run
```

### Full Pipeline Execution

```bash
# Run complete pipeline
npm run pipeline:run
```

### Development

```bash
# Build TypeScript
npm run build

# Run fixtures check
npm run fixtures:check
```

## 📁 Project Structure

```
cyberroomba/
├── src/
│   ├── cli/           # Command-line interfaces
│   ├── lib/           # Core libraries
│   ├── recon/         # Reconnaissance modules
│   ├── scope/         # Scope intake modules
│   ├── schemas/       # MongoDB schemas
│   └── vuln/          # Vulnerability modules
├── data/              # Raw data storage
├── dist/              # Compiled JavaScript
├── docs/              # Documentation
├── workflows/         # n8n workflow definitions
└── config/            # Configuration files
```

## 🔧 Configuration

### Tool Paths

The system automatically detects installed tools. Ensure these are in your PATH:

- `subfinder` - Subdomain enumeration
- `httpx` - HTTP probing
- `nuclei` - Vulnerability scanning

### Parallel Processing Tuning

The system automatically scales based on your hardware:

- **Reconnaissance**: `CPU cores` workers (max 15)
- **Attacks**: `CPU cores * 2` workers (max 20)

## 📊 Data Storage

### MongoDB Collections

- **targets** - Bug bounty program targets
- **recon_results** - Reconnaissance findings
- **vulnerabilities** - Discovered vulnerabilities
- **reports** - Generated reports
- **job_runs** - Execution history

### File System

- **Raw Data**: `data/*/raw/` - Tool output files
- **Reports**: `data/reports/` - Generated reports
- **Logs**: Console output with real-time progress

## 🚨 Discord Integration

Set up Discord webhooks for real-time notifications:

1. Create Discord channels for different severity levels
2. Generate webhook URLs for each channel
3. Configure in `.env.local`
4. Receive live notifications during execution

See [discord-setup.md](discord-setup.md) for detailed setup instructions.

## 🛡️ Security Considerations

- **Rate Limiting**: Built-in rate limiting for API calls
- **Error Handling**: Graceful failure handling
- **Data Sanitization**: Input validation and sanitization
- **Resource Management**: CPU and memory monitoring
- **Logging**: Comprehensive audit trails

## 🔍 Monitoring & Debugging

### Real-time Progress

All commands provide live progress updates:

```
📊 Parallel Recon Progress: 45/100 targets completed (1,247 total hosts discovered)
📊 Parallel Progress: 67/100 hosts completed (0 successful attacks)
```

### Database Queries

Use MongoDB queries to analyze results:

```javascript
// Count total vulnerabilities by severity
db.vulnerabilities.aggregate([
  { $group: { _id: "$severity", count: { $sum: 1 } } }
])

// Get recent job runs
db.job_runs.find().sort({ createdAt: -1 }).limit(10)
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is for educational and authorized testing purposes only. Users are responsible for ensuring they have proper authorization before testing any systems. The authors are not responsible for any misuse or damage caused by this tool.

## 🆘 Support

- **Documentation**: Check the `docs/` directory
- **Issues**: Open an issue on GitHub
- **Discord**: Join our community (if applicable)

## 🎯 Roadmap

- [ ] Additional bug bounty platforms
- [ ] Custom attack template support
- [ ] Web dashboard
- [ ] API integration
- [ ] Cloud deployment options
- [ ] Advanced reporting features

---

