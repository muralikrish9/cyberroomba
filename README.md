# CyberRoomba

Automated bug bounty reconnaissance and attack platform for security researchers.

## Overview

CyberRoomba is a TypeScript-based automation tool that streamlines the bug bounty process through a 5-stage pipeline: scope collection, reconnaissance, vulnerability scanning, attack execution, and reporting. It uses parallel processing to handle large target lists efficiently.

## Features

- **Automated Scope Collection**: Pulls targets from Bugcrowd, HackerOne, and Intigriti APIs
- **Parallel Reconnaissance**: Subdomain discovery and technology detection using Subfinder and Httpx
- **Vulnerability Scanning**: Nuclei-based scanning for common vulnerabilities
- **Attack Execution**: Multi-vector attack testing using Nuclei templates
- **Real-time Notifications**: Discord webhook integration for live updates
- **MongoDB Storage**: Structured data persistence and analysis

## Installation

### Prerequisites

- Node.js 18+
- MongoDB
- Security tools: Subfinder, Httpx, Nuclei

### Setup

```bash
# Clone and install
git clone https://github.com/muralikrish9/cyberroomba.git
cd cyberroomba
npm install
npm run build

# Configure environment
cp env.example .env.local
# Edit .env.local with your settings
```

### Required Tools

Install the security tools:

```bash
# Install tools (see TOOLS_SETUP.md for detailed instructions)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Update Nuclei templates
nuclei -update-templates
```

## Configuration

Create `.env.local`:

```env
# MongoDB
MONGODB_URI=mongodb://127.0.0.1:27017/cyberroomba

# API Keys (optional)
BUGCROWD_API_KEY=your_key
HACKERONE_API_KEY=your_key
INTIGRITI_API_KEY=your_key

# Discord Webhooks (optional)
DISCORD_WEBHOOK_REPORTS=https://discord.com/api/webhooks/...
DISCORD_WEBHOOK_LOW=https://discord.com/api/webhooks/...
DISCORD_WEBHOOK_MEDIUM=https://discord.com/api/webhooks/...
DISCORD_WEBHOOK_HIGH=https://discord.com/api/webhooks/...
```

## Usage

### Individual Stages

```bash
# Collect bug bounty targets
npm run scope:run

# Run reconnaissance
npm run recon:run

# Scan for vulnerabilities
npm run vuln:run

# Execute attacks
npm run attacks:run

# Generate reports
npm run reports:run
```

### Full Pipeline

```bash
# Run complete pipeline
npm run pipeline:run
```

## Architecture

### Pipeline Stages

1. **Scope Intake**: Collects and normalizes targets from bug bounty platforms
2. **Reconnaissance**: Discovers subdomains and detects technologies
3. **Vulnerability Scanning**: Scans for common vulnerabilities using Nuclei
4. **Attack Execution**: Performs targeted attacks using Nuclei templates
5. **Reporting**: Generates reports and sends notifications

### Parallel Processing

- **Reconnaissance**: Up to 15 concurrent workers
- **Attacks**: Up to 20 concurrent workers
- Automatic scaling based on system resources

### Attack Vectors

- General vulnerability scanning
- XSS detection and exploitation
- Directory and file enumeration
- Authentication bypass testing
- SSRF and XXE testing
- SQL, NoSQL, and command injection

## Data Storage

### MongoDB Collections

- `targets`: Bug bounty program targets
- `recon_results`: Reconnaissance findings
- `vulnerabilities`: Discovered vulnerabilities
- `reports`: Generated reports
- `job_runs`: Execution history

### File System

- Raw tool outputs: `data/*/raw/`
- Generated reports: `data/reports/`

## Discord Integration

Set up Discord webhooks for real-time notifications:

1. Create Discord channels for different severity levels
2. Generate webhook URLs for each channel
3. Configure webhook URLs in `.env.local`
4. Receive live notifications during execution

See `discord-setup.md` for detailed setup instructions.

## Development

```bash
# Build TypeScript
npm run build

# Run fixture checks
npm run fixtures:check
```

## Project Structure

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
├── docs/              # Documentation
└── workflows/         # n8n workflow definitions
```

## Monitoring

### Progress Tracking

All commands provide real-time progress updates:

```
Parallel Recon Progress: 45/100 targets completed (1,247 total hosts discovered)
Parallel Progress: 67/100 hosts completed (0 successful attacks)
```

### Database Analysis

Query MongoDB for analysis:

```javascript
// Count vulnerabilities by severity
db.vulnerabilities.aggregate([
  { $group: { _id: "$severity", count: { $sum: 1 } } }
])
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

See `CONTRIBUTING.md` for detailed guidelines.

## License

MIT License - see `LICENSE` file for details.

## Disclaimer

This tool is for educational and authorized testing purposes only. Users must ensure they have proper authorization before testing any systems. The authors are not responsible for any misuse or damage caused by this tool.

## Support

- Check the `docs/` directory for documentation
- Open an issue on GitHub for bugs or feature requests

## Roadmap

- Additional bug bounty platform integrations
- Custom attack template support
- Web dashboard interface
- Enhanced reporting features
- Docker containerization