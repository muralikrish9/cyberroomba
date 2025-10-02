# Part 0 – Environment & Secrets Readiness

## Secrets & Credentials
- SecurityTrails API key stored in local .env.local
- AlienVault OTX key stored in local .env.local
- ZoomEye API key stored in local .env.local
- Discord webhook URL stored in local .env.local
- Rapid7 Sonar HTTP dataset URL referenced in local .env.local
- MongoDB connection string set to mongodb://localhost:27017/cyberroomba

> All sensitive values live only in .env.local, which is ignored via .gitignore.

## Tooling Installed (Local Paths)
- C:\Tools\bin\amass.exe (v5.0.0)
- C:\Tools\bin\masscan.exe (v1.3.1 community Windows build)
- C:\Tools\bin\nuclei.exe (v3.4.10)
- C:\Program Files (x86)\Nmap\nmap.exe (v7.80 w/ Npcap)
- C:\Tools\bin\whatweb.bat wrapper → uby + cloned WhatWeb repo
- C:\Tools\bin\whois.exe (Sysinternals 1.21)

## Runtime Environment
- Hardware: AMD Ryzen 7 9800X3D (8 cores / 32 GB RAM)
- Disk: ~1.2 TB free on C: — sufficient for MongoDB data + recon artifacts
- MongoDB Community Server 8.2 service running locally
- RubyInstaller 3.3 (w/ MSYS2 devkit) for WhatWeb dependencies
- Docker Desktop installed (available for future containerized tooling)

## Data & Storage Choices
- MongoDB will run locally (cyberroomba database)
- Recon/raw artifacts to be stored on local disk under project-specific folders (to define in Part 1)
- Git repository cyberroomba cloned locally (currently empty scaffold)

## Outstanding Decisions for Part 1
- Confirm directory layout for storing recon outputs and logs
- Decide on preferred secrets-loading mechanism for n8n (env vars vs. credentials store)
- Establish initial program allow-list / rate limits to encode in workflows
- Determine GitHub PAT usage for report commits (optional)

With these prerequisites captured, the workspace is ready to move into Part 1 (project scaffold & schema).
