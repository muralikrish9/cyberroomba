# Part 4 – Vulnerability Scanner & CVE Matching

Goal: automatically scan alive hosts discovered by Part 3, parse scanner output, correlate with
CVE data (NVD feed), and persist structured findings into MongoDB. High-level steps:

1. **Job Trigger** – Cron/Manual. Create a `job_runs` entry with workflow `vuln-scanner`.
2. **Fetch Alive Hosts** – Query `recon_results` where `isAlive = true` and `lastScanAt` older than SLA.
3. **Prepare Host Batch** – Build host lists for nuclei/nmap/ffuf, store under `data/vuln/raw/<jobId>/`.
4. **Run Scanners**:
   - CLI: `nuclei` (standard + custom templates).
   - Optional: `nmap --script vuln`, `ffuf`, `gobuster`, `masscan` follow-ups.
   - For web hosts, re-run `httpx` with JSON to capture responses for evidence.
5. **Parse Results** – Function node loads raw JSON, uses `src/vuln/parse.ts` to normalize findings
   into `Vulnerability` documents (severity, references, request/response data).
6. **CVE Matching** – A helper ingests the local NVD JSON (downloaded via curl) and produces a
   lookup keyed on product + version. Findings with tech fingerprints from recon get enriched by
   `src/vuln/matcher.ts` to add `cves[]` with CVSS scores and match confidence.
7. **Persist** – Insert documents into `vulnerabilities` collection, update related
   `recon_results` (e.g., `lastScanAt`, `vulnCount`), update `job_runs` stats.
8. **Alerts/Artifacts** – Attach high severity findings to future Discord alerts (Part 5) and archive
   raw scanner outputs under `data/vuln/raw/` for auditing.

Fixtures & Tests
- `config/mock-vuln/nuclei.json` – sample nuclei output
- `config/mock-vuln/nmap.json` – trimmed NSE results
- `config/mock-vuln/nvd.json` – minimal CVE feed snippet
- `npm run vuln:fixtures` – builds helper code and validates parsing + matching.

Upcoming tasks in this part:
- Implement TypeScript helpers (`src/vuln/parse.ts`, `src/vuln/matcher.ts`).
- Add n8n workflow `part4-vuln-scanner.json` with Execute Command nodes and Function nodes.
- Extend schema usage: ensure `Vulnerability` docs include metadata, CVE matches, severity.

This sets the stage for Part 5 (alerts/reporting) by delivering normalized findings ready for
notification and report drafting.
