# Part 3 – Recon Drone Workflow

This stage orchestrates discovery and enrichment for every target the scope pipeline produces.
It pulls active targets, runs subdomain/port/tech tooling, merges results, and persists a clean
record in MongoDB while archiving raw command output for later review.

## High-Level Flow
1. **Trigger** – Cron (hourly) or manual. Workflow logs a new job in `job_runs` with status `running`.
2. **Fetch Targets** – MongoDB aggregation:
   - Query `targets` where `status = active` and either `lastReconAt` missing or older than 24h.
   - Limit batch size (default 20) to respect API/tool rate limits.
3. **For Each Target** (Split In Batches node):
   - `Execute Command: subfinder` (JSON output) ➜ store binary file.
   - `Execute Command: amass` (JSON output) ➜ store binary.
   - Merge + dedup subdomains (Function node) ➜ enumerate unique hostnames.
   - `Execute Command: httpx` against merged hosts for liveness + tech fingerprints.
   - `Execute Command: masscan` (optional, only for CIDR/IP assets).
   - `Execute Command: nmap` (top ports) for new live IPs.
   - `Execute Command: whatweb` for HTML tech hints (targeted at alive hosts).
   - API enrichment:
     - HTTP Request → SecurityTrails (pass API key from env).
     - HTTP Request → OTX, ZoomEye (ZoomEye requires queries per host).
   - Merge everything via Function node using helpers from `src/recon/normalize.ts`.
   - Persist raw JSON to `data/recon/raw/<jobId>/<tool>/<target>.json`.
4. **Store Results**
   - MongoDB `recon_results.insertMany` with normalized documents.
   - MongoDB `targets.updateOne` to set `lastReconAt`, `lastSeen`, and track latest job ID.
   - Update `job_runs` stats (counts for hosts enumerated, live hosts, services).
5. **Finalize Job** – If all batches succeed set job status `success`, otherwise flag `failed` with error detail; optional Discord notification for failures.

## Tooling References
- CLI binaries assumed on PATH via `C:\Tools\bin`.
- Commands built by helper functions in `src/recon/commands.ts`.
- Output parsers live in `src/recon/normalize.ts`.

## Environment Variables Needed
- `SECURITYTRAILS_API_KEY`
- `ALIENVAULT_OTX_KEY`
- `ZOOMEYE_API_KEY`
- `RAPID7_SONAR_HTTP_DATASET` (optional fallback dataset path)
- `RECON_RAW_DIR` (defaults to `data/recon/raw`)

## Error Handling
- Each Execute Command node has retries (up to 2) and 60s timeout.
- Failures route to a side branch that logs error details in `job_runs.error` and continues with next target (to avoid aborting entire batch).

## Testing With Fixtures
- `config/mock-recon/` contains trimmed outputs from subfinder, amass, httpx, SecurityTrails.
- Run `npm run recon:fixtures` to ensure parsers produce a valid `ReconResult` document before committing workflow changes.

## Future Enhancements
- Integrate DNS resolvers (dnsx) and IP geolocation.
- Allow per-program tool toggles (e.g., skip masscan on restricted programs).
- Add caching for API responses to respect rate limits.
- Emit metrics (duration per tool, success rate) to a dashboard once Grafana is in place.
