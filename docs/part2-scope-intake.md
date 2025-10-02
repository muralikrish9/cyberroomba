# Part 2 – Scope Intake Workflow

This workflow runs on a scheduled trigger, pulls scope from Bugcrowd, HackerOne, and Intigriti,
normalizes every asset using the parsers in `src/scope/parsers.ts`, deduplicates against MongoDB,
and stores new targets alongside their raw payloads for audit.

## High-Level Flow
1. **Cron Trigger** – fires daily at 08:00 UTC (adjust in the Cron node).
2. **HTTP Request (Bugcrowd)** – GET to the public programs endpoint; response body is forwarded.
3. **HTTP Request (HackerOne)** – GET `https://hackerone.com/programs.json` with browser-like headers.
4. **HTTP Request (Intigriti)** – GET `https://api.intigriti.com/core/programs` or fallback feed.
5. **Function Node: `Normalize Scope`** – imports the compiled parser bundle and calls
   `normalizeAllPlatforms` to transform raw payloads into the schema-friendly target list.
6. **Function Node: `Split New Targets`** – checks MongoDB for existing `program + asset.value`
   combinations and emits only unseen assets. Also attaches a `jobRunId` for traceability.
7. **MongoDB Node: `Insert Targets`** – bulk inserts documents into the `targets` collection.
8. **Binary / File Node: `Archive Payload`** – writes the original API responses to
   `data/raw-scope/<platform>/<timestamp>.json` for later review.
9. **Final Notification** – optional Slack/Discord message summarising counts (hooked up later).

## Required Environment Variables
- `MONGODB_URI`, `MONGODB_DB_NAME`
- `N8N_ENCRYPTION_KEY` (for credential store)
- Any future platform credentials (currently all three feeds are public)

## Parser Integration
1. Build the TypeScript helpers:
   ```bash
   npm run build
   ```
2. Mount the `dist` folder into the n8n container (already handled by `docker-compose.yml`).
3. In the `Normalize Scope` Function node, use:
   ```javascript
   const { normalizeAllPlatforms } = require('/data/dist/scope/parsers.js');
   const bugcrowd = items[0].json.bugcrowd;
   // ... gather other payloads ...
   return normalizeAllPlatforms({ bugcrowd, hackerone, intigriti }).map((target) => ({ json: target }));
   ```

## Deduplication Strategy
- Unique key: `${program}:${asset.value}`.
- Mongo query: `findOne({ program, 'asset.value': value })`.
- Only insert when not found; update `lastSeen` separately (Part 3 when recon runs).

## Raw Payload Archival
- Configure Binary Data node to write to `data/raw-scope/<platform>/<ISO8601>.json`.
- Directory is gitignored (see `.gitignore`).
- Store metadata in `job_runs` via a separate MongoDB node for observability.

## Rate Limiting & Retries
- Add 2s wait (`Wait` node) between platform calls to avoid throttling.
- HTTP Request nodes configured with `Max Attempts = 3` and `Retry Delay = 2000ms`.

## Testing With Fixtures
- Run `npm run scope:fixtures` to validate parser logic against the mock data under
  `config/mock-scope/` before hitting live endpoints.
- `Normalize Scope` node can temporarily load fixtures by pointing the HTTP nodes to
  `file://` URLs or by injecting fixture JSON via a Set node.

## Next Steps
- Wire up Discord notifications when `Insert Targets` writes new assets.
- Enrich `job_runs` with per-platform fetch metrics.
- Expand the parser to ingest additional optional feeds (e.g., YesWeHack) without modifying the workflow.
