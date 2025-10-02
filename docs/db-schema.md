# MongoDB Schema

This document captures the baseline structure for the automation datastore. All timestamps
use ISO 8601 strings (UTC) and documents include a standard metadata envelope:

```
{
  "createdAt": "2025-10-01T12:00:00.000Z",
  "updatedAt": "2025-10-01T12:00:00.000Z",
  "tags": ["bugcrowd", "high-priority"]
}
```

## Collections

### `targets`
| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `_id` | ObjectId | Yes | Auto-generated |
| `program` | string | Yes | Bug bounty program identifier (e.g., `bugcrowd:acme`) |
| `source` | string | Yes | `bugcrowd`, `hackerone`, `intigriti`, `manual`, etc. |
| `asset` | object | Yes | Normalized target descriptor |
| `asset.type` | string | Yes | `domain`, `cidr`, `ip`, `hostname`, `url` |
| `asset.value` | string | Yes | Canonical value |
| `asset.scope` | string | No | `in-scope`, `out-of-scope`, `testing` |
| `firstSeen` | string (date) | Yes | When target first ingested |
| `lastSeen` | string (date) | Yes | Last successful scope refresh |
| `status` | string | Yes | `active`, `snoozed`, `retired` |
| `notes` | string | No | Analyst comments |
| `metadata` | object | No | Arbitrary additional attributes |

Indexes: `program + asset.value` (unique), `status`, `lastSeen`.

### `recon_results`
| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `_id` | ObjectId | Yes | |
| `targetId` | ObjectId | Yes | Reference to `targets._id` |
| `subdomain` | string | No | Populated for domain assets |
| `ip` | string | No | IPv4/IPv6 |
| `ports` | array<object> | No | Open ports/services |
| `ports[].port` | number | Yes | |
| `ports[].protocol` | string | Yes | `tcp` or `udp` |
| `ports[].service` | string | No | `http`, `https`, etc. |
| `tech` | array<object> | No | Fingerprinted tech stack |
| `tech[].name` | string | Yes | |
| `tech[].version` | string | No | Semantic version where available |
| `fingerprints` | object | No | Raw data (whatweb headers, TLS info, etc.) |
| `sources` | array<object> | Yes | Recon provenance |
| `sources[].tool` | string | Yes | e.g., `amass`, `httpx` |
| `sources[].runId` | string | Yes | Link to job run |
| `isAlive` | boolean | Yes | HTTP reachability |
| `lastChecked` | string (date) | Yes | |

Indexes: `targetId`, `subdomain`, compound `ip + ports.port`.

### `vulnerabilities`
| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `_id` | ObjectId | Yes | |
| `reconId` | ObjectId | Yes | Reference to `recon_results._id` |
| `source` | string | Yes | `nuclei`, `manual`, etc. |
| `scannerFindingId` | string | No | Raw ID/external reference |
| `title` | string | Yes | Short descriptor |
| `severity` | string | Yes | `critical`, `high`, `medium`, `low`, `info` |
| `confidence` | string | Yes | `confirmed`, `suspected`, `needs-review` |
| `category` | string | No | OWASP category, CWE ID, etc. |
| `description` | string | No | Summary of finding |
| `evidence` | object | No | Request/response, screenshots, CVE matches |
| `cves` | array<object> | No | NVD cross-references |
| `cves[].id` | string | Yes | |
| `cves[].cvss` | object | No | CVSS metrics |
| `remediation` | string | No | Fix guidance |
| `status` | string | Yes | `open`, `triaged`, `mitigated`, `closed` |
| `reportedAt` | string (date) | No | When submitted to platform |
| `resolvedAt` | string (date) | No | Closure timestamp |

Indexes: `severity`, `status`, `reconId`, text index on `title/description`.

### `reports`
| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `_id` | ObjectId | Yes | |
| `program` | string | Yes | Matches `targets.program` |
| `vulnIds` | array<ObjectId> | Yes | Linked vulnerability documents |
| `reportId` | string | No | External platform identifier |
| `status` | string | Yes | `draft`, `submitted`, `triaged`, `resolved`, `duplicated` |
| `payout` | object | No | `{ currency: 'USD', amount: 0 }` |
| `content` | object | Yes | Markdown body fragments |
| `content.title` | string | Yes | |
| `content.body` | string | Yes | Markdown |
| `submittedAt` | string (date) | No | |
| `updatedBy` | string | No | Analyst user ID |

Indexes: `program`, `status`, `reportId`.

### `job_runs`
Tracks workflow executions and tooling runs.

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `_id` | ObjectId | Yes | |
| `workflow` | string | Yes | e.g., `scope-intake`, `recon-drone` |
| `trigger` | string | Yes | `cron`, `manual`, `webhook` |
| `status` | string | Yes | `queued`, `running`, `success`, `failed` |
| `startedAt` | string (date) | Yes | |
| `finishedAt` | string (date) | No | |
| `durationMs` | number | No | Convenience metric |
| `error` | object | No | `{ message, stack, nodeId }` |
| `stats` | object | No | Arbitrary counters per run |
| `artifacts` | array<object> | No | Paths to raw files stored locally |

Indexes: `workflow + startedAt`, `status`.

## Naming Conventions
- Use lowerCamelCase for field names.
- Store arrays even for single values (e.g., `tech`, `cves`) to simplify aggregations.
- Attach provenance to every document via `sources` arrays where possible.

## Validation Strategy
- Zod schemas in `src/schemas/` mirror the structures above.
- Use `parse()` when inserting new documents via custom scripts.
- In n8n, run the schema helper via Function nodes (using the compiled JS in `dist/`).
