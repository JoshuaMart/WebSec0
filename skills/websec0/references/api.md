# WebSec0 API reference

WebSec0's API is OpenAPI 3.0, spec-first. The single source of truth is
`api/openapi.yaml`, served live as JSON at `/api/v1/openapi.json`. This
file is the agent-facing distillation: enough to call the API correctly
without re-fetching the spec.

## Contents

- [Endpoints](#endpoints)
- [Async request-reply pattern](#async-request-reply-pattern)
- [Create a scan — POST /api/v1/scans](#create-a-scan)
- [Fetch a scan — GET /api/v1/scans/{guid}](#fetch-a-scan)
- [Stream events — SSE](#stream-events--sse)
- [Markdown report](#markdown-report)
- [SARIF report](#sarif-report)
- [Catalog — GET /api/v1/checks](#catalog)
- [Authentication](#authentication)
- [Rate limits](#rate-limits)
- [Error envelope](#error-envelope)
- [Finding schema](#finding-schema)

## Endpoints

```
POST   /api/v1/scans                  → 202, body {id, status, links}
GET    /api/v1/scans/{guid}           → 200 always, body with status
GET    /api/v1/scans/{guid}/events    → SSE (text/event-stream)
GET    /api/v1/scans/{guid}/markdown  → text/markdown; charset=utf-8
GET    /api/v1/scans/{guid}/sarif     → application/sarif+json
DELETE /api/v1/scans/{guid}           → 204 (private mode requires token)
GET    /api/v1/checks                 → catalog manifest
GET    /api/v1/checks/{check_id}      → check details
GET    /api/v1/health                 → 200, {status, uptime, version}
GET    /api/v1/version                → 200, {version, commit, build_date}
GET    /api/v1/openapi.json           → embedded OpenAPI spec
```

## Async request-reply pattern

A scan takes 30 s – 2 min. Holding a synchronous connection is an
anti-pattern (proxy timeouts, poor agent UX). The API follows
[Asynchronous Request-Reply](https://learn.microsoft.com/en-us/azure/architecture/patterns/async-request-reply):

1. **POST** `/api/v1/scans` returns `202 Accepted` immediately with
   `Location: /api/v1/scans/{guid}` and `Retry-After: 5`.
2. **Poll** `GET /api/v1/scans/{guid}` — always returns `200 OK` with a
   structured `status` field (`queued`, `running`, `completed`,
   `failed`).
3. Or **stream** progress via `GET /api/v1/scans/{guid}/events` (SSE).
4. Or **block synchronously** by passing `options.wait_seconds` (≤ 120 s)
   on the POST. If the scan exceeds the wait, the API falls back to
   async and returns the in-progress body.

## Create a scan

```http
POST /api/v1/scans
Content-Type: application/json

{
  "target": "example.com",
  "options": {
    "skip_categories": [],
    "private": false,
    "wait_seconds": 30
  }
}
```

`target` accepts a hostname or a full URL; the scheme is ignored
(WebSec0 always tests both HTTP and HTTPS). `wait_seconds` is the
synchronous wait window — 0 returns 202 immediately; up to 120 holds the
connection.

`options.private: true` mints a 256-bit token returned **once** in the
response body (`private_token`). Subsequent `GET`/`DELETE` requires that
token in the `Authorization: Bearer <token>` header.

```http
HTTP/1.1 202 Accepted
Location: /api/v1/scans/f3a1c2b8-9e4d-4f6a-bcde-0123456789ab
Retry-After: 5
Content-Type: application/json

{
  "id": "f3a1c2b8-9e4d-4f6a-bcde-0123456789ab",
  "status": "queued",
  "private_token": null,
  "links": {
    "self":     "/api/v1/scans/f3a1c2b8-…",
    "events":   "/api/v1/scans/f3a1c2b8-…/events",
    "markdown": "/api/v1/scans/f3a1c2b8-…/markdown",
    "sarif":    "/api/v1/scans/f3a1c2b8-…/sarif"
  }
}
```

## Fetch a scan

```http
GET /api/v1/scans/{guid}
```

Always `200 OK`. Read the `status` field to decide what to do next.

While running:

```json
{
  "id": "f3a1c2b8-…",
  "status": "running",
  "target": "example.com",
  "started_at": "2026-04-25T15:30:00Z",
  "progress": { "total": 126, "completed": 23, "current_phase": "headers" },
  "links": { "self": "…", "events": "…", "markdown": "…", "sarif": "…" }
}
```

Once completed, the body contains the full report (see [Finding
schema](#finding-schema) for the per-finding shape):

```json
{
  "id": "f3a1c2b8-…",
  "status": "completed",
  "schema_version": "1.0",
  "scan": { "target": "example.com", "duration_seconds": 102, "scanner_version": "0.1.0" },
  "summary": {
    "grade": "B+",
    "score": 82,
    "scores_per_family": { "tls": 95, "headers": 60, "cookies": 80, "dns": 90, "email": 75, "custom": 85 },
    "counts": { "critical": 0, "high": 2, "medium": 5, "low": 4, "info": 1, "passed": 58, "skipped": 0, "errored": 0 },
    "quick_wins": ["HEADER-CSP-MISSING", "TLS-HSTS-MISSING", "WELLKNOWN-SECURITY-TXT-MISSING"]
  },
  "findings": [ /* see Finding schema below */ ],
  "passed_checks": ["TLS-PROTOCOL-LEGACY-SSL3", "…"],
  "skipped_checks": [{ "id": "EMAIL-SPF-MISSING", "reason": "no MX record found" }],
  "tech_stack_detected": { "server": "nginx", "powered_by": null, "cms": null },
  "links": { /* … */ }
}
```

## Stream events — SSE

```http
GET /api/v1/scans/{guid}/events
Accept: text/event-stream
```

```
event: progress
id: 1
data: {"completed":1,"total":126,"current":"TLS-PROTOCOL-LEGACY-SSL3"}

event: finding
id: 2
data: {"id":"TLS-PROTOCOL-LEGACY-SSL3","status":"pass"}

event: completed
id: 127
data: {"grade":"B+","score":78}
```

`Last-Event-ID` is honoured for native `EventSource` reconnection.
`curl -N` works directly. Heartbeat every 15 s keeps proxies happy.

## Markdown report

```http
GET /api/v1/scans/{guid}/markdown
Accept: text/markdown
```

Returns `text/markdown; charset=utf-8`. Layout:

```markdown
# WebSec0 Scan Report — example.com
**Date**: 2026-04-25T15:30:00Z
**Grade**: B+ (82/100)

## Summary
| Severity | Count |
|---|--:|
| Critical | 0 |
| High | 2 |
…

## Quick wins
1. **HEADER-CSP-MISSING** — Add a Content-Security-Policy header.

## Findings
### TLS-PROTOCOL-LEGACY-TLS10 — TLS 1.0 is enabled
**Severity**: high · **Effort**: low · **Quick win**: yes
…
```

Designed for both human reading and direct LLM ingestion (no fluff,
copy-paste-ready remediation snippets per stack).

## SARIF report

```http
GET /api/v1/scans/{guid}/sarif
Accept: application/sarif+json
```

Returns SARIF 2.1.0. Severity mapping:

| WebSec0 severity   | SARIF level |
|--------------------|-------------|
| `critical`, `high` | `error`     |
| `medium`           | `warning`   |
| `low`, `info`      | `note`      |

Stack-specific snippets land under `runs[].results[].properties` (a
free-form bag, since SARIF locations expect file paths and we operate
on hostnames).

## Catalog

```http
GET /api/v1/checks                 → array of CheckMeta
GET /api/v1/checks/{check_id}      → single CheckMeta
```

`CheckMeta` shape:

```json
{
  "id": "TLS-PROTOCOL-LEGACY-TLS10",
  "family": "tls",
  "default_severity": "high",
  "title": "TLS 1.0 is disabled",
  "description": "TLS 1.0 (1999) was deprecated by RFC 8996…",
  "rfc_refs": ["RFC 8996"]
}
```

This is the manifest agents should load to know which IDs exist before
acting on a scan body. See `references/checks.md` for the family-grouped
summary.

## Authentication

- **Anonymous** access for the public endpoints. Rate-limited (10
  scans/h/IP, cooldown 5 min per target).
- **API key**: `Authorization: Bearer wsk_xxxxx` (env
  `WEBSEC0_API_KEY`). Higher quotas on the public instance.
- **Private scan token**: minted on `POST` with `options.private: true`.
  Returned **once** as `private_token`. Required for `GET`/`DELETE` of
  that scan. Send as `Authorization: Bearer <token>`.

## Rate limits

| Limit | Default | Override |
|---|---|---|
| Per-IP scans/hour | 10 (anon) / 100 (with key) | `Retry-After` header |
| Same target re-scan cooldown | 5 minutes | `?refresh=true` |
| Distinct targets per IP per 5 min | 5 (then 429 `abuse_flagged`) | n/a |

Honour `Retry-After`. Do not retry tighter.

## Error envelope

All non-2xx responses share one shape:

```json
{
  "code": "target_blocked",
  "message": "private IP range",
  "details": { "ip": "10.0.0.1" }
}
```

| HTTP | code               | Reason                                                |
|------|--------------------|-------------------------------------------------------|
| 422  | `target_blocked`   | Resolves to a forbidden IP range (anti-SSRF)          |
| 451  | `domain_blocklist` | Matches the policy blocklist (`.gov`, `.mil`, …)      |
| 429  | `rate_limited`     | Per-IP rate limit hit                                 |
| 429  | `cooldown`         | Same target re-scanned too soon                       |
| 429  | `abuse_flagged`    | Pattern abuse (>5 distinct targets in 5 min)          |
| 404  | `scan_not_found`   | Unknown GUID                                          |
| 401  | `invalid_token`    | Bearer token mismatch                                 |
| 501  | `not_implemented`  | Stub endpoint (transitional, MVP)                     |

## Finding schema

Every finding in `findings[]` has this shape (excerpt):

```json
{
  "id": "TLS-PROTOCOL-LEGACY-TLS10",
  "title": "TLS 1.0 is enabled",
  "severity": "high",
  "confidence": "high",
  "effort": "low",
  "is_quick_win": true,
  "category": "tls",
  "subcategory": "protocol",
  "status": "fail",
  "cwe": ["CWE-326"],
  "cvss": {
    "version": "3.1",
    "score": 5.9,
    "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
  },
  "description": {
    "short": "Server accepts TLS 1.0, deprecated by RFC 8996.",
    "long":  "TLS 1.0 was published in 1999 and contains structural cryptographic weaknesses (BEAST). Formally deprecated by IETF RFC 8996 in March 2021…"
  },
  "impact": {
    "cia": ["confidentiality", "integrity"],
    "summary": "An attacker capable of MitM may force clients to negotiate weak ciphers via downgrade…"
  },
  "evidence": {
    "observed": { "protocols_enabled": ["TLSv1.0", "TLSv1.2", "TLSv1.3"] },
    "expected": { "protocols_enabled": ["TLSv1.2", "TLSv1.3"] },
    "raw_excerpt": "ServerHello version: 0x0301 (TLSv1.0)"
  },
  "remediation": {
    "summary": "Disable TLS 1.0 and TLS 1.1; require TLS 1.2 minimum.",
    "steps": [ "Identify the TLS termination layer", "Set minimum TLS version to 1.2", "Reload and re-scan" ],
    "snippets": {
      "nginx":      "ssl_protocols TLSv1.2 TLSv1.3;",
      "apache":     "SSLProtocol -all +TLSv1.2 +TLSv1.3",
      "caddy":      "tls {\n  protocols tls1.2 tls1.3\n}",
      "haproxy":    "ssl-min-ver TLSv1.2",
      "cloudflare_dashboard": "SSL/TLS → Edge Certificates → Minimum TLS Version → TLS 1.2",
      "spring_boot":"server.ssl.enabled-protocols=TLSv1.2,TLSv1.3",
      "iis_web_config": "Disable via Registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server → Enabled=0"
    },
    "verification": "curl -sI --tls-max 1.0 https://example.com  # expect connection failure"
  },
  "references": [
    { "title": "RFC 8996",                        "url": "https://www.rfc-editor.org/rfc/rfc8996",      "type": "rfc" },
    { "title": "Mozilla SSL Configuration Generator", "url": "https://ssl-config.mozilla.org/",         "type": "tool" }
  ],
  "tags": ["tls", "crypto", "deprecated", "rfc8996"]
}
```

Use `remediation.snippets[<stack>]` to apply the fix. The stack key
vocabulary is documented in `references/stacks.md`.
