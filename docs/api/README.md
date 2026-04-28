# API documentation

WebSec0 is **OpenAPI 3.0 spec-first**. The single source of truth is
[`api/openapi.yaml`](../../api/openapi.yaml). This page describes how to
read it, how to call the API, and how to import a typed Go client.

## Browse the spec

| Format | Where |
|---|---|
| YAML source | [`api/openapi.yaml`](../../api/openapi.yaml) |
| JSON, served live | `GET /api/v1/openapi.json` |
| Interactive UI (Scalar) | `/docs/api` on a running instance |
| External viewers | Paste the JSON URL into [editor.swagger.io](https://editor.swagger.io/), [redocly.com](https://redocly.github.io/redoc/), or [Scalar Sandbox](https://sandbox.scalar.com/) |

A Spectral lint job in CI blocks regressions; a `verify-codegen` workflow
guarantees the generated server/client never drift from the spec.

## Endpoints

```
POST   /api/v1/scans                  → 202, body {id, status, links}
GET    /api/v1/scans/{guid}           → 200 always, body with status
GET    /api/v1/scans/{guid}/events    → SSE (text/event-stream)
GET    /api/v1/scans/{guid}/markdown  → text/markdown; charset=utf-8
GET    /api/v1/scans/{guid}/sarif     → application/sarif+json
DELETE /api/v1/scans/{guid}           → 204 (private mode requires token)
GET    /api/v1/checks                 → catalog manifest
GET    /api/v1/checks/{check_id}     → check details
GET    /api/v1/health                 → 200, {status, uptime, version}
GET    /api/v1/version                → 200, {version, commit, build_date}
GET    /api/v1/openapi.json           → embedded OpenAPI 3.0 spec
```

## Async request-reply pattern

A scan takes 30 s – 2 min. Holding a synchronous connection is an
anti-pattern (proxy timeouts, bad agent UX). The API follows the
[Asynchronous Request-Reply](https://learn.microsoft.com/en-us/azure/architecture/patterns/async-request-reply)
recipe:

1. **`POST /api/v1/scans`** returns `202 Accepted` immediately, with
   `Location: /api/v1/scans/{guid}` and `Retry-After: 5`.
2. Poll **`GET /api/v1/scans/{guid}`** — it always returns `200 OK` with a
   structured `status` field (`queued`, `running`, `completed`, `failed`).
3. Or stream progress via **`GET /api/v1/scans/{guid}/events`** (SSE).
4. Or block synchronously by passing `options.wait_seconds` (≤ 120 s) on
   the POST. If the scan exceeds the wait, the API falls back to async
   and returns the in-progress body.

## Quickstart — `curl`

```bash
# 1. Create a scan (synchronous up to 30 s)
curl -X POST http://localhost:8080/api/v1/scans \
  -H 'content-type: application/json' \
  -d '{"target":"example.com","options":{"wait_seconds":30}}'

# 2. Poll the scan
curl http://localhost:8080/api/v1/scans/$GUID

# 3. Stream progress (SSE)
curl -N http://localhost:8080/api/v1/scans/$GUID/events

# 4. Fetch the Markdown report
curl http://localhost:8080/api/v1/scans/$GUID/markdown

# 5. Fetch the SARIF report (GitHub Code Scanning compatible)
curl http://localhost:8080/api/v1/scans/$GUID/sarif > report.sarif
```

## SSE event format

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

## Authentication

- **MVP**: anonymous access for the public endpoints; rate limiting per
  IP (10 scans/h) and per target (cooldown 5 min between scans of the
  same hostname).
- Optional API key: `Authorization: Bearer wsk_xxxxx` (env
  `WEBSEC0_API_KEY`) for higher quotas on the public instance.
- **Private mode**: `POST` with `options.private: true` mints a 256-bit
  token returned **once**. Subsequent `GET`/`DELETE` requires it.

## Error envelope

All non-2xx responses share a single shape:

```json
{ "code": "target_blocked", "message": "private IP range", "details": {} }
```

Common error codes:

| HTTP | Code                       | Reason                                                |
|------|----------------------------|-------------------------------------------------------|
| 422  | `target_blocked`           | Target resolves to a forbidden IP range (anti-SSRF)   |
| 451  | `domain_blocklist`         | Target matches the policy blocklist (.gov, .mil, …)   |
| 429  | `rate_limited`             | IP rate limit hit                                     |
| 429  | `cooldown`                 | Same target re-scanned too soon (5 min)               |
| 429  | `abuse_flagged`            | Pattern abuse detected (>5 distinct targets in 5 min) |
| 404  | `scan_not_found`           | Unknown GUID                                          |
| 401  | `invalid_token`            | Bearer token mismatch on private scan                 |
| 501  | `not_implemented`          | Stub endpoint (transitional, MVP)                     |

## Schemas

The full schemas live in `components.schemas` of
[`api/openapi.yaml`](../../api/openapi.yaml):

- `ScanRequest`, `ScanOptions`, `ScanCreated`, `Scan`, `ScanStatus`
- `Finding`, `Severity`, `FindingStatus`, `Family`
- `Check` (catalog entry), `CheckMeta`
- `Health`, `Version`, `Error`

A reference rendering of the `Finding` shape is in
[SPECIFICATIONS §6.2](../../SPECIFICATIONS.md#62-schéma-dun-finding).

## Code generation

The spec drives both the server and the client. ogen runs via `go generate`:

```bash
make gen      # regenerates pkg/client/* from api/openapi.yaml
```

The CI job **`verify-codegen`** fails the PR if the regenerated artefacts
differ from the committed copies — that's how we guarantee zero drift.

## Typed Go client

```go
import (
    "context"
    client "github.com/JoshuaMart/websec0/pkg/client"
)

func main() {
    c, _ := client.NewClient("https://websec0.example", nil)

    created, err := c.CreateScan(context.Background(), &client.ScanRequest{
        Target: "example.com",
        Options: client.NewOptScanOptions(client.ScanOptions{
            WaitSeconds: client.NewOptInt(30),
        }),
    })
    if err != nil { /* … */ }

    scan, _ := c.GetScan(context.Background(), client.GetScanParams{Guid: created.ID})
    _ = scan
}
```

The package is generated; do not edit the files under `pkg/client/`. To
extend the client, edit `api/openapi.yaml` and re-run `make gen`.

## Other languages

OpenAPI 3.0 is broadly supported. Generate a client for your language with:

- **Python** — [`openapi-python-client`](https://github.com/openapi-generators/openapi-python-client)
  ```bash
  openapi-python-client generate --url https://websec0.example/api/v1/openapi.json
  ```
- **TypeScript** — [`openapi-typescript`](https://openapi-ts.dev/)
  ```bash
  npx openapi-typescript https://websec0.example/api/v1/openapi.json -o websec0.d.ts
  ```
- **Rust** — [`progenitor`](https://github.com/oxidecomputer/progenitor)
- **Java** — [`openapi-generator-cli`](https://github.com/OpenAPITools/openapi-generator-cli)

## Related documents

- [Architecture](../architecture.md) — components, concurrency, layout
- [Self-hosting](../self-hosting.md) — Docker, binaries, reverse proxy
- [AI agents](../ai-agents.md) — Claude/Codex/Cursor integration recipes
- [Checks catalog](../checks/) — one page per supported check
