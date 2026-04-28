# CLAUDE.md

Operational notes for Claude Code working in this repo. Everything here
is non-obvious from the code; standard Go / Astro idioms are assumed.

## What this repo is

WebSec0 — a passive web security configuration scanner. Single Go binary
with the Astro frontend embedded via `//go:embed all:dist`. Module path:
`github.com/JoshuaMart/websec0`. Toolchain: **Go 1.26.2** (pinned in
`go.mod`). Frontend: **Astro 6** + Tailwind + Alpine, built with **pnpm**.

## Layout (where things live)

| Path | What it holds |
|---|---|
| `api/openapi.yaml` | Source of truth for the HTTP API. Editing it is mandatory before changing handler shapes. |
| `cmd/websec0/` | Server binary. |
| `cmd/websec0-cli/` | CLI binary (`scan`, `report`, `catalog`, `version`). |
| `internal/checks/` | `Check` interface, `Target`, registry, `CheckMeta`. |
| `internal/scanner/<family>/` | Check implementations (`tls`, `headers`, `cookies`, `dns`, `email`, `wellknown`, `http`, `safety`). One `Register(r *checks.Registry)` per family — wired from three call sites: `cmd/websec0/main.go`, `cmd/websec0-cli/cmd/scan.go`, `cmd/websec0-cli/cmd/catalog.go`. |
| `internal/api/{handlers,middleware,sse,spec}/` | HTTP layer. `handlers/` implements the ogen-generated server interface. |
| `pkg/client/` | ogen-generated client. The server reuses these types. **Do not edit by hand** — `make gen` regenerates. |
| `internal/report/` | `grade.go` (scoring), `markdown.go`, `sarif.go`. |
| `internal/scanner/safety/` | SSRF / DNS-rebinding / domain-blocklist gate. **Never bypass** in production code paths. |
| `internal/storage/{memory,…}/` | `ScanStore` implementations, keyed by GUIDv4. |
| `internal/webfs/` | `go:embed all:dist` of the built frontend. |
| `web/` | Astro source. Build output → `internal/webfs/dist/`. |
| `tests/e2e/` | Full-orchestrator E2E tests (build tag `e2e`). |
| `tests/e2e/legacy-fixture/` | Docker fixtures (nginx 1.18 + httpd 2.4) deliberately misconfigured. |

## Commands

```bash
make build-all     # build frontend then Go binaries → ./bin/
make test          # unit tests
make test-race     # tests under -race (must be clean before merging)
make test-e2e      # full E2E suite (badssl + reference, needs internet)
make test-e2e-fixture  # brings up Docker fixture, runs gated tests, tears down
make lint          # golangci-lint
make audit         # gosec + govulncheck + osv-scanner
make bench         # benches for TLS probes / CSP / SPF parsers
make cover         # writes coverage.html
make gen           # regenerate pkg/client/ from api/openapi.yaml
make docs          # regenerate docs/checks/ + skill catalog from the live registry
```

The CLI's standalone mode is the fastest scanner sanity check:

```bash
go run ./cmd/websec0-cli scan badssl.com --standalone --markdown
```

## Conventions that bite

- **Check IDs are public API.** SCREAMING-KEBAB-CASE, format
  `{FAMILY}-{SUBCATEGORY}-{CHECK}`. Once shipped, **never rename** —
  users gate CI on these via `--fail-on critical,high`. Add new IDs;
  deprecate old ones with `Status: skipped`.
- **Severity has 5 levels: `info`, `low`, `medium`, `high`, `critical`.**
  Don't add a sixth.
- **Findings always return non-nil.** A `Run` returning `(nil, nil)`
  becomes a synthetic `Status: error` upstream. Errors do too — that's
  the contract; do not panic, do not retry inside `Run`.
- **No retries.** A timeout is itself information; surface it as
  `Status: error`. Per-check timeout is enforced by the orchestrator
  (default 8 s).
- **Per-target shared resources.** DNS lookups, the homepage HTTP fetch,
  TLS connection state, parsed certificates — all memoized on `*Target`
  via `Target.CacheValue` (singleflight under concurrency). Add cache
  keys; don't re-fetch.
- **Anti-SSRF is non-negotiable.** All outbound connections must dial
  via `safety.HTTPClient` (which pins to admission-time IPs) unless the
  caller is an explicit test running on loopback. The dialer's
  `DialAddress` re-joins `Hostname` with the *passed-in* port whenever
  `PinnedIPs` is set — non-standard ports are dropped. See
  `tests/e2e/helpers_test.go`'s `runFullScan` for the loopback workaround.
- **Spec-first API.** Edit `api/openapi.yaml` *first*, then `make gen`.
  CI's `verify-codegen` job fails the PR if there's drift.
- **Privacy by design.** `logging.log_targets: false` is the default.
  Access logs include the GUIDv4, **never** the target hostname.

## Frontend

```bash
make web         # pnpm install + pnpm build (writes to internal/webfs/dist/)
make web-dev     # Astro dev server on :3000, proxies API to :8080
```

Astro is **static output only** — no SSR. Any interactivity is an
Alpine.js island opted in via `client:load` / `client:visible`. A
`<noscript>` block on each page should still link to the API equivalent
(graceful degradation for IA-only consumers).

## Tests

- Unit tests live next to the code; `go test ./...` runs them all.
- Per-family **integration** tests (build tag `integration`) hit
  badssl.com / cloudflare.com / etc. and skip on offline runners. Run:
  `go test -tags integration ./internal/scanner/tls/`.
- **E2E** tests (build tag `e2e`) live under `tests/e2e/` and exercise
  the full orchestrator (126 checks). Run via `make test-e2e`.
- The Docker fixture under `tests/e2e/legacy-fixture/` is **opt-in** via
  `WEBSEC0_LEGACY_FIXTURE_HOST` / `WEBSEC0_APACHE_FIXTURE_HOST`. CI
  without Docker simply skips.
- Avoid mocking the database in tests where it exists — but most of
  this codebase has no DB; in-memory storage is the test default.

## Scope discipline (passive only)

The MVP is **passive**: TLS handshakes on 443/25/465/587, HTTP `GET` /
`OPTIONS` / `TRACE`, DNS lookups, single CORS probe, ≤ 50 requests per
scan total. Anything outside that needs an architectural discussion in
an issue **before** code lands. Refused at the design layer:

- Crawling, parameter fuzzing, authenticated flows
- Arbitrary port scanning
- Generic CVE testing (à la Nuclei)
- Headless Chromium

## Docs that are generated

- `docs/checks/<ID>.md` (126 files) and `skills/websec0/references/checks.md`
  are produced by `scripts/gen-checks-docs.sh`. **Don't hand-edit them**
  — fix the script or the source check, then `make docs`.
- `pkg/client/*` is produced by ogen — fix `api/openapi.yaml`, then
  `make gen`.

## Commit / PR etiquette

- **Conventional Commits 1.0.0** (validated by `commitlint` in CI).
- Signed commits required on `main` (branch protection).
- Open-PR checklist: `make test-race` clean, `make lint` clean,
  `make audit` clean (no new HIGH findings), and if you touched a check,
  `make docs` to refresh the catalog.
- Do not skip hooks (`--no-verify`) — fix the underlying issue.

## When in doubt

- Architecture overview: [`docs/architecture.md`](./docs/architecture.md)
- Adding a new check: [`docs/contributing/checks.md`](./docs/contributing/checks.md)
- API: [`docs/api/`](./docs/api/) and the live `/api/v1/openapi.json`
- Per-check pages: [`docs/checks/`](./docs/checks/)
- Self-hosting: [`docs/self-hosting.md`](./docs/self-hosting.md)
