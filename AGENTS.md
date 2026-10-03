# WebSec0 — instructions for coding agents

These instructions apply to the whole repository. Follow any more specific
`AGENTS.md` in the directory being changed.

WebSec0 is a Go web-security scanner with a chi HTTP API and an embedded
Astro/Preact frontend. It reports TLS, HTTP-header and custom findings.

## Repository map and references

- `cmd/websec0/`: configuration, scanner and HTTP-server startup.
- `internal/scanner/`: probe orchestration; `internal/scan/`: API payload types;
  `internal/scoring/`: scores and grades.
- `internal/safehttp/`: outbound-network policy; `internal/tls/`, `sslv2/`,
  `sslv3/`, `headers/` and `custom/`: probes.
- `internal/api/`: API routes; `internal/frontend/`: embedded static assets;
  `web/src/`: frontend source.

Consult the reference relevant to the change:

- [CONTRIBUTING.md](CONTRIBUTING.md): setup, PR conventions and procedures for
  adding checks or configuration fields.
- [skills/websec0/SKILL.md](skills/websec0/SKILL.md): API contract, grading model
  and finding interpretation.
- [catalog/checks.json](catalog/checks.json): finding IDs and remediation text.
- [websec0.yaml.example](websec0.yaml.example): configuration reference.
- [TODO.md](TODO.md): planned and deferred work. Keep deferred items outside
  unrelated changes.

## Commands and validation

Run commands from the repository root. Tool requirements are in
[CONTRIBUTING.md](CONTRIBUTING.md); dependency versions are in `go.mod` and
`web/package.json`. Use pnpm for the frontend and keep its lockfile in sync.

```sh
make frontend-install  # install frontend dependencies
make build             # rebuild/embed changed frontend sources, then build Go
make test              # go test -race -count=1 ./...
make lint              # golangci-lint run ./...
make frontend-test     # report helpers and Preact rendering tests
make bundle-size       # run after the frontend build; 80 KB gzip limit
```

- For code changes, run `make test`, `make lint` and `make build` before committing.
  For frontend changes, also run `make frontend-test` and `make bundle-size`.
- For documentation-only changes, check links, commands and `git diff --check`;
  a full build and test run is not needed.
- Use local test servers and committed fixtures for regression tests; tests
  must not depend on live third-party sites. Follow existing `httptest`
  helpers rather than relaxing network policy to accommodate test servers.
- Report which checks ran and any failures or checks that could not run.
  Fixture provenance, scoring expectations and benchmark commands are linked
  from [CONTRIBUTING.md](CONTRIBUTING.md#test-references).

## Architecture and report invariants

- Probes return `scan.*` types. Neither `scan` nor its types import probe or
  scoring packages; `scoring` imports `scan`, not the reverse.
- Call `tls.DeriveWeaknesses` from the orchestrator after both TLS and HTTP
  observations are available. Calling it inside `tls.Probe` loses the HTTP
  `Server` header used by some heuristics.
- Runtime TLS finding IDs use the catalog's `vuln.*` namespace; the display
  label belongs in `VulnerabilityFinding.Title`. Keep new IDs in the catalog.
- Preserve the distinction between absent, unavailable and unassessed data.
  An aborted probe is not evidence that a protocol is disabled. Follow the
  API guide when changing JSON fields, scoring inputs or frontend summaries.
- Custom findings and SCT observations are informational and do not affect
  grades. Keep Go payload types and `web/src/islands/report-types.ts` aligned.
- Register fallback certificate roots in the binary entry point only.
  System trust remains preferred; preserve the fallback bundle's constraints.
- Keep lint configuration in [.golangci.yml](.golangci.yml). Explain each
  `//nolint` on the same line instead of adding broad suppressions.

## SSRF defence

- Route outbound traffic through `safehttp`; do not introduce direct
  `net.Dial` or `http.Get` calls in production probes.
- Resolve and validate targets through `safehttp`, then use its pinned dialer
  or HTTP client. Preserve address pinning, timeouts, body limits and rate limits.
- Loopback, link-local, multicast and unspecified addresses, plus configured
  `Policy.Extra` ranges, remain blocked with `AllowPrivate: true`. See
  [policy.go](internal/safehttp/policy.go) for the complete policy.
- Preserve redirect checks. An apex/www follow-up must be re-resolved through
  the same policy by the orchestrator; it must not bypass the IP gate.

## Frontend and generated files

- Edit `web/src/` and `web/public/`. `make frontend` copies `web/dist/` into
  `internal/frontend/dist/`; `make build` invokes this when needed.
- Keep the embed as a copy, not a symlink, and preserve
  `internal/frontend/dist/.keep`. Do not hand-edit or commit generated bundles
  or build binaries.
- Keep the report island `client:only="preact"` in `web/src/pages/r/index.astro`.
  Its data loading and navigation depend on the browser.
- Preserve routing boundaries: `/api/*` returns typed JSON errors; report
  paths under `/r/` use the report shell, and other SPA paths use the landing
  shell. Check both API routing and `internal/frontend/embed.go` when changing
  these fallbacks.
- `maquette/`, when present, is an ignored design reference, not an importable
  part of the frontend.
