# WebSec0 — agent context

WebSec0 is a passive web-security scanner: one Go binary (`./dist/websec0`)
embeds an Astro/Preact frontend and exposes a chi-routed HTTP API that
runs TLS, HTTP-header and custom checks against a single hostname.

**Authoritative docs** (read these before non-trivial work):
- `skills/websec0/SKILL.md` — full API contract, grading model and
  finding interpretation, written for AI agents but human-readable.
  Treat as the canonical reference when SPEC-level detail is needed.
- `catalog/checks.json` — every check the scanner emits, with its
  remediation snippet.
- `websec0.yaml.example` — every configurable field, annotated.
- `TODO.md` — what's open for v1.1 (deferred items, with reason).
- `README.md` — public-facing summary.

The maquette in `/maquette/` is a **design reference only** (gitignored).
Don't import from it; port the look manually to `web/`.

## Commands

```bash
make build              # build dist/websec0  (does NOT rebuild the frontend)
make test               # go test -race ./...
make lint               # golangci-lint run ./...
make frontend           # pnpm build in web/, then rsync to internal/frontend/dist
make frontend-install   # pnpm install in web/
make clean              # remove build artefacts (keeps internal/frontend/dist/.keep)
make docker             # build distroless image
```

`make build` does **not** chain `make frontend`. Run `make frontend` first
when frontend sources changed; otherwise the embedded site is stale.

Run the binary: `./dist/websec0` (loads `./websec0.yaml` if present, else
defaults). `--version` prints build identifiers; `--config <path>` overrides.

## Architecture

```
cmd/websec0/        entry point (config → scanner → api router → http.Server)
internal/
  api/              chi router, JSON handlers, typed errors, rate limit
  scanner/          orchestrator — fans out probes in parallel
  scan/             public payload types (TLSReport, HeadersReport, …)
  scoring/          grade thresholds + TLSFinal / HeadersFinal
  safehttp/         SSRF + DNS-rebinding gate (ALL outbound traffic uses this)
  tls/              modern TLS probe (stdlib crypto/tls)
  sslv2/, sslv3/    raw ClientHello probes
  headers/          HTTP header probe + parsers + grading inputs
  custom/           security.txt, robots.txt (pluggable Check interface)
  cache/            generic Cache[V] + scan-ID generator
  history/          opt-in "Recent scans" strip
  frontend/         //go:embed all:dist + http.Handler with SPA fallback
  config/           YAML loader + Validate()
  version/          -ldflags injection target
catalog/            checks.json + Load() + Raw() — served at /api/v1/checks
web/                Astro 6 + Preact project (pnpm-managed)
  src/pages/        index.astro (landing) and r/index.astro (report shell)
  src/islands/      Report.tsx (Preact island, client:only)
  src/styles/       global.css (design tokens from the maquette)
```

## Rules

These are non-obvious invariants that have already cost time to discover —
violating any of them will cause regressions.

1. **All outbound traffic goes through `safehttp`**. Never `net.Dial` or
   `http.Get` directly. The package enforces IP pinning, blocked-range
   policy and per-host rate limiting. Tests rely on these defences holding.
2. **Probes return `scan.*` types but `scan` never imports probes**. The
   orchestrator (`internal/scanner`) lives outside `internal/scan` to
   break the cycle. Don't move it back.
3. **`scoring` imports `scan`, not the other way around**. `Grade` lives
   in `scan/grade.go` precisely because `scan/types.go` references it.
4. **The frontend is embedded via copy, not symlink**. `make frontend`
   rsyncs `web/dist/` → `internal/frontend/dist/`. The committed
   `internal/frontend/dist/.keep` keeps `//go:embed all:dist` happy on a
   fresh clone. Don't delete it.
5. **SPA fallback is path-prefixed**. `/api/*` returns typed JSON 404,
   `/r/*` falls back to `r/index.html`, everything else to `index.html`.
   Adding new SPA roots needs a new branch in `internal/frontend/embed.go`.
6. **The report island is `client:only="preact"`**, never `client:load`.
   It reads `location.pathname` which doesn't exist during SSR.
7. **DeriveWeaknesses runs in the orchestrator, not in `tls.Probe`**.
   Heartbleed and Ticketbleed need the HTTP `Server:` header — only the
   orchestrator has both reports in scope.
8. **`Loopback`, link-local, multicast and unspecified are ALWAYS blocked**
   in `safehttp.Policy.IsBlocked`, even with `AllowPrivate: true`. This
   is intentional — do not relax without a config change.
9. **Catalog IDs and runtime IDs are currently misaligned**. Catalog uses
   `vuln.poodle`; runtime weakness findings emit `"POODLE"`. A future
   refactor will reconcile; do not "fix" one without the other.
10. **TODO items marked `*deferred to v1.x*` are intentional**. Don't
    implement them as a side effect of an unrelated change.

## Workflows

**Before any commit:**
- `make test` must be green (race detector on)
- `golangci-lint run ./...` must report 0 issues
- If frontend sources changed, `make frontend` then verify the bundle
  stays under the 80 KB gzip budget (currently ~92 KB raw)

**Adding a new check** (custom):
1. Implement the `custom.Check` interface in `internal/custom/<name>.go`
2. Add an entry to `catalog/checks.json` with the same ID
3. Register it in `custom.All()` (registry.go)
4. Add a test that hits an httptest server

**Adding a new TLS heuristic** (vulnerability):
1. Update `internal/tls/weakness.go` `DeriveWeaknesses(...)`
2. Add a `vuln.<name>` entry to `catalog/checks.json`
3. Update `TODO.md` Phase 4 weakness list
4. Add a table test

**Adding a config field:**
1. Add to `internal/config/config.go` struct
2. Update `internal/config/defaults.go`
3. Update `internal/config/validate.go` if it needs bounds
4. Mirror in `websec0.yaml.example` (the user-facing config doc)

**Lint exceptions are tracked**, not handed out. `errcheck`, `gosec`,
`unparam` and `bodyclose` are silenced **only in `*_test.go`** via
`.golangci.yml`. Any in-tree `//nolint` directive must end with the
reason on the same line (existing examples in `safehttp` and `tls`).

## Glossary

- **Grade** — payload-shape string from `scan.Grade` (A+ … F, plus T for
  "no trust"). Letters are normative; the JSON marshalling depends on it.
- **Floor** — a grade cap applied after the SSL Labs formula
  (`scoring/tls.go::Worst(grade, ...)`). E.g. SSLv3 enabled → F.
- **Pin / pinning** — `safehttp.Target.IP` is locked at resolve-time.
  Subsequent `Dial` calls hit that exact IP regardless of what DNS says
  later (anti-rebinding).
- **Probe** — a per-domain inspector (`tls.Probe`, `sslv2.Probe`,
  `headers.Probe`, `custom.RunAll`). Each probe is independent and
  resilient: failure produces a partial report, not a scan error.
- **Catalog** — `catalog/checks.json`, served verbatim at `/api/v1/checks`.
  Source of truth for remediation snippets.
- **Maquette** — the design mockup in `/maquette/` (HTML+React via Babel
  CDN, gitignored). Reference only — not part of the build.

## SSRF defence

The scanner ingests user-supplied hostnames, so every outbound request
must be funnelled through `internal/safehttp`. Four cooperating layers,
each owning one file in the package:

1. **Input validation** (`safehttp/input.go`) — `ValidateInput` parses
   the raw target, applies the scheme allow-list and refuses IP
   literals, userinfo and odd ports.
2. **Resolution & pinning** (`safehttp/resolver.go`, `safehttp/dialer.go`)
   — DNS is resolved exactly once at `Resolver.Resolve`; the chosen IP
   is frozen in the `*Target`. `PinnedDialer` then dials that single
   IP for every subsequent request, defeating DNS rebinding.
3. **IP policy** (`safehttp/policy.go`) — `Policy.IsBlocked` filters
   IPs. Loopback, link-local, multicast and unspecified are always
   rejected; RFC 1918 / ULA / 100.64 are rejected unless
   `AllowPrivate: true`. Operators can extend the deny list via
   `Policy.Extra`.
4. **Behavioural limits** (`safehttp/redirect.go` + per-host rate
   limiter, body cap, timeouts) — `AllowRedirect` refuses off-host
   redirects (with the apex↔www sibling carve-out wired in the
   orchestrator); the client caps body size and dial/handshake
   timeouts.

Adding a new outbound call: never `net.Dial` or `http.Get` directly.
Build a `*safehttp.Target` via the resolver and use
`safehttp.NewClient(...)` or `safehttp.PinnedDialer(...)`. All
existing probes (`tls`, `sslv2`, `sslv3`, `headers`, `custom`) follow
this pattern; mirror them.
