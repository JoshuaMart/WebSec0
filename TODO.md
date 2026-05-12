# WebSec0 — Implementation TODO

> Living checklist for v1. Tracks the work from empty repo to shippable binary.
> Each phase builds on the previous one; respect the order.

---

## Phase 0 — Repo bootstrap

- [x] `go mod init github.com/JoshuaMart/websec0`
- [x] Pin Go toolchain version in `go.mod` (`go 1.26`)
- [x] Create directory skeleton matching SPEC §11 (`cmd/`, `internal/`, `catalog/`, `web/`, `skills/`)
- [x] Add `.gitignore` entries for `web/dist/`, `web/node_modules/`, `*.log`, `dist/`, `coverage.out`
- [x] Add `.editorconfig` (LF, UTF-8, 4-space indent for Go, 2-space for JS/Astro/YAML)
- [x] Add `LICENSE` (MIT) referenced by the README badge
- [x] Create `websec0.yaml.example` mirroring SPEC §7
- [x] Add `Makefile` with targets: `build`, `test`, `lint`, `frontend`, `docker`, `clean`
- [x] Configure `golangci-lint` (`.golangci.yml`) — enable `gosec`, `errcheck`, `revive`, `gocritic`
- [x] Add `goreleaser` skeleton (`.goreleaser.yaml`) for binary release builds

## Phase 1 — Configuration & shared types

- [x] `internal/config`: YAML loader with the resolution order from SPEC §7
- [x] `internal/config`: defaults table + validation (port ranges, duration parsing, CIDR parsing for `extra_blocked_cidrs`)
- [x] `internal/config`: env-var override (`WEBSEC0_CONFIG`)
- [x] `internal/config`: unit tests covering invalid YAML, missing required fields, malformed CIDRs
- [x] `internal/scan/types.go`: shared payload types (`ScanResult`, `TLSReport`, `HeadersReport`, `CustomFinding`) matching SPEC §6.4–6.6
- [x] `internal/scoring/grade.go`: `Grade` enum (A+ → F, T) with stable string representation

## Phase 2 — `safehttp` (the security-critical core)

- [x] `internal/safehttp/policy.go`: `IsBlocked(netip.Addr)` using stdlib `IsLoopback`, `IsLinkLocalUnicast`, `IsLinkLocalMulticast`, `IsMulticast`, `IsUnspecified`, `IsPrivate`
- [x] `internal/safehttp/policy.go`: extra hardcoded blocklist (CGNAT, IETF test nets, doc ranges, NAT64) per SPEC §8.3
- [x] `internal/safehttp/policy.go`: IPv4-mapped IPv6 unwrapping before policy check
- [x] `internal/safehttp/policy.go`: support for `extra_blocked_cidrs` from config
- [x] `internal/safehttp/input.go`: scheme / port / hostname validation per SPEC §8.1 (reject IP literals, userinfo, invalid FQDN, disallowed schemes)
- [x] `internal/safehttp/dialer.go`: `net.Dialer` with `Control` callback enforcing IP pin
- [x] `internal/safehttp/resolver.go`: single resolution → pinned IP, returns typed errors (`ErrPrivateTarget`, `ErrNoAllowedIP`, …)
- [x] `internal/safehttp/httpclient.go`: factory for `*http.Client` using the pinned dialer, with body cap (1 MB) and redirect cap (3) per SPEC §8.4
- [x] `internal/safehttp/redirect.go`: detect off-host redirects, stop following, surface as finding
- [x] `internal/safehttp/ratelimit.go`: per-IP + per-host limiters (in-memory, token bucket)
- [x] Unit tests: each blocked range produces `ErrPrivateTarget`
- [x] Unit tests: pinned dialer rejects a connect to a different IP
- [x] Integration test: rebinding scenario (resolver returns IP_A then IP_B) — only IP_A is ever connected
- [x] Integration test: redirect to a different host on a different IP is refused

## Phase 3 — Cache & history

- [x] `internal/cache/lru.go`: TTL + max-entries LRU (consider `hashicorp/golang-lru/v2` or roll a thin one)
- [x] `internal/cache/id.go`: scan ID generation (content-addressable, e.g. truncated BLAKE3 of host+timestamp+nonce)
- [x] `internal/history`: opt-in public list, retention purge, in-memory only
- [x] Unit tests: TTL expiry, LRU eviction order, `list_in_history` toggle

## Phase 4 — TLS probes

### Modern (`internal/tls`)

- [x] Enumerate offered protocols (TLS 1.0, 1.1, 1.2, 1.3) via successive handshakes with `MinVersion = MaxVersion = X`
- [x] Enumerate cipher suites per protocol (loop through stdlib suite IDs, observe what the server picks)
- [x] Detect server preference vs client preference — exposed as `tls.cipher_preference` (`server` / `client` / unknown), 2 TLS 1.2 handshakes with reversed orders
- [x] Extract full certificate chain, parse leaf + intermediates (subject, SAN, issuer, validity, key alg, sig alg, serial, SHA-256)
- [x] Verify chain against Mozilla root store — *system roots via `crypto/x509.SystemCertPool` only; CCADB fallback bundle not shipped*
- [ ] Bundle a CCADB Mozilla root fallback so the binary validates chains identically across host OSes — **moderate / passive** (embed a curated PEM, fall back when system pool is empty)
- [x] OCSP stapling presence detection (bool)
- [x] OCSP response parsing if stapled — exposed as `tls.ocsp_status` (`good` / `revoked` / `unknown_to_responder` / `parse_error`), via `x/crypto/ocsp.ParseResponse`
- [ ] SCT extraction from `state.SignedCertificateTimestamps` (count + log IDs) — **moderate / passive**
- [ ] SCT extraction from the leaf cert's X.509 extension (OID 1.3.6.1.4.1.11129.2.4.2) — **complex / passive** (ASN.1 OctetString of SignedCertificateTimestampList)
- [x] Session ticket / session ID detection — exposed as `tls.session_resumption` (`supported` / `not_supported`), via two GETs sharing a ClientSessionCache
- [ ] 0-RTT (early data) detection on TLS 1.3 — **complex / passive** (requires real early-data send, not directly exposed)
- [x] Unit tests against `crypto/tls` test servers (`httptest.NewTLSServer` with crafted configs)

#### TLS weakness heuristics

- [x] **POODLE** (CVE-2014-3566) — detected via SSLv3 offered — passive
- [x] **DROWN** (CVE-2016-0800) — detected via SSLv2 offered — passive
- [x] **BEAST** (CVE-2011-3389) — detected via TLS 1.0 offered — passive
- [x] **Sweet32** (CVE-2016-2183) — detected via 3DES cipher offered — passive
- [x] **RC4 weakness** (CVE-2015-2808) — detected via RC4 cipher offered — passive
- [x] **Heartbleed** (CVE-2014-0160) — detected via `Server:` header OpenSSL 1.0.1 through 1.0.1f range — passive (heuristic, false-positive risk on non-OpenSSL servers)
- [x] **Lucky13** (CVE-2013-0169) — detected via TLS 1.0 or 1.1 offered alongside non-AEAD ciphers on those protocols — passive
- [x] **Ticketbleed** (CVE-2016-9244) — detected via `Server:` header containing "BIG-IP" — passive (heuristic warn-level)
- [ ] **FREAK** (CVE-2015-0204) — placeholder *Not assessed* — **moderate / passive** (export cipher enumeration; not in stdlib, needs raw ClientHello)
- [ ] **Logjam** (CVE-2015-4000) — placeholder *Not assessed* — **complex / passive** (parse ServerKeyExchange DH group, reject < 1024 bits)
- [ ] **CRIME** (CVE-2012-4929) — placeholder *Not assessed* — **complex / passive** (TLS compression detection; stdlib disables it client-side, so requires raw probing)
- [ ] **Raccoon Attack** (CVE-2020-1968) — placeholder *Not assessed* — **complex / passive** (multi-handshake DH-share comparison)

### SSLv2 (`internal/sslv2`)

- [x] Forge SSLv2 CLIENT-HELLO bytes (record type 0x01, length-prefix `\x80\x2e`, 7 cipher specs incl. `0x010080`)
- [x] Classify response: `0x04 …` → supported, `0x16 0x03 …` → not supported, RST/timeout → not supported
- [x] Unit tests with golden bytes for each response class

### SSLv3 (`internal/sslv3`)

- [x] Forge TLS-framed ClientHello with `record.version = 0x03 0x00` and `client_hello.version = 0x03 0x00`
- [x] Classify response: `0x16 0x03 0x00 …` → supported, `0x15 …` → not supported, `0x16 0x03 0x01+ …` → not supported
- [x] Unit tests with golden bytes for each response class

## Phase 5 — Header probe & scoring

- [x] `internal/headers/fetch.go`: GET request via `safehttp` client, capture all response headers (including duplicates)
- [x] `internal/headers/parse.go`: per-header parsers (HSTS directives, CSP source list, `Set-Cookie` attributes, `Permissions-Policy`)
- [x] `internal/headers/core.go`: evaluate the 6 core headers per SPEC §4.2 (status + value)
- [x] `internal/headers/additional.go`: evaluate bonus / malus signals (COOP/COEP/CORP, `Server` version leak, `Set-Cookie` flags, `Access-Control-Allow-Origin`)
- [x] `internal/scoring/headers.go`: compute final 0–100 + grade letter
- [x] Unit tests: each core header maps to its weight; each malus deducts the right amount; clamp to [0, 100] works

## Phase 6 — Scoring TLS

- [x] `internal/scoring/tls_cert.go`: certificate sub-score (0–100)
- [x] `internal/scoring/tls_protocol.go`: protocol-support sub-score
- [x] `internal/scoring/tls_kx.go`: key-exchange sub-score
- [x] `internal/scoring/tls_cipher.go`: cipher-strength sub-score
- [x] `internal/scoring/tls.go`: combine via the SPEC §5.1 formula, apply all floors
- [x] `internal/scoring/tls.go`: A+ bonus when HSTS-preload-eligible (cross-module read from headers result)
- [x] Unit tests: every floor condition produces the expected cap
- [ ] Reference fixtures: snapshot scores for 5 well-known sites in CI (no live network, replay captured handshakes) — *deferred to v1.1*

## Phase 7 — Custom checks

- [x] `internal/custom/securitytxt.go`: fetch `/.well-known/security.txt`, parse RFC 9116 fields, check expiry, detect PGP signature
- [x] `internal/custom/robotstxt.go`: fetch `/robots.txt`, parse, flag suspicious `Disallow:` paths (`/admin`, `/internal`, `/private`, `/api`, etc.)
- [x] `internal/custom/registry.go`: pluggable interface so future checks slot in without touching the orchestrator
- [x] Unit tests for both checks (golden files for parsing, table tests for status mapping)

## Phase 8 — Scan orchestrator

- [x] `internal/scanner/scanner.go`: parallel fan-out (TLS modern, SSLv2, SSLv3, headers, custom) under one budget (`scan.timeout`) — *moved out of `internal/scan/` to avoid import cycle with probes*
- [x] `internal/scanner/scanner.go`: graceful per-probe timeout + partial-result reporting (one slow probe doesn't kill the scan)
- [x] `internal/scanner/scanner.go`: assemble `ScanResult`, push to cache, return ID
- [x] Integration test: full scan against `httptest` server with crafted bad config — expected grades

## Phase 9 — API layer

- [x] `internal/api/router.go`: `chi` router, request ID middleware, structured logging (`slog`), panic recovery
- [x] `internal/api/scan.go`: `POST /api/v1/scan` handler — validate input via `safehttp`, run orchestrator, return scan
- [x] `internal/api/scan.go`: `GET /api/v1/scan/:id` handler — cache lookup, 404 on miss
- [x] `internal/api/checks.go`: `GET /api/v1/checks` handler — *stub catalog; real content lands in Phase 10*
- [x] `internal/api/errors.go`: typed error responses per SPEC §6.1 (`invalid_scheme`, `private_target_blocked`, `scan_timeout`, …)
- [x] Rate limiter wired as middleware (`internal/api/middleware.go`)
- [ ] `internal/api/cors.go`: CORS for the frontend — *deferred; same-origin works out of the box with the embedded frontend*
- [x] Integration tests: each error code is reachable, payload shape matches SPEC §6

## Phase 10 — Check catalog

- [x] `catalog/checks.json`: 35 entries covering tls.protocol, tls.chain, tls.cipher, tls.vulnerability, headers.core, headers.additional, custom
- [x] Each entry has: `id`, `category`, `title`, `severity_when_fail`, `score_impact`, `remediation.summary`, `remediation.example_stack`, `remediation.example_snippet`
- [x] `catalog/catalog.go`: `//go:embed checks.json`, Load() parses + Validate(), Raw() for direct HTTP serving, ByID() lookup
- [x] Unit test: key well-known check IDs (`custom.security_txt`, `custom.robots_txt`, `tls.protocol.sslv2`, …) exist in the catalog
- [x] Unit test: every catalog entry has a non-empty remediation snippet

## Phase 11 — Frontend (Astro 6 + Preact)

- [x] `web/`: scaffold Astro 6 project (manual minimal scaffold via `pnpm add`), TypeScript strict
- [x] `astro.config.mjs`: integrations `@astrojs/preact`, `output: 'static'`, `compressHTML: true`
- [ ] Port maquette `styles.css` → `web/src/styles/global.css`, keep CSS custom properties as the design tokens
- [ ] Port `landing.html` → `web/src/pages/index.astro` (form posts to `/api/v1/scan`, redirect to `/r/<id>`)
- [ ] Wire `GET /api/v1/history` into the landing for the "Recent scans" strip
- [ ] Port `index.html` (report) → `web/src/pages/r/[id].astro` (Astro page) + `web/src/islands/Report.tsx` (Preact island that fetches `/api/v1/scan/:id`)
- [ ] Port React components from `app.jsx` to Preact (TS, function components, `preact/compat` only where strictly needed)
- [ ] Implement copy-button on every remediation snippet
- [ ] Loading / error states for the report island
- [x] Astro build pipeline → `web/dist/` (`make frontend`, ~36 KB output)
- [x] `internal/frontend/embed.go`: `//go:embed all:dist` populated by `make frontend` rsync from `web/dist`, served at `/*` with `index.html` SPA fallback (direct write of bytes to avoid Go's `/index.html → ./` redirect loop)
- [x] Production build size budget: bundle ≤ 80 KB gzip — currently 36 KB total, well under (CI check still TBD)

## Phase 12 — AI artefacts

- [ ] `skills/websec0/SKILL.md`: written for agents — explains the API, the grading model in one paragraph each, the catalog endpoint, and how to interpret findings
- [ ] Include a worked example (single API call → interpretation of the response)
- [ ] Add a `metadata` front-matter block with `tools`, `inputs`, `outputs`

## Phase 13 — Entry point & packaging

- [x] `cmd/websec0/main.go`: load config, wire scanner + api router, `http.Server` with sane timeouts. Frontend embed deferred to Phase 11.
- [x] Graceful shutdown on SIGINT/SIGTERM (`http.Server.Shutdown` + drain bounded by `scan.timeout`)
- [x] `internal/version/`: `-ldflags` injection of version + commit + date, `--version` flag prints them
- [x] `Dockerfile` multi-stage: golang:1.26-alpine → distroless/static-debian12:nonroot
- [x] Binary size 7.4 MB (well under the 15 MB target — image build deferred until Docker is exercised in CI)

## Phase 14 — Quality gates

- [ ] CI workflow (`.github/workflows/ci.yml`): `go test ./...`, `golangci-lint`, `go vet`, frontend build, bundle-size check
- [ ] CI workflow (`.github/workflows/codeql.yml`): CodeQL for Go + JS — already referenced by the README badges
- [ ] CI workflow (`.github/workflows/release.yml`): tagged release → `goreleaser` produces multi-arch binaries + Docker image
- [ ] OpenSSF Scorecard workflow — already referenced by the README badge
- [ ] Coverage report uploaded as CI artefact (no badge yet, just visibility)
- [ ] `SECURITY.md` (responsible disclosure) — referenced by the project's own `security.txt` when we host an instance

## Phase 15 — Documentation polish

- [ ] README: usage section (run a scan via curl, run via UI, run in Docker)
- [ ] README: configuration section pointing to `websec0.yaml.example`
- [ ] README: minimal architecture diagram (mermaid)
- [ ] README: contribution guide stub (`CONTRIBUTING.md`) explaining how to add a new check
- [ ] Tag `v1.0.0`, write release notes
