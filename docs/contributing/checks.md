# Adding a new check

This guide shows how to add a new security check end-to-end: interface,
registration, snippets, tests, catalog metadata, scoring, and docs.

If you're new to the codebase, read [`docs/architecture.md`](../architecture.md)
first.

## TL;DR

1. Pick a stable ID and a [family](#families).
2. Implement `checks.Check` (and optionally `checks.Describer`) in the
   right `internal/scanner/<family>/` package.
3. Wire it into the package's `Register(r *checks.Registry)` function.
4. Write tests (table-driven, using fixtures).
5. Run `make docs` to refresh `docs/checks/<ID>.md`.
6. Update `CHANGELOG.md` under `Unreleased`.

## 1. Pick an ID

Format: `{FAMILY}-{SUBCATEGORY}-{CHECK}`, **SCREAMING-KEBAB-CASE**, ASCII
only. Examples: `TLS-PROTOCOL-LEGACY-SSL3`, `HEADER-CSP-MISSING`,
`EMAIL-SPF-PASS-ALL`.

The ID is part of the **public API**: it's serialized in JSON, SARIF,
Markdown reports, the SKILL manifest, and consumed by user CI pipelines
via `--fail-on`. **Never rename a published ID.** Add new ones; deprecate
the old via a `status: skipped` shim if you must.

## 2. Pick a family <a id="families"></a>

| Family       | Package                            | Scope                                       |
|--------------|------------------------------------|---------------------------------------------|
| `tls`        | `internal/scanner/tls/`            | TLS protocols, ciphers, certs, HSTS         |
| `headers`    | `internal/scanner/headers/`        | CSP, XCTO, XFO, COOP/COEP/CORP, …           |
| `cookies`    | `internal/scanner/cookies/`        | Set-Cookie analysis                         |
| `dns`        | `internal/scanner/dns/`            | DNSSEC, CAA, dangling CNAME, …              |
| `email`      | `internal/scanner/email/`          | SPF, DKIM, DMARC, MTA-STS, DANE, BIMI       |
| `wellknown`  | `internal/scanner/wellknown/`      | security.txt, change-password, robots, SRI  |
| `exposures`  | `internal/scanner/exposures/`      | Sensitive paths (Phase 11, WIP)             |
| `http`       | `internal/scanner/http/`           | CORS, OPTIONS/TRACE, 404 probe, mixed content, HTTP/2 |

Severity vocabulary lives in [`internal/checks/types.go`](../../internal/checks/types.go)
(`SeverityCritical` … `SeverityInfo`). Default scoring penalties: critical
= -25, high = -10, medium = -5, low = -2, info = 0 — implemented in
[`internal/report/grade.go`](../../internal/report/grade.go).

## 3. Implement `checks.Check`

The contract:

```go
// internal/checks/registry.go
type Check interface {
    ID() string
    Family() Family
    DefaultSeverity() Severity
    Run(ctx context.Context, target *Target) (*Finding, error)
}
```

Optionally implement `checks.Describer` to populate the catalog and the
generated per-check page in `docs/checks/`:

```go
type Describer interface {
    Title() string
    Description() string
    RFCRefs() []string
}
```

Minimal example (one struct = one check):

```go
// internal/scanner/wellknown/changepassword.go
package wellknown

import (
    "context"
    "github.com/JoshuaMart/websec0/internal/checks"
)

const IDChangePassword = "WELLKNOWN-CHANGE-PASSWORD-MISSING"

type changePasswordCheck struct{}

func (changePasswordCheck) ID() string                       { return IDChangePassword }
func (changePasswordCheck) Family() checks.Family            { return checks.FamilyWellKnown }
func (changePasswordCheck) DefaultSeverity() checks.Severity { return checks.SeverityInfo }
func (changePasswordCheck) Title() string                    { return "/.well-known/change-password is published" }
func (changePasswordCheck) Description() string {
    return "RFC 8615 reserves /.well-known/change-password as a discoverable redirect to the user-facing change-password flow."
}
func (changePasswordCheck) RFCRefs() []string { return []string{"RFC 8615"} }

func (changePasswordCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
    // 1. Fetch the URL with the shared Target HTTP client (memoized,
    //    short timeout, anti-SSRF dialer).
    // 2. Build a Finding (status pass/fail/warn, evidence, remediation).
    // 3. Return (finding, nil) — never `(nil, nil)`. On runtime failure,
    //    return a synthetic Finding with Status: StatusError.
    // …
    return &checks.Finding{
        ID:       IDChangePassword,
        Family:   checks.FamilyWellKnown,
        Severity: checks.SeverityInfo,
        Status:   checks.StatusPass,
        Title:    "/.well-known/change-password redirects to the change-password flow",
    }, nil
}
```

### Run conventions

- **Always return a `*Finding`**, even on `StatusPass` (the catalog/coverage
  UI relies on it).
- **Never panic.** A `nil` return + non-`nil` error becomes a synthetic
  `StatusError` finding upstream — fine for I/O failures.
- **Respect the context.** Per-check timeout is enforced by the
  orchestrator (default 8 s); use `ctx` for all network operations.
- **Reuse the cached resources on `*Target`** — DNS, HTTP homepage,
  TLS connection state, parsed certificates. Don't re-fetch.
- **Don't retry.** A timeout is information; emit a `StatusError` and
  let the orchestrator surface it.

## 4. Register the check

Each family package exposes a `Register` function. Add your check there:

```go
// internal/scanner/wellknown/wellknown.go (or similar)
func Register(r *checks.Registry) {
    r.Register(missingCheck{})
    r.Register(expiredCheck{})
    // …
    r.Register(changePasswordCheck{}) // ← new
}
```

The package's `Register` is called from both `cmd/websec0/main.go` and
`cmd/websec0-cli/cmd/{scan,catalog}.go` — don't add a top-level `init()`,
keep registration explicit.

If you create a brand-new family, add three call sites:
- `cmd/websec0/main.go`
- `cmd/websec0-cli/cmd/scan.go`
- `cmd/websec0-cli/cmd/catalog.go`

## 5. Build a useful `Finding`

The struct is defined in [`internal/checks/types.go`](../../internal/checks/types.go);
the worked example with full `evidence` / `remediation.snippets` /
`references` is in
[`docs/ai-agents.md` § "Why findings are LLM-ready"](../ai-agents.md#why-findings-are-llm-ready).
What matters operationally:

- **`Evidence`** — observed values, expected values, and a raw excerpt.
  Be specific: `{"server_header":"nginx/1.18.0"}`, not `{"bad":true}`.
- **`Remediation.snippets`** — a map keyed by stack. Cover the major
  ones (`nginx`, `apache`, `caddy`, `cloudflare`, …). Snippets are
  copy-paste-ready; no placeholders the user has to fill, no shell
  pipes, no `# TODO`.
- **`Remediation.references`** — RFCs first, then MDN/OWASP, then
  vendor docs.
- **`Remediation.verification`** — a one-line shell command that proves
  the fix works.

A great finding is one an LLM can quote verbatim and an SRE can paste
into their reverse-proxy config.

## 6. Tests

Put unit tests under the same package, named `<check>_test.go`. Patterns
in use:

- Table-driven, with fixture files under `testdata/`.
- Use `httptest.Server` for HTTP-fetching checks.
- Use the in-process miekg/dns server for DNS checks (see existing
  patterns under `internal/scanner/dns/`).
- For TLS probes: build a tiny TCP server that replies with the byte
  sequence you want (see `internal/scanner/tls/probes/*_test.go`).

For checks that depend on a real internet target (badssl.com,
cloudflare.com, …), use the `integration` build tag:

```go
//go:build integration

package …
```

Run with `go test -tags integration ./…`. Keep these out of `go test
./...` — they break in offline CI environments.

## 7. Refresh the docs

```bash
make docs
```

This runs `scripts/gen-checks-docs.sh` and regenerates
`docs/checks/<ID>.md` for every registered check, plus the index. Commit
the generated files alongside your check.

## 8. CHANGELOG

Add a line under `Unreleased` → `Added` in [`CHANGELOG.md`](../../CHANGELOG.md):

```markdown
### Added
- New check `WELLKNOWN-CHANGE-PASSWORD-MISSING` (RFC 8615).
```

## 9. Open the PR

- Use a Conventional Commit: `feat(checks): add WELLKNOWN-CHANGE-PASSWORD-MISSING`.
- Sign your commits (`git commit -S`). Branch protection requires it.
- Make sure CI is green: `lint`, `test`, `regenerate and diff` (no
  ungenerated drift), `openapi (spectral)`.

## Anti-patterns to avoid

- **Renaming a published ID.** Once shipped, IDs are immutable.
- **Adding hidden network calls.** All HTTP must go through the shared
  `Target` client (anti-SSRF dialer, identifiable User-Agent).
- **Probing arbitrary ports.** MVP scope is 443 (HTTPS) and 25/465/587
  (SMTP STARTTLS). Anything else needs a SPEC update first.
- **Long blocking calls.** Respect the 8 s budget; if you need more, do
  background work on a single shared resource on `*Target` so other
  checks can reuse it.
- **Heavy retry logic.** A timeout is information.
- **Adding a 5th severity tier.** Five is the contract (`info` → `critical`).

Also worth checking: anything outside MVP scope (active probing, port
scanning beyond 443/25/465/587, fuzzing) needs an architectural
discussion in an issue first — passive-only is non-negotiable.

## See also

- [Catalog of currently-supported checks](../checks/)
- [Architecture](../architecture.md)
- [API documentation](../api/) — the `Finding` schema is served live
  via `/api/v1/openapi.json`
- Reference implementations:
  - Simple HTTP probe: [`internal/scanner/wellknown/securitytxt.go`](../../internal/scanner/wellknown/securitytxt.go)
  - Stateful family: [`internal/scanner/email/spf.go`](../../internal/scanner/email/spf.go)
  - Raw socket probe: [`internal/scanner/tls/probes/sslv3.go`](../../internal/scanner/tls/probes/sslv3.go)
