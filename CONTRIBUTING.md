# Contributing to WebSec0

Thanks for taking the time to look at this. WebSec0 is small and
opinionated on purpose, so the bar for new code is "does it earn its
weight in the v1 scope?". This guide is a stub focused on the most
common contribution: **adding a new check**.

## Quick start

```bash
make frontend-install   # one-time: install the Astro dev deps (pnpm)
make build              # produce ./dist/websec0 (rebuilds the frontend if web/ sources changed)
./dist/websec0          # serves on :8080 with the embedded UI
```

Run a scan against the local instance:

```bash
curl -sS -X POST http://localhost:8080/api/v1/scan \
  -H 'Content-Type: application/json' \
  -d '{"host":"example.com"}' | jq .
```

## Development workflow

Before opening a PR, every change must pass:

```bash
make test               # go test -race -count=1 ./...
make lint               # golangci-lint run ./...
make bundle-size        # only if web/ changed — gzip budget is 80 KB
```

`make build` declares the embedded bundle as a Make prerequisite, so a
touch under `web/` triggers a rebuild + rsync into
`internal/frontend/dist/` before the Go build. No manual `make frontend`
step is needed.

The same three gates run in `.github/workflows/ci.yml` and must be
green for the PR to land.

## Commit and PR conventions

- Commit messages follow Conventional Commits with a scope:
  `feat(web): …`, `fix(scanner): …`, `docs(skills): …`, `ci: …`. Keep
  the subject under ~72 chars and lead with the *why* in the body
  when the change is non-trivial.
- One logical change per commit. If a refactor and a feature land in
  the same PR, split them.
- PR title mirrors the commit style. The description should call out
  any non-obvious decision, especially when the change touches
  scoring, the SSRF gate or the API contract.

## Adding a new custom check

Custom checks are the easiest kind to add. They never contribute to a
grade — they surface as a separate list in the scan response,
alongside the TLS and Headers reports.

1. **Implement the interface** in `internal/custom/<name>.go`:

   ```go
   type MyCheck struct{}

   func (MyCheck) ID() string { return "custom.my_check" }

   func (MyCheck) Run(ctx context.Context, target *safehttp.Target) scan.CustomFinding {
       // Use safehttp (NEVER net.Dial or http.Get directly) — SSRF policy,
       // IP pinning and per-host rate limit live there.
       // Return a scan.CustomFinding with ID, Title, Status (pass/warn/fail/info)
       // and a json.RawMessage of structured details.
   }
   ```

   See `internal/custom/securitytxt.go` and `robotstxt.go` for two
   contrasting examples — one that parses a file with rules, one that
   inspects a list for suspicious entries.

2. **Register it** in `internal/custom/registry.go` by appending
   `MyCheck{}` to `All()`. Order is preserved in the API output, so
   keep new checks at the end unless you have a reason to reorder.

3. **Add a catalog entry** in `catalog/checks.json` with the same ID:

   ```json
   {
     "id": "custom.my_check",
     "category": "custom",
     "title": "Short human-readable title",
     "severity_when_fail": "warn",
     "score_impact": "Informational only — does not affect grade.",
     "remediation": {
       "summary": "What the operator should do, in one sentence.",
       "example_stack": "nginx",
       "example_snippet": "# canonical config snippet here"
     }
   }
   ```

   `severity_when_fail` is one of `critical | warn | info`. Custom
   checks almost always sit at `warn` or `info` — they are signal,
   not scoring.

4. **Write a test** in `internal/custom/<name>_test.go` against an
   `httptest.Server`. Cover the happy path, the missing-file path and
   one malformed-input path. The repo runs with `go test -race`, so
   make sure no shared state leaks between iterations.

5. **Update the SKILL.md mapping** in `skills/websec0/SKILL.md` §5.4
   if your check exposes new `details` keys an agent should
   understand.

## Adding a TLS weakness heuristic

1. Update `internal/tls/weakness.go` in `DeriveWeaknesses(...)`. Use
   the existing `finding(...)` helper — keep the condition explicit
   and put any cipher/protocol gate next to the others.
2. Add a `vuln.<name>` entry to `catalog/checks.json` under the
   `tls.vulnerability` category. The catalog ID stays lowercase
   dotted; the runtime emits the bare short name (e.g. `BEAST`) — that
   mismatch is documented in `skills/websec0/SKILL.md` §5.5 and in
   `CLAUDE.md` rule 9.
3. Update `TODO.md` Phase 4 weakness list if you flip a `*deferred*`
   item to implemented.
4. Add a table test covering "vulnerable", "not vulnerable" and
   "unknown" branches.

## Adding a configuration field

1. Add the field to the relevant struct in `internal/config/config.go`.
2. Set its default in `internal/config/defaults.go`.
3. Validate bounds in `internal/config/validate.go` if it has them.
4. Mirror the field in `websec0.yaml.example` with a short comment.

## Things to watch out for

- **All outbound traffic goes through `safehttp`.** Never `net.Dial`
  or `http.Get` directly. The package enforces IP pinning, blocked
  ranges (loopback/private/link-local are always blocked, even when
  `AllowPrivate: true`) and the per-host rate limit. Tests rely on
  these defences holding.
- **The frontend is embedded via copy, not symlink.** `make frontend`
  rsyncs `web/dist/` into `internal/frontend/dist/`. The committed
  `internal/frontend/dist/.keep` keeps `//go:embed all:dist` happy on
  a fresh clone — do not delete it.
- **`scan` never imports probes.** Probes return `scan.*` types but
  the orchestrator (`internal/scanner`) wires them together so the
  type package stays leaf.
- **Lint exceptions are tracked, not handed out.** Any in-tree
  `//nolint` directive must end with the reason on the same line.
  Existing examples live in `safehttp` and `tls`.

## Reporting issues

- Functional bugs and feature requests:
  <https://github.com/JoshuaMart/WebSec0/issues>.
- Security issues: please follow
  [`SECURITY.md`](./SECURITY.md) and report privately via the GitHub
  Security Advisory workflow.

## License

By contributing, you agree your contributions are licensed under the
MIT License (see [`LICENSE`](./LICENSE)).
