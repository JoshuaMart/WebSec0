# Contributing to WebSec0

Keep changes focused and check [TODO.md](TODO.md) for planned work.
Coding-agent instructions are in [AGENTS.md](AGENTS.md).

## Getting started

Requires Go 1.26+, Node 22.18+, pnpm 10+, rsync, and golangci-lint for linting.

```sh
make frontend-install
make build
./dist/websec0          # http://localhost:8080
```

`make build` rebuilds and embeds the frontend when its sources change.
See [README.md](README.md) for usage and deployment.

## Before opening a PR

```sh
make test              # Go tests with the race detector
make lint
make build
```

For changes under `web/`, also run:

```sh
make frontend-test
make bundle-size       # after make build; maximum 80 KB gzip
```

[CI](.github/workflows/ci.yml) runs Go tests and vet, lint, frontend tests,
and the frontend build and bundle-size check.

Use Conventional Commits for commit subjects and PR titles (`feat(web): …`,
`fix(scanner): …`, `docs: …`). Keep subjects under about 72 characters and
separate unrelated changes.
The PR description should explain the behavior change, relevant decisions
and how it was tested, especially for scoring, SSRF protection or API changes.

## Common changes

### Custom check

Custom findings are informational and do not affect grades.

1. Implement `custom.Check` in `internal/custom/<name>.go`. Use
   [securitytxt.go](internal/custom/securitytxt.go) or
   [robotstxt.go](internal/custom/robotstxt.go) as a reference.
2. Append the check to `All()` in [registry.go](internal/custom/registry.go);
   registration order determines API output order.
3. Add an entry with the same ID to [catalog/checks.json](catalog/checks.json).
4. Test success, missing resources and malformed input with an `httptest.Server`.
5. Document new `details` fields in [the report guide](skills/websec0/references/interpretation.md#custom-fields).

### TLS weakness heuristic

1. Update `DeriveWeaknesses` in [weakness.go](internal/tls/weakness.go).
2. Add a `vuln.<name>` catalog entry under `tls.vulnerability`. Runtime IDs
   must match the catalog; the display name belongs in `Title`.
3. Test positive, negative and unknown outcomes, and update [TODO.md](TODO.md).

### Configuration field

Add the field, default and validation in `internal/config/`, then document
it in [websec0.yaml.example](websec0.yaml.example).

## Code conventions

- Route all outbound traffic through `safehttp` for IP pinning, address
  filtering and rate limiting. Loopback, link-local, multicast and unspecified
  addresses remain blocked even with `AllowPrivate: true`; see
  [policy.go](internal/safehttp/policy.go).
- Probes return `scan.*` types; `scan` must not import probes. The orchestrator
  in `internal/scanner` combines their results.
- Embed the frontend by copy, not symlink. Keep `internal/frontend/dist/.keep`
  so fresh clones can build Go packages before generating the frontend.
- Give every `//nolint` directive a reason on the same line.
- Register embedded certificate roots only in `cmd/websec0`. Keep the fallback
  module current through Dependabot and check updates with `govulncheck`;
  preserve its trust constraints rather than replacing it with a PEM export.

## Test references

- [TLS scoring fixtures](internal/scoring/testdata/tls/README.md): expected
  calculations and update policy; included in `make test`.
- [SCT certificate fixture](internal/tls/testdata/scts/README.md): provenance
  and independent decoding reference.
- [Certificate-tab tests](web/tests/report-certificate.test.tsx): Preact HTML
  rendering; included in `make frontend-test`, with no browser required.
- [Email DNS tests](internal/email/probe_test.go) and
  [email-tab tests](web/tests/report-email.test.tsx): synthetic TXT responses,
  DNS failures and rendered states; no external DNS queries.
- Root selection: [validation tests](internal/tls/roots_test.go) and
  [binary registration tests](cmd/websec0/roots_test.go).

Email parsing benchmark (synthetic DNS, no network latency):
`go test ./internal/email -run '^$' -bench BenchmarkProbeFixtures -benchmem`.

History benchmarks:
`go test ./internal/history -run '^$' -bench BenchmarkHistoryPurge -benchmem`.

## Issues and license

Report bugs and feature requests in [GitHub Issues](https://github.com/JoshuaMart/WebSec0/issues).
For security reports, follow the private disclosure process in [SECURITY.md](SECURITY.md).
Contributions are licensed under the [MIT License](LICENSE).
