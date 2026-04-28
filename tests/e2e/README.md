# End-to-end test suite (Phase 21)

Full-orchestrator integration tests: every check family is registered
on a fresh `Registry`, a real `Runner.Run` executes against a real
target, and `report.Build` renders a real Report. Assertions then
inspect the report.

These are slower and noisier than the per-family `integration` tests
under `internal/scanner/<family>/`, so they live behind a distinct
build tag (`e2e`).

## Suites

| File | What it does | Network |
|---|---|---|
| `badssl_e2e_test.go` | Asserts each badssl.com subdomain triggers the matching finding (`expired`, `self-signed`, `tls-v1-0`, `rc4`, `dh1024`, …). Plus pass-cases for `hsts.badssl.com` and `badssl.com` (redirect). | badssl.com |
| `reference_e2e_test.go` | Full scan against `cloudflare.com`, `github.com`, `mozilla.org`. Hard gate: zero `critical` findings. Per-check gate: 20+ legacy/weak checks must not fail. Score gate: ≥ 70. | reference vendors |
| `legacy_fixture_e2e_test.go` | Drives the local Nginx fixture under `legacy-fixture/`. Asserts the deliberately-broken setup is flagged correctly (legacy TLS, self-signed, no HSTS, missing headers, exposed `.git/config`, info disclosure). Score gate: < 50. | localhost only |

The legacy suite is **opt-in**: it runs only when
`WEBSEC0_LEGACY_FIXTURE_HOST` is set. CI without Docker simply skips.

## Run

```bash
# Full e2e suite (badssl + references — needs internet)
go test -tags e2e -v -timeout 10m ./tests/e2e/...

# Just badssl
go test -tags e2e -v -run TestE2E_BadSSL ./tests/e2e/...

# Just reference (cloudflare/github/mozilla)
go test -tags e2e -v -run TestE2E_APlus ./tests/e2e/...

# Legacy fixture
make -C tests/e2e/legacy-fixture up
WEBSEC0_LEGACY_FIXTURE_HOST=localhost:18443 \
  go test -tags e2e -v -run TestE2E_LegacyFixture ./tests/e2e/...
make -C tests/e2e/legacy-fixture down
```

`make test-e2e` from the repo root runs the network suites.
`make test-e2e-fixture` runs the legacy fixture suite end-to-end (brings
the container up, tests, tears it down).

## Why a separate `e2e` build tag

`integration` is used by per-family tests that exercise a single check
class against a single target — quick, focused, ~30 s per target.

`e2e` runs the **full orchestrator** (126 checks) against every target
in the matrix — minutes total. We do not want `go test -tags
integration ./...` to take 10+ minutes, so the slow path is gated
separately.

## Stability notes

The reference suite (`TestE2E_APlus`) is the one most likely to flap
when an upstream vendor changes their headers. Decisions:

- **Hard gate** (test fails) — any `critical`-severity finding, plus a
  curated allowlist of universally-bad checks (cert validity, SSLv2/v3,
  NULL/EXPORT/RC4/DES, DH-weak).
- **Soft gate** (logged, not failed) — `high`-severity findings,
  vendor-policy choices (TLS 1.0/1.1 acceptance on CDNs, HSTS on apex).
- **Score gate** — ≥ 70. Liberal on purpose.

The badssl suite (`TestE2E_BadSSL`) classifies each fixture target as
either **stable** (cert variants, legacy-protocol acceptance — hard
gate) or **drifted** (incomplete-chain, rc4, dh1024 — soft-warn). On a
drifted target, the test logs a `VENDOR DRIFT` line with the reason but
does not fail. Known drift today:

- `incomplete-chain.badssl.com` — Go stdlib TLS does AIA chasing and
  completes the chain at verify time. Detecting wire-chain absence is a
  separate scanner enhancement.
- `rc4.badssl.com` — Cloudflare disabled RC4 at the edge for the entire
  badssl.com CDN.
- `dh1024.badssl.com` — upstream upgraded to 2048-bit DH parameters.

Re-evaluate the soft-warn classifications periodically: if upstream
fixes itself or the scanner gains the capability (e.g. wire-chain
detection lands), promote the entry back to hard-fail.

## Adding a new target

```go
// Append to TestE2E_BadSSL.cases:
{"foo.badssl.com", scannertls.IDxxx, "what we expect to fail"},

// Or for an A+ reference:
hosts := []string{"…", "yourvendor.com"}
```

Every entry needs `reachable(t, host+":443")` so the test skips
gracefully on offline runners. The `runFullScan` helper handles the
target/policy/runner wiring.
