# Legacy E2E fixture

A deliberately-misconfigured Nginx container that the E2E suite uses to
exercise checks we cannot reproduce against badssl.com (information
disclosure headers, missing security headers across the board, exposed
`.git/config`, mixed content, missing SRI, no HSTS, no HTTPS redirect on
port 80).

**Do not deploy this anywhere reachable.** It is wrong on purpose.

## What it exposes

| Port | Service | Notes |
|---|---|---|
| `127.0.0.1:18080` | HTTP  | Returns 200 — does not redirect to HTTPS |
| `127.0.0.1:18443` | HTTPS | Self-signed cert, weak ciphers, no security headers |

The HTML page (`www/index.html`) deliberately includes a mixed-content
image (`http://`) and an external script without `integrity=` to
trigger `HTTP-MIXED-CONTENT` and `SRI-EXTERNAL-RESOURCE-NO-INTEGRITY`.

The path `/.git/config` is mapped to `www/dotgit/config` to trigger the
`EXPOSURE-DOTGIT-CONFIG` check (Phase 11; assertion is opt-in).

## Run

```bash
# Generate the self-signed cert and bring the container up
make up

# Run the gated E2E test against it
WEBSEC0_LEGACY_FIXTURE_HOST=localhost:18443 \
  go test -tags e2e ../ -v -run TestE2E_LegacyFixture

# Tear down
make down
```

`make up` waits for the container's healthcheck before returning.

## Why a local fixture

Public "weak" demo sites (the old `aspnet.example.com`, etc.) come and
go and we cannot pin them. A local fixture is reproducible, isolated,
and harmless. The E2E test that drives it is gated on
`WEBSEC0_LEGACY_FIXTURE_HOST` so CI without Docker simply skips it.
