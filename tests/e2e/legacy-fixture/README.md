# Legacy E2E fixtures

Two deliberately-misconfigured server containers (Nginx 1.18 and Apache
HTTPD 2.4) that the E2E suite uses to exercise checks we cannot
reproduce against badssl.com — information disclosure headers, missing
security headers across the board, exposed `.git/config`, mixed
content, missing SRI, no HSTS, no HTTPS redirect on port 80, TRACE
enabled, and CORS reflection.

**Do not deploy these anywhere reachable.** They are wrong on purpose.

## What it exposes

| Service | HTTP port | HTTPS port | Triggers |
|---|---|---|---|
| `legacy-nginx` (`nginx:1.18-alpine`)  | `127.0.0.1:18080` | `127.0.0.1:18443` | TLS 1.0/1.1 enabled, weak ciphers, self-signed cert, no security headers, no HSTS, no redirect, `server_tokens on`, `/.git/config` exposed, mixed content, no SRI |
| `legacy-apache` (`httpd:2.4`)         | `127.0.0.1:18180` | `127.0.0.1:18543` | TLS 1.0/1.1 enabled, weak ciphers, self-signed cert, no security headers, **`TraceEnable On`** (HTTP-TRACE-ENABLED), **CORS origin reflection + `Allow-Credentials: true`**, `ServerTokens Full` (banner version), `ServerSignature On`, mixed content, no SRI |

The two services share the same self-signed cert (`tls/`).

## Layout

```
legacy-fixture/
├── docker-compose.yml      # both services
├── Makefile                # generates cert, brings both up/down
├── README.md               # this file
├── tls/                    # shared self-signed cert (gitignored)
├── nginx/
│   ├── nginx.conf          # weak nginx config
│   └── www/
│       ├── index.html      # mixed content + no SRI
│       └── dotgit/config   # exposed at /.git/config
└── apache/
    ├── httpd.conf          # weak Apache config (TRACE, CORS)
    └── www/
        └── index.html      # mixed content + no SRI
```

## Run

```bash
# Generate the self-signed cert and bring both containers up
make up

# Run both gated E2E tests
WEBSEC0_LEGACY_FIXTURE_HOST=localhost:18443 \
WEBSEC0_APACHE_FIXTURE_HOST=localhost:18543 \
  go test -tags e2e -v \
  -run 'TestE2E_(LegacyFixture|ApacheFixture)' \
  ../

# Tear down
make down
```

Or, from the repo root, in one command:

```bash
make test-e2e-fixture
```

`make up` waits for both containers' healthchecks before returning.

## Why local fixtures

Public "weak" demo sites (the old `aspnet.example.com` and friends)
come and go and we cannot pin them. Local fixtures are reproducible,
isolated, and harmless. The E2E tests that drive them are each gated
on their own env var so CI without Docker simply skips.

## Adding another fixture

To add e.g. a vulnerable Spring Boot Actuator fixture:

1. Add a service to `docker-compose.yml` on a new local port pair.
2. Create `<service>/` with the config files and `www/`.
3. Reuse the shared `tls/` cert if HTTPS is needed.
4. Write a corresponding gated test (`<service>_fixture_e2e_test.go`)
   that asserts the service-specific findings.
5. Wire it into `Makefile`'s `up` / `down` (no change — compose
   handles both).
6. Update the matrix in this README.
