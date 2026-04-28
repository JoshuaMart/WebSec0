# Self-hosting WebSec0

WebSec0 ships as a single statically-linked binary with the frontend embedded.
No Node.js, no database, no external services required at runtime.

## Prerequisites

| Method        | Requirements                         |
|---------------|--------------------------------------|
| Docker        | Docker ≥ 24, docker compose v2       |
| Binary        | Linux, macOS, or Windows (amd64/arm64) |
| Build from source | Go 1.26+, Node 24+, pnpm         |

---

## Option 1 — Docker (recommended)

### Quick start

```bash
docker run --rm -p 8080:8080 ghcr.io/joshuamart/websec0:latest
```

Open `http://localhost:8080`.

### docker compose (production)

```bash
mkdir websec0 && cd websec0
curl -sSL https://raw.githubusercontent.com/JoshuaMart/websec0/main/deploy/docker/docker-compose.yml -o docker-compose.yml
docker compose up -d
```

To override configuration, create a `config.yaml` in the same directory
(see [Configuration](#configuration) below) before running `docker compose up`.

### Verify image signature (cosign v3)

```bash
cosign verify \
  --certificate-identity-regexp="https://github.com/JoshuaMart/websec0/.github/workflows/release.yml@refs/tags/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  ghcr.io/joshuamart/websec0:latest
```

---

## Option 2 — Pre-built binary

### One-liner installer

```bash
curl -sSL https://raw.githubusercontent.com/JoshuaMart/websec0/main/scripts/install.sh | sh
```

Installs `websec0` to `/usr/local/bin`. Verifies SHA256 checksum automatically.

To also verify the cosign bundle:

```bash
VERIFY_COSIGN=1 curl -sSL https://raw.githubusercontent.com/JoshuaMart/websec0/main/scripts/install.sh | sh
```

To install the CLI tool instead:

```bash
WEBSEC0_BINARY=websec0-cli curl -sSL https://raw.githubusercontent.com/JoshuaMart/websec0/main/scripts/install.sh | sh
```

### Manual installation

1. Download the archive for your platform from the [Releases page](https://github.com/JoshuaMart/websec0/releases).

2. Verify the checksum:
   ```bash
   sha256sum --check checksums.txt
   ```

3. Verify the cosign bundle (requires [cosign](https://github.com/sigstore/cosign) ≥ 3.0):
   ```bash
   cosign verify-blob --bundle checksums.txt.bundle checksums.txt
   ```

4. Extract and install:
   ```bash
   tar xzf websec0_*_Linux_x86_64.tar.gz
   sudo mv websec0 /usr/local/bin/
   ```

5. Start the server:
   ```bash
   websec0
   # or with a config file:
   websec0 --config /etc/websec0/config.yaml
   ```

---

## Option 3 — Build from source

```bash
git clone https://github.com/JoshuaMart/websec0.git
cd websec0
make build-all        # builds frontend then Go binaries → bin/websec0 + bin/websec0-cli
./bin/websec0
```

---

## Configuration

WebSec0 loads configuration from (highest priority first):

1. CLI flags
2. Environment variables prefixed `WEBSEC0_`
3. Config file (`/etc/websec0/config.yaml` or path from `--config`)
4. Built-in defaults

### Example `config.yaml`

```yaml
server:
  listen: ":8080"
  read_timeout: 30s
  write_timeout: 60s

scanner:
  max_concurrent_scans: 50
  max_concurrent_checks_per_scan: 10
  per_check_timeout: 8s
  per_scan_timeout: 120s
  user_agent: "WebSec0/1.0 (+https://your-instance.example/about; passive-scan)"

storage:
  backend: memory        # memory | ristretto | redis
  ttl: 24h
  redis:
    url: ""              # e.g. redis://localhost:6379/0

ratelimit:
  # Per-source-IP cap on scan creation (POST /api/v1/scans).
  # Static assets, the SSE event stream, and result polling are NOT
  # counted — opening the web UI never burns this budget.
  per_ip:
    rate: 10
    period: 1h
  # Per-target cooldown: a hostname scanned within `cooldown` returns
  # the cached scan instead of launching a new one.
  per_target:
    cooldown: 5m

security:
  refuse_private_ranges: true
  refuse_loopback: true
  domain_blocklist:
    - ".gov"
    - ".mil"
    - ".gouv.fr"
    - ".gc.ca"

reports:
  default_visibility: public
  private_token_bytes: 32

logging:
  level: info
  format: json
  log_targets: false     # set to true to log scanned domains (off by default)
```

### Key environment variables

| Variable                             | Default  | Description                       |
|--------------------------------------|----------|-----------------------------------|
| `WEBSEC0_SERVER_LISTEN`            | `:8080`  | Listen address                    |
| `WEBSEC0_STORAGE_BACKEND`          | `memory` | `memory`, `ristretto`, or `redis` |
| `WEBSEC0_STORAGE_REDIS_URL`        | —        | Redis URL (if backend=redis)      |
| `WEBSEC0_SECURITY_REFUSE_PRIVATE_RANGES` | `true` | Block SSRF to private IPs   |
| `WEBSEC0_LOGGING_LEVEL`            | `info`   | `debug`, `info`, `warn`, `error`  |
| `WEBSEC0_LOGGING_LOG_TARGETS`      | `false`  | Log scanned domains               |

---

## Reverse proxy setup

WebSec0 serves HTTP only. Terminate TLS at the reverse proxy.

### Nginx

```nginx
server {
    listen 443 ssl;
    server_name websec0.example.com;

    ssl_certificate     /etc/ssl/certs/websec0.pem;
    ssl_certificate_key /etc/ssl/private/websec0.key;
    ssl_protocols       TLSv1.2 TLSv1.3;

    location / {
        proxy_pass         http://127.0.0.1:8080;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        # SSE requires buffering disabled
        proxy_buffering    off;
        proxy_read_timeout 180s;
    }
}
```

### Caddy

```caddy
websec0.example.com {
    reverse_proxy localhost:8080 {
        flush_interval -1   # required for SSE
    }
}
```

---

## Opting out of scans

If you want to prevent WebSec0 from scanning your domain, add the following
to your `robots.txt`:

```
User-agent: WebSec0
Disallow: /
```

WebSec0 respects this directive and cancels the scan with an explanatory message.

---

## Updating

### Docker

```bash
docker compose pull && docker compose up -d
```

### Binary

Re-run the installer — it always fetches the latest release unless
`WEBSEC0_VERSION` is set.

---

## Reporting abuse

If you believe WebSec0 is being used to scan your infrastructure without
authorization, contact **abuse@websec0.example** (replace with your instance's
address). We target a response time under 72 hours.
