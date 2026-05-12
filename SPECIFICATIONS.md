# WebSec0 — Specifications

> Status: **draft v0.2** · Last update: 2026-05-12

This document is the source of truth for the v1 scope of WebSec0. Anything
not listed here is **out of scope**.

---

## 1. Vision

A modern, opinionated, **passive** web security scanner that any sysadmin,
developer or AI agent can point at a hostname and get, in under 10 seconds:

1. A **TLS grade** (A+ → F) based on a transparent, documented scoring model.
2. A **Headers grade** (A+ → F) based on the same kind of model, applied to
   HTTP security headers.
3. A list of **custom findings** (`security.txt`, `robots.txt`, …) without
   contribution to the grades — pure additional signal.
4. **Copy-paste remediation snippets** for each actionable finding.

Two audiences, treated at parity:

- **Humans** — clean report, prioritised by impact, copy-paste fixes.
- **AI agents** — `GET /api/v1/checks` catalog, self-sufficient findings
  (no external fetch needed), shipped [`SKILL.md`](./skills/websec0/SKILL.md).

## 2. Non-goals

- ❌ **Active testing** — no fuzzing, no exploitation, no auth brute-force.
- ❌ **DNS / Email security** — DNSSEC, DMARC, SPF, DKIM, MTA-STS are *not*
  in scope.
- ❌ **Compliance scoring** (PCI DSS, ANSSI, BSI, …) — out of scope.
- ❌ **Exposed sensitive files probing** (`.env`, `.git`, …) — out of scope.
- ❌ **Vulnerability scanning of the underlying application** — WebSec0
  inspects *configuration*, not the app behind it.
- ❌ **Crawling** — one hostname, one port. No link following.
- ❌ **Per-stack remediation matrices** — one canonical example (Nginx)
  per finding, not eight.
- ❌ **TLS client simulation** — not in v1.

---

## 3. Architecture

```
                    ┌─────────────────────────────────────────────┐
                    │                  websec0                    │
                    │           single static binary              │
                    │                                             │
  HTTPS request ──▶ │  Chi router  ──▶  scan engine  ──▶  cache   │
                    │       │              │                      │
                    │       │              ├─ tls probe (stdlib)  │
                    │       │              ├─ sslv2 raw probe     │
                    │       │              ├─ sslv3 raw probe     │
                    │       │              ├─ http header probe   │
                    │       │              └─ custom checks       │
                    │       │                     ↑               │
                    │       │              centralised safe HTTP  │
                    │       │              client (IP-pinned)     │
                    │       │                                     │
                    │       └─▶  embed.FS  (Astro static build)   │
                    └─────────────────────────────────────────────┘
```

- **Backend**: Go 1.26+, `chi` router, stdlib `crypto/tls` for TLS 1.0 →
  TLS 1.3, custom raw TCP probes for SSLv2 and SSLv3. No `zcrypto`, no cgo.
- **Frontend**: Astro 6 (static output) + Preact islands. Built artefacts
  are `//go:embed`-ed into the binary. No Node runtime in production.
- **Storage**: in-memory LRU cache, configurable TTL. No DB. Restart loses
  history (assumed).
- **Distribution**: one binary, distroless Docker image, ~15 MB.

### 3.1 Request lifecycle

1. `POST /api/v1/scan { "host": "example.com", "list_in_history": false }`
2. Input validation, resolution and IP pinning (see §8).
3. Engine runs in parallel against the pinned IP:
   - Modern TLS probe (versions, ciphers, certificate chain, OCSP, SCTs)
   - Raw SSLv2 ClientHello probe
   - Raw SSLv3 ClientHello probe
   - HTTP/HTTPS request → header inventory
   - Custom checks (`/.well-known/security.txt`, `/robots.txt`)
4. Scoring engine produces `tls_score`, `headers_score`, `findings[]`.
5. Result stored in cache under a content-addressable ID, returned to client.
6. Frontend renders `/r/<id>` by fetching `GET /api/v1/scan/<id>`.

---

## 4. Scope v1

### 4.1 TLS checks

| Category | What we inspect |
|---|---|
| **Protocol support** | SSLv2 (raw probe), SSLv3 (raw probe), TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3 |
| **Cipher suites** | Enumeration per protocol, AEAD vs CBC, PFS yes/no, key size, server vs client preference |
| **Key exchange** | Curve / DH group, key size, ECDHE vs DHE vs RSA |
| **Certificate** | Subject, SAN, issuer chain, key algorithm and size, signature algorithm, validity, days remaining, SHA-256 fingerprint, serial |
| **Chain validation** | Path validation against Mozilla root store, intermediate completeness, name match |
| **Revocation** | OCSP stapling presence, OCSP response (if stapled), CRL distribution point check best-effort |
| **Certificate Transparency** | Embedded SCTs (count, log operators) |
| **Session** | Session tickets, session IDs, 0-RTT advertised |
| **Known TLS weaknesses** (presence-based, no exploitation) | Heartbleed (version-based), ROBOT, POODLE, BEAST, CRIME, Logjam, FREAK, DROWN, Sweet32, Lucky13, Raccoon, Ticketbleed |

### 4.2 Header checks

#### Core (contribute to Headers grade)

| Header | Required value (recommended) | Weight |
|---|---|---|
| `Strict-Transport-Security` | `max-age ≥ 31536000; includeSubDomains` | 20 |
| `Content-Security-Policy` | Present, not `unsafe-inline` in `script-src` | 25 |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN`, or covered by CSP `frame-ancestors` | 15 |
| `X-Content-Type-Options` | `nosniff` | 10 |
| `Referrer-Policy` | Any restrictive value (`strict-origin-when-cross-origin`, …) | 15 |
| `Permissions-Policy` | Present | 15 |

Total: 100. Grade thresholds: A+ ≥ 95, A ≥ 85, B ≥ 70, C ≥ 55, D ≥ 40, E ≥ 25, F < 25.

#### Additional (bonus / malus, capped influence)

| Signal | Effect |
|---|---|
| `Cross-Origin-Opener-Policy: same-origin` | +5 bonus |
| `Cross-Origin-Embedder-Policy` | +3 bonus |
| `Cross-Origin-Resource-Policy` | +2 bonus |
| `Server` header leaks version (e.g. `nginx/1.27.1`) | −5 malus |
| `Set-Cookie` without `Secure` on HTTPS | −5 malus per cookie (capped −10) |
| `Set-Cookie` without `HttpOnly` (session-looking) | −3 malus |
| `Set-Cookie` without `SameSite` | −3 malus |
| `Access-Control-Allow-Origin: *` with credentials or sensitive endpoint | −10 malus |

The total is clamped to [0, 100] before grading.

### 4.3 Custom checks (findings, no grade contribution)

| Check | What | Output |
|---|---|---|
| `security.txt` | Presence at `/.well-known/security.txt`, RFC 9116 conformance (required fields, expiry, signature) | `pass` / `fail` / `warn` |
| `robots.txt` | Presence at `/robots.txt`, parse validity, detection of overly permissive or suspicious directives (e.g. `Disallow: /admin` which leaks the existence of `/admin`) | `pass` / `fail` / `warn` / `info` |

---

## 5. Scoring model

### 5.1 TLS score

Four sub-scores 0-100:

- **Certificate score** (weight 30%)
- **Protocol Support score** (weight 30% of remaining 70%)
- **Key Exchange score** (weight 30% of remaining 70%)
- **Cipher Strength score** (weight 40% of remaining 70%)

Formula:

```
final = (cert × 0.30) + (((proto + kx + cipher) / 3) × 0.70)
```

Then apply **floors** (final grade is the worst of the formula and the floors):

| Condition | Cap |
|---|---|
| SSLv2 enabled | F |
| SSLv3 enabled | F |
| Certificate expired | T (no trust) |
| Certificate self-signed or untrusted | T |
| Hostname mismatch | T |
| TLS 1.0 or 1.1 enabled | C |
| No forward secrecy on any suite | C |
| Anonymous cipher offered | F |
| Export-grade cipher offered | F |
| RC4 offered | F |
| 3DES offered (Sweet32) | C |

Grade mapping: A+ ≥ 95 (with HSTS preload eligible), A ≥ 80, B ≥ 65, C ≥ 50, D ≥ 35, E ≥ 20, F < 20.

### 5.2 Headers score

See §4.2 — sum of core weights + bonuses − maluses, clamped to [0, 100].

### 5.3 Custom findings

No score. Surfaced as a list with `pass` / `fail` / `warn` / `info` and a
remediation block per finding.

---

## 6. API surface

All endpoints under `/api/v1`. JSON in, JSON out. No auth in v1 (self-hosted
assumption — gate it behind a reverse proxy if exposing publicly).

### 6.1 `POST /api/v1/scan`

Trigger a new scan.

```json
// request
{
  "host": "example.com",
  "port": 443,
  "list_in_history": false,
  "fresh": false   // if true, bypass cache
}

// response 200
{
  "id": "8a31ffd219...",
  "host": "example.com",
  "port": 443,
  "resolved_ip": "203.0.113.42",
  "scanned_at": "2026-05-12T14:32:00Z",
  "duration_ms": 8420,
  "tls": { /* see §6.4 */ },
  "headers": { /* see §6.5 */ },
  "custom": [ /* see §6.6 */ ]
}
```

Error responses are typed:

```json
// 400 — input rejected before scan
{ "error": { "code": "invalid_scheme", "message": "only https:// is accepted" } }
// 403 — target blocked by security policy
{ "error": { "code": "private_target_blocked", "message": "203.0.113.42 resolves to a private range" } }
// 408 — scan budget exceeded
{ "error": { "code": "scan_timeout", "message": "scan exceeded 15s budget" } }
```

### 6.2 `GET /api/v1/scan/:id`

Retrieve a cached scan by ID. 404 if expired or unknown.

### 6.3 `GET /api/v1/checks`

Machine-readable catalog of every check WebSec0 performs. Used by the
SKILL.md and by AI agents to reason about coverage without scanning.

```json
{
  "version": "1.0.0",
  "checks": [
    {
      "id": "tls.protocol.sslv2",
      "category": "tls.protocol",
      "title": "SSLv2 enabled",
      "severity_when_fail": "critical",
      "score_impact": "caps TLS grade at F",
      "remediation": {
        "summary": "Disable SSLv2 in your TLS configuration.",
        "example_stack": "nginx",
        "example_snippet": "ssl_protocols TLSv1.2 TLSv1.3;"
      }
    }
  ]
}
```

Each check ships **one** canonical example (Nginx by default). Other stacks
are deliberately out of scope.

### 6.4 TLS payload shape

```json
{
  "grade": "A+",
  "scores": {
    "certificate": 100,
    "protocol_support": 100,
    "key_exchange": 95,
    "cipher_strength": 90,
    "final": 96
  },
  "protocols": [
    { "name": "TLS 1.3", "offered": true,  "probe": "stdlib" },
    { "name": "TLS 1.2", "offered": true,  "probe": "stdlib" },
    { "name": "SSL 3.0", "offered": false, "probe": "raw_clienthello" },
    { "name": "SSL 2.0", "offered": false, "probe": "raw_clienthello" }
  ],
  "ciphers": [ /* per-protocol cipher arrays */ ],
  "certificate_chain": [ /* leaf → root */ ],
  "vulnerabilities": [ /* presence-based finding list */ ]
}
```

### 6.5 Headers payload shape

```json
{
  "grade": "B",
  "score": 72,
  "core": {
    "strict-transport-security": { "present": true,  "value": "max-age=63072000; includeSubDomains; preload", "status": "pass" },
    "content-security-policy":   { "present": false, "status": "fail" },
    "x-frame-options":           { "present": true,  "value": "DENY", "status": "pass" }
  },
  "additional": {
    "server":            { "value": "nginx/1.27.1", "status": "warn" },
    "set-cookie":        [ { "name": "session", "secure": false, "httponly": true, "samesite": null, "status": "fail" } ],
    "access-control-allow-origin": { "value": null, "status": "info" }
  }
}
```

### 6.6 Custom findings shape

```json
[
  {
    "id": "custom.security_txt",
    "title": "security.txt",
    "status": "pass",
    "details": {
      "url": "https://example.com/.well-known/security.txt",
      "rfc9116_compliant": true,
      "expires": "2026-12-31T00:00:00Z",
      "signed": true,
      "contact_count": 2
    }
  },
  {
    "id": "custom.robots_txt",
    "title": "robots.txt",
    "status": "warn",
    "details": {
      "url": "https://example.com/robots.txt",
      "size_bytes": 412,
      "parseable": true,
      "suspicious_disallow": ["/admin", "/internal"]
    }
  }
]
```

---

## 7. Configuration

Single YAML file, location resolved in this order:
`$WEBSEC0_CONFIG` env var → `./websec0.yaml` → `/etc/websec0/websec0.yaml`.

```yaml
server:
  listen: "0.0.0.0:8080"
  trusted_proxies: []           # for X-Forwarded-For when behind a reverse proxy

scan:
  timeout: 15s                  # global per-scan budget
  parallel_probes: true
  follow_redirects: true        # for header probing
  max_redirects: 3

security:
  allow_private_targets: false  # public instance: false. self-hosted internal: true.
  allow_custom_ports: false     # public instance: false. self-hosted: true.
  allowed_schemes: ["https"]    # http will be a v1.1 opt-in
  extra_blocked_cidrs: []       # operator-supplied additional blocks

cache:
  ttl: 24h                      # how long a scan ID remains retrievable
  max_entries: 1000             # LRU bound

history:
  enabled: true                 # exposes the "Recent scans" strip on the landing
  retention: 7d                 # scans listed publicly are purged after this
  rate_limit:
    per_ip: "10/hour"
    per_host: "1/minute"        # avoid hammering a target

frontend:
  enabled: true                 # serve the embedded UI at /
  base_path: "/"

telemetry:
  anonymous_stats: false        # if true, send scan counts (no hostnames) to a stats endpoint
```

---

## 8. Security model — SSRF, DNS rebinding, target safety

The scanner is a request-forging tool by nature. On a public instance, that
turns it into a potential SSRF gadget if not constrained. Defence is in
three layers.

### 8.1 Layer 1 — Input validation

Applied before any network activity:

- Scheme must be in `security.allowed_schemes` (v1: `["https"]` only).
  - If the user submits a bare hostname, `https://` is prefixed.
  - `http://`, `file://`, `gopher://`, `ftp://`, `ldap://`, `dict://`, etc.
    are rejected with `invalid_scheme`.
- Port: defaults to 443. If a custom port is supplied:
  - `allow_custom_ports: false` → rejected with `custom_port_blocked`.
  - `allow_custom_ports: true` → accepted, port must be in [1, 65535].
- Hostname rules:
  - IP literals (`https://192.168.1.1`, `https://[::1]`) are rejected
    unconditionally — the scanner is hostname-oriented.
  - Userinfo (`https://user:pass@host`) is rejected.
  - Query string and fragment are stripped.
  - The hostname must be a valid FQDN: at least one dot, valid IDN/Punycode,
    not a TLD on its own, no trailing dot weirdness.

### 8.2 Layer 2 — Resolution & IP pinning (anti-rebinding)

A single resolver, a single pinned IP per scan:

```go
// pseudo-Go
ips, err := resolver.LookupNetIP(ctx, "ip", host)        // ① one resolution
ip, err := pickAllowedIP(ips, policy)                    // ② policy check
if err != nil { return blocked(err) }
dialer := &net.Dialer{
    Control: func(network, address string, c syscall.RawConn) error {
        // ③ every Dial() in the scan must hit `ip`, no exceptions
        target, _ := netip.ParseAddrPort(address)
        if target.Addr() != ip { return errIPPinViolation }
        return nil
    },
}
// TLS uses `host` for SNI and the HTTP layer uses `host` for the Host header,
//    but the underlying connect is always to the pinned `ip`.
```

This neutralises:

- **DNS rebinding** — only the first resolution matters; subsequent ones
  are ignored.
- **TOCTOU** — the IP at policy-check time is the IP at connect time.
- **Trickery via CNAMEs / GeoDNS** — the resolved set is computed once.

### 8.3 Layer 3 — IP policy

The pinned IP is checked against a deny-list. Implementation uses
`net/netip` stdlib helpers:

```go
func isBlocked(ip netip.Addr) bool {
    if ip.IsLoopback() ||
       ip.IsLinkLocalUnicast() ||   // covers 169.254/16 → cloud metadata
       ip.IsLinkLocalMulticast() ||
       ip.IsMulticast() ||
       ip.IsUnspecified() ||
       ip.IsPrivate() {              // RFC1918 + RFC4193
        return true
    }
    return inExtraBlockedRanges(ip)
}
```

The "extras" list (small, hardcoded) catches what the stdlib does not flag:

- `100.64.0.0/10` — CGNAT
- `192.0.0.0/24`, `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` — IETF test nets / docs
- `198.18.0.0/15` — benchmark range
- `240.0.0.0/4` — reserved future-use
- IPv6: `2001:db8::/32` (docs), `64:ff9b::/96` (NAT64), `100::/64` (discard)
- IPv4-mapped IPv6 (`::ffff:0:0/96`) is unwrapped before checking.

Operators can extend via `security.extra_blocked_cidrs`.

If `security.allow_private_targets: true`, layer 3 is **disabled**. Layer 2
(IP pinning) stays on regardless — TOCTOU protection is always useful.

### 8.4 Layer 4 — Behavioural limits

- **Per-host rate limit**: `1/minute` by default — prevents using the
  scanner as a flooding amplifier.
- **Per-IP rate limit (client)**: `10/hour` by default — limits abuse.
- **Scan budget**: hard 15s timeout, no I/O retries beyond a single attempt
  per probe.
- **Body cap**: 1 MB for `robots.txt` / `security.txt` fetches.
- **Redirect cap**: 3 hops max for header probing. Each redirect target is
  *not* re-pinned — if a redirect points to a different IP, the scan flags
  it as an "off-host redirect" finding and stops following.

---

## 9. SSLv2 / SSLv3 detection

Go's `crypto/tls` does not support SSLv2 or SSLv3. `zmap/zcrypto` defines
the constants but actively rejects negotiation (`SSLv3 is cryptographically
broken, and is no longer supported by this package`). We therefore implement
both detections at the raw TCP layer — we do not need a full handshake, only
to determine whether the server *speaks* the protocol.

### 9.1 SSLv2

Send a hand-crafted **SSLv2 CLIENT-HELLO** record (record type 0x01, the
deprecated `\x80\x2e` length-prefixed format) advertising 7 cipher specs
including `SSL_CK_RC4_128_WITH_MD5` (`0x010080`). Read up to 5 bytes:

| First byte(s) | Conclusion |
|---|---|
| `0x16 0x03 …` (TLS record framing) | SSLv2 **not** supported |
| `0x04 …` (SSLv2 SERVER-HELLO) | SSLv2 **supported** |
| Reset / timeout | SSLv2 **not** supported |

### 9.2 SSLv3

Send a TLS-record-framed ClientHello with `record.version = 0x03 0x00` and
`client_hello.version = 0x03 0x00`. Read the first 5 bytes of the response:

| Response | Conclusion |
|---|---|
| `0x16 0x03 0x00 …` (ServerHello with version SSLv3) | SSLv3 **supported** |
| `0x15 …` (alert: `protocol_version` or `handshake_failure`) | SSLv3 **not** supported |
| Negotiated up to `0x03 0x01` or higher | SSLv3 **not** supported |

Each probe is ~50 lines of Go, no cgo, no external dependency. Together
they let us cap the TLS grade at F as soon as either is detected.

---

## 10. UX principles

These are the rules that drive every UI and API decision.

1. **One hostname, one input** — the landing has a single text field. No
   configuration step before the scan.
2. **Two grades, side by side** — TLS and Headers are equally visible.
   Never collapse them into one number.
3. **Every finding is self-sufficient** — title + impact + remediation in
   the report itself. No "click here for details" leading to an external
   docs site.
4. **Remediation is copy-paste** — one canonical example per finding,
   ready to drop into the user's config.
5. **Sorted by ROI** — findings are ordered by `severity × ease_of_fix`, so
   the user knows what to do first.
6. **Shareable URLs** — `/r/<id>` is permanent (within cache TTL), reflects
   the exact state of the scan, no auth needed to view.
7. **AI parity** — anything the UI displays is in the JSON. Anything in the
   JSON is in the catalog at `/api/v1/checks`.

---

## 11. Project structure (target)

```
.
├── cmd/websec0/             # main entrypoint
├── internal/
│   ├── api/                 # chi router, handlers, middleware
│   ├── scan/                # orchestrator, parallel probes
│   ├── tls/                 # modern TLS probe (crypto/tls based)
│   ├── sslv2/               # raw SSLv2 ClientHello
│   ├── sslv3/               # raw SSLv3 ClientHello
│   ├── headers/             # HTTP header inspection + grading
│   ├── custom/              # security.txt, robots.txt
│   ├── scoring/             # TLS and Headers grade engines
│   ├── safehttp/            # IP-pinned dialer, deny-list, rate limit (§8)
│   ├── cache/               # LRU + TTL
│   └── config/              # YAML loader, validation
├── catalog/                 # JSON source of the check catalog (compiled into binary)
├── web/                     # Astro 6 project (built into web/dist, then embedded)
│   ├── src/
│   │   ├── pages/
│   │   │   ├── index.astro          # landing
│   │   │   └── r/[id].astro         # report page (Preact island)
│   │   └── components/              # Preact components ported from maquette
│   └── astro.config.mjs
├── skills/websec0/SKILL.md
├── websec0.yaml.example
├── Dockerfile               # distroless
├── README.md
└── SPECIFICATIONS.md
```
