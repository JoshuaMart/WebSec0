---
name: websec0
description: >-
  Audits a hostname's TLS configuration and HTTP security headers via the
  WebSec0 API and interprets the resulting grades, vulnerabilities and
  remediation snippets. Use when the caller wants a passive security report for
  a public website, needs to interpret a websec0 scan response, or asks about
  HSTS / CSP / cipher health of a known host.
metadata:
  tools: [http]
  inputs:
    host: {type: string, required: true, description: "FQDN, no scheme"}
    port: {type: integer, required: false, default: 443}
    list_in_history: {type: boolean, required: false, default: false}
    fresh: {type: boolean, required: false, default: false}
  outputs:
    scan_result: "scan.Result envelope (see §5.1)"
---

# WebSec0

WebSec0 is a passive web-security scanner. It points at one hostname,
inspects what the server publishes (TLS handshake, certificate chain,
HTTP response headers, `security.txt`, `robots.txt`) and returns two
grades plus a list of findings — each with a self-contained remediation
snippet. It does not fuzz, exploit, brute-force, or crawl. One host,
one port, ~10 seconds.

## 1. Scope and non-goals

In scope:
- TLS protocol matrix (SSL 2.0 / 3.0 / TLS 1.0 / 1.1 / 1.2 / 1.3)
- Cipher suites, PFS, AEAD, server vs client preference
- Certificate chain trust, OCSP stapling, session resumption
- Known TLS weaknesses (POODLE, BEAST, DROWN, Sweet32, RC4, Heartbleed,
  Lucky13, Ticketbleed) by passive heuristic
- HTTP security headers (HSTS, CSP, XFO, XCTO, Referrer-Policy,
  Permissions-Policy) + COOP/COEP/CORP, Server, Set-Cookie, ACAO
- Custom checks: `security.txt` (RFC 9116) and `robots.txt`

Explicitly **out of scope**: active testing, DNS/email security
(DMARC/SPF/DKIM/MTA-STS), compliance scoring, app-level vuln scanning,
crawling, multi-host or multi-port enumeration.

## 2. Quick start

A single POST returns the entire report. Default base URL is
`https://www.websec0.com`.

```bash
curl -sS -X POST https://www.websec0.com/api/v1/scan \
  -H 'Content-Type: application/json' \
  -d '{"host":"example.com"}' | jq .
```

Subsequent calls with the same `host:port` are served from cache. Pass
`{"fresh": true}` to bypass the cache and re-run the probes.

## 3. API surface

All endpoints live under `/api/v1`. No authentication. Every response
is JSON. Errors share a typed envelope: `{"error":{"code":"...","message":"..."}}`.

### 3.1 POST `/api/v1/scan`

Initiate a scan.

Request body fields:

| Field             | Type    | Required | Default | Notes                                          |
|-------------------|---------|----------|---------|------------------------------------------------|
| `host`            | string  | yes      | —       | Lowercase ASCII FQDN. No scheme, no path.      |
| `port`            | integer | no       | 443     | Non-default ports may be refused (see policy). |
| `list_in_history` | bool    | no       | false   | If true, becomes visible to `/api/v1/history`. |
| `fresh`           | bool    | no       | false   | Bypass cache.                                  |

Unknown fields are rejected.

Success: `200 OK` with a `scan.Result` (see §5.1).

Errors:

| HTTP | code                     | when                                                |
|------|--------------------------|-----------------------------------------------------|
| 400  | `invalid_json`           | malformed body or unknown field                     |
| 400  | `invalid_host`           | empty or syntactically invalid hostname             |
| 400  | `invalid_scheme`         | scheme not in allowed list                          |
| 400  | `ip_literal`             | hostname is a raw IPv4/IPv6                         |
| 400  | `userinfo_in_url`        | URL contained `user:pass@`                          |
| 403  | `custom_port_blocked`    | non-standard port refused by policy                 |
| 403  | `private_target_blocked` | resolved IP is loopback/private/link-local          |
| 408  | `scan_timeout`           | scan exceeded its deadline                          |
| 429  | `rate_limited`           | per-IP or per-host budget exhausted                 |
| 502  | `no_allowed_ip`          | DNS returned zero usable IPs (all blocked or empty) |
| 500  | `internal_error`         | unexpected                                          |

Rate limits (defaults): 10 requests/hour per client IP, 1 request/min
per target host. Both must pass.

### 3.2 GET `/api/v1/scan/{id}`

Return the cached `scan.Result` by its `id` (UUID). `404 not_found` if
the entry has expired or never existed. `400 invalid_id` on empty id.

### 3.3 GET `/api/v1/checks`

Return the immutable check catalog (see §5.5). Sent with
`Cache-Control: public, max-age=3600`. Use this to look up
human-readable titles and copy-paste remediation snippets for any
finding the scanner reports.

Shape:

```json
{
  "version": "1.0.0",
  "checks": [
    {
      "id": "tls.protocol.sslv2",
      "category": "tls.protocol",
      "title": "SSLv2 enabled",
      "severity_when_fail": "critical",
      "score_impact": "Caps TLS grade at F",
      "remediation": {
        "summary": "Disable SSLv2 …",
        "example_stack": "nginx",
        "example_snippet": "ssl_protocols TLSv1.2 TLSv1.3;"
      }
    }
  ]
}
```

38 checks across 7 categories: `tls.protocol`, `tls.chain`, `tls.cipher`,
`tls.vulnerability`, `headers.core`, `headers.additional`, `custom`.

### 3.4 GET `/api/v1/history?limit=N`

Return the most recent scans submitted with `list_in_history: true`.
`limit` defaults to 20 and is capped at 100. Each entry:

```json
{"id":"…","host":"…","scanned_at":"…","tls_grade":"A","headers_grade":"B","highest_tls":"TLS 1.3"}
```

`400 invalid_limit` if `limit` is not a positive integer.

## 4. Grading model

### 4.1 Grade alphabet

A scan produces two grades — TLS and Headers — drawn from this
alphabet, best to worst: `A+ A B C D E F T`.

`T` is reserved for certificate-trust failures (expired, self-signed,
hostname mismatch, untrusted chain). It outranks `F`: a `T` means the
report cannot be trusted as a TLS report at all, the chain is broken.

### 4.2 TLS grade

Four sub-scores are computed independently from the TLS observation,
each in `[0, 100]`:

| Sub-score          | Built from                                                       |
|--------------------|------------------------------------------------------------------|
| `certificate`      | Leaf key algorithm (ECDSA/Ed25519 > RSA > DSA) and days-to-expiry|
| `protocol_support` | Worst and best protocol offered, averaged                        |
| `key_exchange`     | Binary: 90 if any cipher offers PFS, else 40                     |
| `cipher_strength`  | Worst and best bit strength offered, averaged                    |

The final score is a weighted aggregate:

```
final = certificate · 0.30 + ((protocol_support + key_exchange + cipher_strength) / 3) · 0.70
```

Thresholds: A+ ≥ 95, A ≥ 80, B ≥ 65, C ≥ 50, D ≥ 35, E ≥ 20, else F.

Floors (override the score-derived grade):

| Observation                                  | Grade cap |
|----------------------------------------------|-----------|
| Chain trust ≠ `trusted`                      | **T**     |
| SSL 2.0 or 3.0 offered                       | **F**     |
| RC4 / anonymous / export cipher offered      | **F**     |
| 3DES cipher offered                          | **C**     |
| No PFS available (no ECDHE/DHE)              | **C**     |
| TLS 1.0 or 1.1 offered                       | **C**     |

A+ gate: a final score of ≥ 95 is only awarded A+ when the *Headers*
report carries an HSTS line with `max-age ≥ 31536000` (one year),
`includeSubDomains`, and `preload`. Otherwise the grade is capped at A.
A scan with no Headers report (e.g. the HTTPS endpoint failed) cannot
earn A+.

### 4.3 Headers grade

The score starts at the weighted sum of six core headers:

| Header                       | Weight |
|------------------------------|--------|
| `content-security-policy`    | 25     |
| `strict-transport-security`  | 20     |
| `x-frame-options`            | 15     |
| `referrer-policy`            | 15     |
| `permissions-policy`         | 15     |
| `x-content-type-options`     | 10     |

Each header contributes its full weight on `pass`, half on `warn`,
zero on `fail`. Then bonuses and maluses adjust the score:

| Signal                                              | Δ score              |
|-----------------------------------------------------|----------------------|
| `Cross-Origin-Opener-Policy: same-origin`           | +5                   |
| `Cross-Origin-Embedder-Policy` present              | +3                   |
| `Cross-Origin-Resource-Policy` present              | +2                   |
| `Server` header leaks a version                     | −5                   |
| Each `Set-Cookie` without `Secure`                  | −5 (capped at −10)   |
| Each `Set-Cookie` without `SameSite`                | −3                   |
| Session-like cookie (`session`/`auth`/`token`/…) without `HttpOnly` | −3   |
| `Access-Control-Allow-Origin: *`                    | −10                  |

Result clamped to `[0, 100]`. Thresholds: A+ ≥ 95, A ≥ 85, B ≥ 70,
C ≥ 55, D ≥ 40, E ≥ 25, else F.

### 4.4 Headers ↔ TLS interaction

Headers are scored first. The parsed HSTS values are then passed back
into the TLS A+ gate (§4.2). If Headers cannot be fetched (probe error
not recoverable), TLS A+ is unreachable even at a perfect score.

## 5. Interpreting findings

### 5.1 The `scan.Result` envelope

```json
{
  "id":          "uuid",
  "host":        "example.com",
  "port":        443,
  "resolved_ip": "93.184.216.34",
  "scanned_at":  "2026-05-13T07:18:00Z",
  "duration_ms": 4321,
  "tls":     { "...": "TLSReport, omitempty"     },
  "headers": { "...": "HeadersReport, omitempty" },
  "custom":  [ { "...": "CustomFinding"          } ]
}
```

`tls`, `headers`, `custom` are independent. A probe failure on one
does not invalidate the others.

### 5.2 TLS findings

- `tls.grade` (string) and `tls.scores` (`{certificate, protocol_support,
  key_exchange, cipher_strength, final}`).
- `tls.protocols`: list of `{name, offered, probe}`. Names include
  `SSL 2.0`, `SSL 3.0`, `TLS 1.0`, …, `TLS 1.3`. `probe` is `stdlib`
  for modern Go probes and `raw_clienthello` for the SSLv2/SSLv3 raw
  probes.
- `tls.ciphers`: each `{protocol, name, code, strength, aead, pfs, level}`.
  `level` is one of `good | warn | bad | info`.
- `tls.cipher_preference`: `"server"` | `"client"` | `""`.
- `tls.certificate_chain`: leaf-to-root certs with `step`, `cn`, `issuer`,
  `not_before`, `not_after`, `days_left`, `key_alg`, `sig_alg`, `san[]`.
- `tls.chain_trust`: `trusted` | `expired` | `self_signed` |
  `hostname_mismatch` | `untrusted` (capping the grade at T when ≠ trusted).
- `tls.ocsp_stapling` (bool) and `tls.ocsp_status` (`good` | `revoked`
  | `unknown` | `""`).
- `tls.session_resumption`: `supported` | `not_supported` | `""`.
- `tls.vulnerabilities`: each `{id, cve, state, level, body}`.

### 5.3 Headers findings

- `headers.grade`, `headers.score`.
- `headers.core` is a map keyed by the lowercase header name
  (`content-security-policy`, `strict-transport-security`, …). Each
  value is `{present, value?, status}` where `status ∈ pass|warn|fail`.
- `headers.additional` carries `server`, `set-cookie[]`, `access-control-
  allow-origin`, `cross-origin-opener-policy`, `cross-origin-embedder-
  policy`, `cross-origin-resource-policy`.
- `headers.probed_host` is set only when the scan followed an apex →
  `www` sibling redirect (e.g. `cloudflare.com` → `www.cloudflare.com`).
  When present, the headers in the report come from that sibling, not
  from the originally submitted host.

### 5.4 Custom findings

`custom` is an array. Each entry has `{id, title, status, details}`:

| `id`                  | `details` keys                                                                 |
|-----------------------|--------------------------------------------------------------------------------|
| `custom.security_txt` | `url, rfc9116_compliant, expires, signed, contact_count, note?`                |
| `custom.robots_txt`   | `url, size_bytes, parseable, suspicious_disallow?, note?`                      |

`details.expires` may be the zero-time `"0001-01-01T00:00:00Z"` when
no Expires field was present in the file — treat that value as "no
expiry set".

### 5.5 Catalog ID mapping (important)

Vulnerability findings emitted by the scanner at runtime use bare
short names; the catalog uses dotted IDs. To resolve a runtime finding
to a catalog entry (and hence to a remediation snippet), lowercase the
runtime id and prefix it with `vuln.`:

| Runtime `id` | Catalog `id`        |
|--------------|---------------------|
| `POODLE`     | `vuln.poodle`       |
| `BEAST`      | `vuln.beast`        |
| `DROWN`      | `vuln.drown`        |
| `Sweet32`    | `vuln.sweet32`      |
| `RC4`        | `vuln.rc4`          |
| `Heartbleed` | `vuln.heartbleed`   |
| `Lucky13`    | `vuln.lucky13`      |
| `Ticketbleed`| `vuln.ticketbleed`  |

Header, cipher, protocol and custom findings already share a single
dotted-ID space and need no translation.

## 6. Worked example — `cloudflare.com`

Request:

```bash
curl -sS -X POST http://localhost:8080/api/v1/scan \
  -H 'Content-Type: application/json' \
  -d '{"host":"cloudflare.com"}'
```

Response (excerpt, fields trimmed for clarity):

```json
{
  "id": "9af3…",
  "host": "cloudflare.com",
  "port": 443,
  "resolved_ip": "104.16.132.229",
  "tls": {
    "grade": "C",
    "scores": {"certificate":100,"protocol_support":85,
               "key_exchange":90,"cipher_strength":90,"final":91},
    "protocols": [
      {"name":"TLS 1.3","offered":true,"probe":"stdlib"},
      {"name":"TLS 1.2","offered":true,"probe":"stdlib"},
      {"name":"TLS 1.1","offered":true,"probe":"stdlib"},
      {"name":"TLS 1.0","offered":true,"probe":"stdlib"},
      {"name":"SSL 3.0","offered":false,"probe":"raw_clienthello"},
      {"name":"SSL 2.0","offered":false,"probe":"raw_clienthello"}
    ],
    "vulnerabilities": [
      {"id":"BEAST",  "cve":"CVE-2011-3389","state":"vulnerable","level":"bad",
       "body":"TLS 1.0 is enabled — CBC paths are exploitable."},
      {"id":"Lucky13","cve":"CVE-2013-0169","state":"vulnerable","level":"bad",
       "body":"TLS 1.0/1.1 with a CBC cipher is offered."},
      {"id":"Sweet32","cve":"CVE-2016-2183","state":"vulnerable","level":"bad",
       "body":"A 3DES cipher is offered (64-bit block)."}
    ],
    "chain_trust": "trusted",
    "ocsp_stapling": true,
    "ocsp_status": "good"
  },
  "headers": {
    "grade": "C",
    "score": 67,
    "probed_host": "www.cloudflare.com",
    "core": {
      "content-security-policy":   {"present":true, "status":"pass"},
      "strict-transport-security": {"present":true, "status":"pass"},
      "x-frame-options":           {"present":true, "status":"pass"},
      "permissions-policy":        {"present":true, "status":"pass"},
      "x-content-type-options":    {"present":true, "status":"pass"},
      "referrer-policy":           {"present":true, "status":"pass"}
    }
  }
}
```

How to read it:

1. **Headline**: TLS C, Headers C. Chain is trusted (no `T` floor), so
   the C reflects real configuration debt, not certificate trouble.
2. **Why TLS is C, not A**: `final = 91` (would map to A by threshold)
   but the floor applies — TLS 1.0 is offered (`tls.protocols`) and
   the cipher list (omitted here) includes 3DES + RC4-free CBC suites.
   That caps the grade at **C** independently of the score.
3. **Vulnerabilities to act on**: BEAST and Lucky13 share one fix
   (disable TLS 1.0 and 1.1). Sweet32 requires removing the 3DES
   cipher (`TLS_RSA_WITH_3DES_EDE_CBC_SHA`, code `0x000A`). Heartbleed
   is not listed, so the Server-header heuristic did not match.
4. **Headers C, not better**: every core header is `pass`, so the
   weighted base is 100. The drop to 67 comes from the bonuses/maluses
   block — typically `Set-Cookie` cookies (here `__cf_bm` without all
   modern attributes) and the `Server: cloudflare` header which leaks
   a vendor name (no version digits → no leak penalty in this case;
   the score loss is mostly from cookies).
5. **`probed_host`**: the scan started on `cloudflare.com`, which
   301'd off-host to `www.cloudflare.com`. The orchestrator followed
   the apex→www sibling and the headers in the report are the ones
   served at `www.cloudflare.com`. Surface this when reporting to a
   human user so they understand which surface was inspected.
6. **To produce a fix list**: for each vulnerability `id`, map to its
   catalog id per §5.5 (`Sweet32 → vuln.sweet32`), `GET
   /api/v1/checks` once, and read `remediation.example_snippet` for a
   copy-paste line.

## 7. Decision recipes

### "Is this site safe to onboard?"

1. `chain_trust === "trusted"` — non-negotiable; if not, return
   `unsafe` and stop. The grade is already `T`.
2. No vulnerability with `level === "bad"`. The catalog calls these
   `severity_when_fail: critical`.
3. TLS grade ≥ B **and** Headers grade ≥ B.
4. HSTS is set with `max-age >= 31536000` (one year).

If steps 1-2 pass and 3-4 partially fail, the site is *workable* but
needs remediation — surface the failing items, do not block.

### "What are the top 3 fixes?"

Order findings by impact, deduplicated by root cause:

1. Any `tls.vulnerabilities[].level === "bad"` finding — these include
   POODLE/BEAST/Lucky13/etc., usually all resolved by disabling
   legacy protocols and weak ciphers.
2. Any `headers.core` entry with `status === "fail"`, weighted by §4.3
   (CSP and HSTS first; XCTO last).
3. Any custom finding with `status === "fail"` (most often
   `security.txt` missing).

If the same root cause fixes multiple findings (typical: dropping
TLS 1.0 kills BEAST and Lucky13 in one move), report it once.

### Surfacing copy-paste remediation

For any finding `id` from a scan response:

1. Translate to a catalog id (§5.5 for runtime vuln IDs; otherwise the
   finding `id` is already a catalog id).
2. Fetch `/api/v1/checks` once per session (it is immutable per build,
   `Cache-Control: max-age=3600`) and index by `id`.
3. Present `remediation.summary` as the explanation and
   `remediation.example_snippet` as the copy-paste fix. The
   `example_stack` field tells the caller which web server the snippet
   targets (typically `nginx`).

Never paraphrase a remediation in your own words when the catalog
provides one — the catalog is the source of truth and is versioned.
