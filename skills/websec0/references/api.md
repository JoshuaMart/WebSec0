# WebSec0 API reference

Use this reference when submitting a scan, retrieving a report or handling an
API error. Paths are relative to the instance selected for the task. The
built-in API has no authentication; a deployment may add access controls.

All endpoints live under `/api/v1`. Responses from the built-in API are JSON.
Errors share a typed envelope: `{"error":{"code":"...","message":"..."}}`.

## POST `/api/v1/scan`

Run a scan for the requested host. Prefer a bare ASCII hostname with the port
in its own field; do not silently switch to a different host or port.

```http
POST /api/v1/scan
Content-Type: application/json

{"host":"example.com","port":443,"list_in_history":false,"fresh":false}
```

This is a request example, not an instruction to scan `example.com`.
The service can return a cached report for the same host and port. `fresh`
bypasses that cache, but not rate limits. Check `scanned_at` for freshness.

Request body fields:

| Field             | Type    | Required | Default | Notes                                          |
|-------------------|---------|----------|---------|------------------------------------------------|
| `host`            | string  | yes      | —       | Prefer a bare lowercase ASCII hostname.       |
| `port`            | integer | no       | 443     | Non-default ports may be refused (see policy). |
| `list_in_history` | bool    | no       | false   | If true, becomes visible to `/api/v1/history`. |
| `fresh`           | bool    | no       | false   | Bypass cache.                                  |

Unknown fields are rejected.

Success: `200 OK` with a `scan.Result` (see [Result envelope](#result-envelope)).

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
per target host. Both must pass; deployment settings can differ.
On `rate_limited`, stop immediate retries and report the limit. A timeout or
server error is not evidence of an insecure target. Do not retry by changing
the target, instance or network policy. A `404` for a cached report means it
is unavailable, not that a fresh scan succeeded or failed.

## GET `/api/v1/scan/{id}`

Return the cached `scan.Result` by its `id` (UUID). `404 not_found` if
the entry has expired or never existed. `400 invalid_id` on empty id.

## GET `/api/v1/checks`

Return the check catalog bundled with the running build. Sent with
`Cache-Control: public, max-age=3600`. Use this to look up
human-readable titles and available remediation snippets for matching findings.

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

Discover checks and categories from this response rather than assuming a fixed
count. `remediation.example_stack` and `remediation.example_snippet` are optional.

## GET `/api/v1/history?limit=N`

Return the most recent scans submitted with `list_in_history: true`.
`limit` defaults to 20 and is capped at 100. Each entry:

```json
{"id":"…","host":"…","scanned_at":"…","tls_grade":"A","headers_grade":"B","highest_tls":"TLS 1.3"}
```

`400 invalid_limit` if `limit` is not a positive integer.

## Result envelope

```json
{
  "id":          "uuid",
  "host":        "example.com",
  "port":        443,
  "resolved_ip": "192.0.2.10",
  "scanned_at":  "2026-05-13T07:18:00Z",
  "duration_ms": 4321,
  "tls":     { "...": "TLSReport, omitempty"     },
  "headers": { "...": "HeadersReport, omitempty" },
  "custom":  [ { "...": "CustomFinding"          } ],
  "email":   { "...": "EmailReport, omitempty"   }
}
```

`tls`, `headers`, `custom` and `email` are independent. A probe failure on one
does not invalidate the others.

The example shows field layout, not literal nested schemas. `tls`, `headers`,
`custom` and `email` may be omitted. See the skill's interpretation and email
references for their fields and limits. A successful HTTP response does not
mean every probe completed.
