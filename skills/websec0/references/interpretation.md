# Interpreting WebSec0 reports

Use the returned grades and findings as observations from the stated host,
port and scan time. Explain missing evidence before ranking corrective work.
For SPF/DMARC fields, use the email reference linked from `SKILL.md`.

## Report completeness

A missing section is unassessed, not a passing result. The report sections are
independent, so retain useful results even if another probe failed.
`tls.scan_status: "partial_blocked"` means the target stopped responding during
probing. A protocol with `probe: "aborted"` was not tested: its `offered: false`
must not be described as disabled. Empty or omitted status in an older report
is not proof of completeness.

TLS vulnerability findings are configuration or version heuristics. Preserve
their `state`, `level` and explanation; do not turn them into confirmed exploit
results. Absence of a finding does not prove absence of the vulnerability.
`severity_when_fail` in the catalog describes a check, not the observed outcome.

## Grades

A scan produces two grades — TLS and Headers — drawn from this
alphabet, best to worst: `A+ A B C D E F T`.

`T` is reserved for certificate-trust failures (expired, self-signed,
hostname mismatch, untrusted chain). It is ranked below `F` because the
certificate could not be trusted. Other observations remain useful; `T` does
not invalidate the report itself.

## TLS grading

Four sub-scores are computed independently from the TLS observation,
each in `[0, 100]`:

| Sub-score          | Built from                                                       |
|--------------------|------------------------------------------------------------------|
| `certificate`      | Leaf key algorithm (ECDSA/Ed25519 > RSA > DSA) and days-to-expiry|
| `protocol_support` | Worst and best offered protocol scores, averaged                        |
| `key_exchange`     | 90 if any cipher offers PFS, else 40; 0 if none enumerated                     |
| `cipher_strength`  | Worst and best scores derived from offered cipher strengths, averaged |

The final score is a weighted aggregate, truncated to an integer:

```
final = certificate · 0.30 + ((protocol_support + key_exchange + cipher_strength) / 3) · 0.70
```

Thresholds: A+ ≥ 95, A ≥ 80, B ≥ 65, C ≥ 50, D ≥ 35, E ≥ 20, else F.

Grade caps (the worst applicable grade wins):

| Observation                                  | Grade cap |
|----------------------------------------------|-----------|
| Expired, self-signed, mismatched or untrusted chain                      | **T**     |
| SSL 2.0 or 3.0 offered                       | **F**     |
| RC4 / anonymous / export cipher offered      | **F**     |
| 3DES cipher offered                          | **C**     |
| Ciphers enumerated but none offer PFS              | **C**     |
| TLS 1.0 or 1.1 offered                       | **C**     |

A+ gate: a final score of ≥ 95 is only awarded A+ when the *Headers*
report carries an HSTS line with `max-age ≥ 31536000` (one year),
`includeSubDomains`, and `preload`. Otherwise the grade is capped at A.
A scan with no Headers report (e.g. the HTTPS endpoint failed) cannot
earn A+. These directives do not prove membership in a browser preload list.

## Headers grading

The score starts at the weighted sum of six core headers:

| Header                       | Weight |
|------------------------------|--------|
| `content-security-policy`    | 25     |
| `strict-transport-security`  | 20     |
| `x-frame-options`            | 15     |
| `referrer-policy`            | 15     |
| `permissions-policy`         | 15     |
| `x-content-type-options`     | 10     |

Each header contributes its full weight on `pass`, half rounded down on `warn`,
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

## Headers and TLS interaction

Headers are scored first. The parsed HSTS values are then passed back
into the TLS A+ gate. If Headers cannot be fetched (probe error
not recoverable), TLS A+ is unreachable even at a perfect score.

## TLS fields

- `tls.grade` (string) and `tls.scores` (`{certificate, protocol_support,
  key_exchange, cipher_strength, final}`).
- `tls.protocols`: list of `{name, offered, probe}`. Names include
  `SSL 2.0`, `SSL 3.0`, `TLS 1.0`, …, `TLS 1.3`. `probe` is `stdlib`
  for modern Go probes and `raw_clienthello` for the SSLv2/SSLv3 raw
  probes, or `aborted` when unassessed.
- `tls.ciphers`: each `{protocol, name, code, strength, aead, pfs, level}`.
  `level` is one of `good | warn | bad | info`.
- `tls.cipher_preference`: `"server"` | `"client"` | `""`.
- `tls.certificate_chain`: leaf-to-root certs with `step`, `cn`, `issuer`,
  `not_before`, `not_after`, `days_left`, `key_alg`, `sig_alg`, `san[]`.
- `tls.chain_trust`: `trusted` | `expired` | `self_signed` |
  `hostname_mismatch` | `untrusted` | `no_chain` | `""`. The four explicit
  trust failures cap the grade at T; `no_chain` and empty values mean the
  chain was unavailable or trust was not established, not trusted.
  The shipped binary prefers system trust and falls back to an embedded
  Mozilla/NSS root bundle only when system trust is unavailable. It does not
  retry rejected chains against that bundle when a system store is available;
  trust outcomes may therefore differ across OSes.
- `tls.ocsp_stapling` (bool) and `tls.ocsp_status` (`good` | `revoked`
  | `unknown_to_responder` | `parse_error` | `""`).
- `tls.session_resumption`: `supported` | `not_supported` | `""`.
- `tls.handshake_scts`: `{count, log_ids, unparsed_count}`, from the TLS
  extension only. Omitted if the certificate handshake was unavailable (or
  in older reports); `count: 0` means no SCTs were observed via that extension.
  `count` includes duplicates and unparsed entries. `log_ids` contains unique
  lowercase hex IDs from structurally decoded v1 SCTs, in first-seen order;
  `unparsed_count` counts malformed entries and unsupported versions.
  Informational only: no scoring impact, signature verification, log trust
  assessment or inclusion proof. Absence here does not establish absence of CT.
- `tls.certificate_scts`: `{count, log_ids, unparsed_count, present, parse_error}`,
  from the leaf certificate's SCT extension (OID `1.3.6.1.4.1.11129.2.4.2`).
  Omitted when no leaf certificate is available or in older reports.
  `present: false` means the extension is absent. `parse_error: true` means
  the extension's DER or list framing is malformed; the zero counts and empty
  IDs then mean unavailable, not absent. Otherwise the counts and IDs follow
  the same rules as `handshake_scts`, independently for this source. A malformed
  individual SCT increments `unparsed_count` without discarding other entries.
  Only the leaf is inspected; intermediate certificates and OCSP SCT extensions
  are not assessed. No signature/inclusion verification or scoring impact.
- `tls.vulnerabilities`: each `{id, title, cve, state, level, body}`.
  `id` is the catalog identifier (e.g. `vuln.poodle`); `title` is the
  human-readable label (`POODLE`).

## Headers fields

- `headers.grade`, `headers.score`.
- `headers.core` is a map keyed by the lowercase header name
  (`content-security-policy`, `strict-transport-security`, …). Each
  value is `{present, value?, status}` where `status` is `pass | warn | fail | info`.
- `headers.additional` carries `server`, `set-cookie[]`, `access-control-
  allow-origin`, `cross-origin-opener-policy`, `cross-origin-embedder-
  policy`, `cross-origin-resource-policy`.
- `headers.probed_host` is set only when the scan followed an apex →
  `www` sibling redirect (e.g. `cloudflare.com` → `www.cloudflare.com`).
  When present, the headers in the report come from that sibling, not
  from the originally submitted host.

## Custom fields

`custom` is an array. Each entry has `{id, title, status, details}`:

| `id`                  | `details` keys                                                                 |
|-----------------------|--------------------------------------------------------------------------------|
| `custom.security_txt` | `url, rfc9116_compliant, expires, signed, contact_count, note?`                |
| `custom.robots_txt`   | `url, size_bytes, parseable, suspicious_disallow?, note?`                      |

`details.expires` may be the zero-time `"0001-01-01T00:00:00Z"` when
no Expires field was present in the file — treat that value as "no
expiry set".

A custom finding can carry default parsed fields when its resource was absent
or unavailable. Use `status` and `details.note` to distinguish an incomplete
response from a measured result; do not interpret default fields as evidence.
`signed` detects a PGP wrapper; it does not verify the signature. Custom findings
are informational and do not change either grade.

## Catalog lookup and remediation

Fetch `/api/v1/checks` from the same instance as the report. Cache by instance
and build when known; a newer catalog may not contain every ID from an older
report. Unknown IDs do not invalidate the original finding.

| Observation | Lookup |
|-------------|--------|
| `tls.vulnerabilities[]`, `custom[]`, `email.spf`, `email.dmarc` | Match the supplied `id` exactly. |
| `headers.core` | Prefix `headers.` and replace hyphens in the header name with underscores; verify the ID exists. |
| Protocol rows | Map the name explicitly: `SSL 2.0` → `tls.protocol.sslv2`, `SSL 3.0` → `tls.protocol.sslv3`, `TLS 1.0` … `TLS 1.3` → `tls.protocol.tls10` … `tls.protocol.tls13`. |
| Chain trust failures | Match `tls.chain.expired`, `tls.chain.self_signed`, `tls.chain.hostname_mismatch` or `tls.chain.untrusted` to the observed failure. |
| Cipher and additional-header observations | Match the observed condition to a relevant catalog entry; there is no universal ID conversion. |

Protocol, cipher and header rows have no `id` field. A catalog entry's existence
is not evidence that its condition was observed. Some observations have no
matching catalog entry; explain the evidence without inventing an ID.

Use `remediation.summary` when present. Offer `example_snippet` only when supplied
and appropriate for the user's stack (`example_stack`); otherwise describe the
change without inventing a catalog snippet. Translate or paraphrase faithfully,
and distinguish any additional advice from the supplied remediation.

## Prioritizing the response

Lead with the two grades, completeness and main findings. Rank corrections by
observed impact and the user's priorities, grouping shared root causes. Keep
informational custom/email results distinct from TLS/Headers grades. For email,
use the assessment recommendations and state what remains unverified.

For an onboarding decision, compare the observations with the user's acceptance
criteria. Without such criteria, explain the technical concerns and limits;
do not label a site globally safe or unsafe from its grades alone.

### Example: a high score with a lower grade

In a synthetic report, certificate=100, protocol_support=85, key_exchange=90
and cipher_strength=90 give a final score of 91. Offered TLS 1.0 caps the TLS
grade at C despite that score. Recommend reviewing legacy-client requirements
before disabling legacy protocols. Do not infer a Headers score, cookie defects
or a confirmed exploit from these TLS observations.
