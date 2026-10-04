# SPF and DMARC observations

Read this reference when interpreting the `email` section or explaining why
email checks were skipped.

`email` is omitted for unassessed hosts and older reports. It is present only
for a registrable domain or its exact `www.` alias, selected using the bundled
Public Suffix List (including private suffixes). For `www.example.co.uk`,
`email.domain` is `example.co.uk`; `api.example.co.uk` and
`www.api.example.co.uk` are skipped. Unknown suffixes are skipped.
Selection uses the requested host, independently of HTTP redirects.

`email.spf` and `email.dmarc` each contain `id`, `state`, `records[]` (complete
TXT strings), and `warnings[]`. IDs are `email.spf` and `email.dmarc`.

| State | Meaning |
|-------|---------|
| `observed` | A policy was interpreted within the audit's limits; not a message-authentication pass. |
| `absent` | No relevant policy found after successful DNS lookups. |
| `invalid` | Published records could not establish a usable policy. |
| `unavailable` | DNS error, cancellation or scan limit prevented a conclusion; not evidence of absence. |

Each record also has `assessment: {status, title, summary, recommendations[]}`.
It explains the policy and next steps without assigning an email grade.
`status` is `pass | warn | fail | info` within the stated audit scope, never
a message-authentication result. Older reports may omit it.

SPF exposes `all?` (the first catch-all qualifier), `includes[]` and `redirect?`.
Syntax, literal IP ranges and duplicate policies/modifiers are checked.
Positive `/0` IP mechanisms before the first `all` are flagged as permissive.
For an observed root policy, `audit` contains `complete`, `lookup_terms`,
`lookup_limit_exceeded`, `queries[]`, `issues[]` and `limitations[]`.
Static include/redirect TXT dependencies are checked for missing or invalid
records and cycles. Repeated references count toward the term budget even when
their TXT response is reused. Mechanisms after the first `all`, and redirects
in a policy containing `all`, are not followed. SPF is not inherited.

Expansion stops when the conservative walk encounters an eleventh DNS-causing
term. This is a **potential** budget overflow: a real sender's evaluation may
stop sooner. Macros and address mechanisms (`a`, `mx`, `ptr`, `exists`) are not
evaluated; their DNS/void-lookup limits remain unverified. Missing dependencies
are errors, while DNS failures and unsupported expansion produce partial audits.
`complete` means the static audit completed without issues or limitations,
not that arbitrary messages authenticate. The root DNS `state` remains distinct
from dependency diagnostics. A `~all` policy is a valid softfail choice, not
automatically a configuration error.

DMARC exposes `policy?` (`none | quarantine | reject`), `policy_domain?`,
`policy_tag?` (`p | sp`), `inherited`, `testing` and `queries[]`.
Discovery follows [RFC 9989](https://www.rfc-editor.org/rfc/rfc9989.html),
including the bounded parent tree walk and `psd` boundaries. `records` contains
the selected record (including an unusable policy), or discarded records at
the selected email domain. Warnings identify discarded parent records.
An invalid `p`/`sp`/`np` value in the selected policy falls back to `none` only
with a usable reporting URI; otherwise the result is `invalid`, without
substituting another ancestor policy. Unknown tags are ignored.
`policy` describes the requested handling for an existing domain, including
inherited `sp` and `t=y` reductions. The legacy `pct` tag is reported as ignored;
older receivers can behave differently. `reporting_state` is `configured`,
`absent` or `invalid` when a policy is observed; `reporting_uris[]` contains
syntactically valid aggregate-report URIs. Mixed valid/invalid lists retain
the valid URIs with a warning. Destinations are never contacted. `p=none`
without usable `rua` is described as no enforcement or reports, not monitoring.
This audit does not validate message alignment, external reporting authorization
or report delivery. Older reports may omit the reporting fields.

TXT queries use the system resolver through `safehttp`: at most eleven SPF TXT and
eight DMARC lookups, two seconds each, five seconds overall, within the scan
deadline. Each response is limited to 128 TXT records and 64 KiB of text.
Only TXT metadata is queried for SPF dependencies; no mail server or reporting
destination is contacted.
Results share the scan cache and its freshness rules.

Email observations never affect TLS/HTTP grades or their highlights. Do not
infer mail usage or message authenticity from them. DKIM is unassessed because
no selector is available.
