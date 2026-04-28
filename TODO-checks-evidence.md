# Checks evidence audit

Audit of every check's `Run()` for evidence quality and description
clarity, scored against criteria a/b/c/d below. The bar is what
`WELLKNOWN-SECURITY-TXT-MISSING` now does post-`543e886`: a structured
trail of what was probed and what was observed
(`{"attempts": [{url, status, final_url?, error?}, ...]}`), so an
operator reading the report page knows exactly what happened without
re-running curl.

## Legend

- **a** — Evidence vide. `Run()` returns a `Finding` without setting
  `Evidence` on at least one fail / warn / pass path.
- **b** — Evidence pauvre. One or two generic fields (e.g. just
  `{"url": "..."}` or just a count) without showing the actual values
  observed.
- **c** — Evidence redondante avec la description. Repeats the
  human-readable text without adding observable values.
- **d** — Description vague. Says what the finding is but doesn't quote
  / cite the specific values observed.

Status paths considered: `pass`, `fail`, `warn`, `skipped`. Each bullet
hints which path is weak when only one branch is at fault.

---

## COOKIE

- [x] `COOKIE-SECURE-MISSING` — pass path returns only a count, not the list of cookie names that carry `Secure`. Tags: b (cookies/checks.go:135)
- [x] `COOKIE-HTTPONLY-MISSING-SESSION` — pass path lists session names but doesn't confirm each carries `HttpOnly`. Tags: d (cookies/checks.go:180)
- [x] `COOKIE-SAMESITE-MISSING` — pass path returns nil Evidence; should show observed `SameSite` value per cookie. Tags: a (cookies/checks.go:226)
- [x] `COOKIE-SAMESITE-NONE-WITHOUT-SECURE` — pass path returns nil Evidence. Tags: a (cookies/checks.go:269)
- [x] `COOKIE-NO-SECURITY-FLAGS` — pass path lists cookie names but not the per-cookie flag breakdown. Tags: d (cookies/checks.go:315)
- [x] `COOKIE-PREFIX-SECURE-MISSING` — pass path returns nil Evidence. Tags: a (cookies/checks.go:358)
- [x] `COOKIE-PREFIX-HOST-MISSING` — pass path returns nil Evidence. Tags: a (cookies/checks.go:401)

## DNS

- [x] `DNS-DNSSEC-MISSING` — both paths return only a count, not the actual DS records. Tags: b (dns/checks.go:84)
- [x] `DNS-DNSSEC-WEAK-ALGO` — pass path returns nil Evidence; fail path lists algorithm names but not key tags or digest values. Tags: a,b (dns/checks.go:121)
- [x] `DNS-DNSSEC-BROKEN` — fail path on AD-flag failure returns nil Evidence. Tags: a (dns/checks.go:158)
- [x] `DNS-CAA-MISSING` — both paths return only a count, not the actual CAA records. Tags: b (dns/checks.go:195)
- [x] `DNS-CAA-NO-IODEF` — fail path returns nil Evidence when the `iodef` tag is missing. Tags: a (dns/checks.go:221)
- [x] `DNS-AAAA-MISSING` — both paths return only a count, not the actual AAAA addresses. Tags: b (dns/checks.go:253)
- [x] `DNS-WILDCARD-DETECTED` — pass path returns nil Evidence (no record of which probe label was tried). Tags: a (dns/checks.go:281)
- [x] `DNS-DANGLING-CNAME` — pass path lists CNAMEs without resolution outcome; fail/warn only show the matched pattern, not the dangling target. Tags: b (dns/checks.go:332)
- [x] `DNS-NS-DIVERSITY-LOW` — Evidence has the NS list but no network/ASN diversity data — that's the actual signal. Tags: c (dns/checks.go:386)

## EMAIL

- [x] `EMAIL-DMARC-MISSING` — fail path omits Evidence (no record of which DNS query was made). Tags: a (email/dmarc.go:71)
- [x] `EMAIL-DMARC-POLICY-WEAK` — warn branch (`p=quarantine`) omits Evidence. Tags: a (email/dmarc.go:209)
- [x] `EMAIL-DMARC-NO-RUA` — fail path omits Evidence (no parsed DMARC record shown). Tags: a (email/dmarc.go:246)
- [x] `EMAIL-SPF-MISSING` — fail path omits Evidence. Tags: a (email/spf.go:107)
- [x] `EMAIL-SPF-NO-ALL` — fail path omits Evidence (no parsed SPF record). Tags: a (email/spf.go:211)
- [x] `EMAIL-SPF-PASS-ALL` — fail path omits Evidence. Tags: a (email/spf.go:246)
- [x] `EMAIL-SPF-SOFTFAIL-ALL` — warn path omits Evidence. Tags: a (email/spf.go:280)
- [x] `EMAIL-SPF-PTR-MECHANISM` — fail path omits Evidence (no quoted SPF fragment). Tags: a (email/spf.go:318)
- [x] `EMAIL-DANE-MISSING` — fail path Evidence is just `tlsa_record_count`; no list of MX hosts probed nor DNSSEC state. Tags: b (email/dane.go:133)
- [x] `EMAIL-DANE-MISMATCH` — fail path only carries `mx_host`; no TLSA record or cert hash that failed to match. Tags: b (email/dane.go:239)
- [x] `EMAIL-STARTTLS-FAIL` — fail path omits Evidence (no protocol error captured). Tags: a (email/starttls.go:197)
- [x] `EMAIL-MTASTS-MODE-TESTING` — pass branch (`mode=enforce`) omits Evidence. Tags: a (email/mtasts.go:117)
- [x] `EMAIL-TLSRPT-MISSING` — fail path omits Evidence. Tags: a (email/tlsrpt_bimi.go:38)
- [x] `EMAIL-BIMI-MISSING` — fail path omits Evidence. Tags: a (email/tlsrpt_bimi.go:71)

## HEADER

- [ ] `HEADER-CSP-MISSING` — fail path returns no Evidence; pass path only the raw header without parsed directives. Tags: a,b (headers/csp.go:96)
- [ ] `HEADER-CSP-UNSAFE-INLINE` — pass and fail return nil/empty Evidence (no list of directives carrying `'unsafe-inline'`). Tags: a (headers/csp.go:150)
- [ ] `HEADER-CSP-UNSAFE-EVAL` — pass and fail return nil/empty Evidence. Tags: a (headers/csp.go:177)
- [ ] `HEADER-CSP-WILDCARD-SRC` — pass path returns nil; fail path shows only directive name, not the actual `*` source. Tags: a,b (headers/csp.go:204)
- [ ] `HEADER-CSP-NO-OBJECT-SRC` — fail path returns nil Evidence. Tags: a (headers/csp.go:234)
- [ ] `HEADER-CSP-NO-BASE-URI` — pass and fail return nil Evidence. Tags: a (headers/csp.go:263)
- [ ] `HEADER-CSP-NO-FRAME-ANCESTORS` — pass and fail return nil Evidence. Tags: a (headers/csp.go:290)
- [ ] `HEADER-XCTO-MISSING` — pass and fail return nil Evidence (header value not stored). Tags: a (headers/security_headers.go:23)
- [ ] `HEADER-XFO-MISSING` — most paths return nil Evidence; only the bad-value fail case records anything. Tags: a (headers/security_headers.go:54)
- [ ] `HEADER-REFERRER-POLICY-MISSING` — fail path returns nil Evidence; pass has the value. Tags: a (headers/security_headers.go:109)
- [ ] `HEADER-REFERRER-POLICY-UNSAFE` — both fail and warn carry `value`, but neither labels which token is unsafe. Tags: b (headers/security_headers.go:138)
- [ ] `HEADER-PERMISSIONS-POLICY-MISSING` — fail path returns nil Evidence. Tags: a (headers/security_headers.go:180)
- [ ] `HEADER-FEATURE-POLICY-DEPRECATED` — warn and pass return nil Evidence (deprecated header value not stored). Tags: a (headers/security_headers.go:211)
- [ ] `HEADER-COOP-MISSING` — fail returns nil Evidence (presence-check helper). Tags: a (headers/security_headers.go:241)
- [ ] `HEADER-COEP-MISSING` — fail returns nil Evidence. Tags: a (headers/security_headers.go:258)
- [ ] `HEADER-CORP-MISSING` — fail returns nil Evidence. Tags: a (headers/security_headers.go:275)
- [ ] `HEADER-REPORTING-ENDPOINTS-NONE` — fail path returns nil Evidence. Tags: a (headers/security_headers.go:294)
- [ ] `HEADER-NEL-NONE` — fail returns nil Evidence. Tags: a (headers/security_headers.go:328)
- [ ] `HEADER-XSS-PROTECTION-DEPRECATED` — pass and fail return nil Evidence; only warn has a value. Tags: a (headers/deprecated.go:23)
- [ ] `HEADER-HPKP-DEPRECATED` — pass / fail / warn return nil Evidence. Tags: a (headers/deprecated.go:55)
- [ ] `HEADER-EXPECT-CT-DEPRECATED` — pass returns nil Evidence; only warn has the value. Tags: a (headers/deprecated.go:90)
- [ ] `HEADER-INFO-SERVER` — pass returns nil Evidence (no record of which `Server` header was inspected). Tags: a (headers/info_disclosure.go:35)
- [ ] `HEADER-INFO-X-POWERED-BY` — pass returns nil Evidence. Tags: a (headers/info_disclosure.go:71)
- [ ] `HEADER-INFO-X-ASPNET-VERSION` — pass returns nil Evidence. Tags: a (headers/info_disclosure.go:78)
- [ ] `HEADER-INFO-X-GENERATOR` — pass returns nil Evidence. Tags: a (headers/info_disclosure.go:85)
- [ ] `HEADER-INFO-SERVER-TIMING` — pass returns nil Evidence. Tags: a (headers/info_disclosure.go:92)

## HTTP

- [x] `HTTP-CORS-WILDCARD-CREDENTIALS` — fail path returns nil Evidence (no captured ACAO + credentials combo). Tags: a (http/cors.go:30)
- [x] `HTTP-CORS-ORIGIN-REFLECTED` — fail path doesn't include the probe `Origin` we sent, only the reflected `ACAO`. Tags: b (http/cors.go:67)
- [x] `HTTP-CORS-NULL-ORIGIN` — fail path returns nil Evidence. Tags: a (http/cors.go:112)
- [x] `HTTP-OPTIONS-DANGEROUS-METHODS` — pass path doesn't enumerate which methods were actually allowed. Tags: b (http/methods.go:27)
- [x] `HTTP-TRACE-ENABLED` — fail path stores only the status code; should include the response body excerpt that confirms TRACE echo. Tags: b (http/methods.go:75)
- [x] `HTTP-404-STACK-TRACE` — fail path records only the matching regex pattern, not the actual matched body excerpt. Tags: b,d (http/error_pages.go:66)
- [x] `HTTP-404-DEFAULT-ERROR-PAGE` — fail path records only the signal pattern, not the body excerpt. Tags: b,d (http/error_pages.go:100)
- [x] `HTTP-HTTP2-MISSING` — fail path returns nil Evidence (negotiated protocol not stored). Tags: a (http/protocol_checks.go:24)
- [x] `HTTP-HTTP3-MISSING` — fail path returns nil Evidence. Tags: a (http/protocol_checks.go:62)
- [x] `HTTP-COMPRESSION-NONE` — fail path returns nil Evidence. Tags: a (http/protocol_checks.go:94)
- [x] `HTTP-MIXED-CONTENT` — Evidence lists deduplicated resources but not which element type or position raised it. Tags: c (http/html.go:138)

## Other (ROBOTS / SRI)

- [x] `ROBOTS-TXT-INVALID` — all three fail branches (wrong content-type / looks-like-HTML / no recognized directive) return nil Evidence. Operator can't tell which condition triggered. Tags: a (http/robots.go:41–55)

## TLS

- [x] `TLS-HSTS-MISSING` — already correct: fail evidence carries `raw_header`. Tags: c (tls/hsts.go:82)
- [x] `TLS-HSTS-NO-INCLUDESUBDOMANS` — fail path returns nil Evidence (parsed HSTS values not surfaced). Tags: a (tls/hsts.go:172)
- [x] `TLS-PROTOCOL-TLS12-MISSING` — fail path returns nil Evidence; handshake error not captured. Tags: a,d (tls/protocol_checks.go:55)
- [x] `TLS-PROTOCOL-TLS13-MISSING` — fail path returns nil Evidence; handshake error not captured. Tags: a,d (tls/protocol_checks.go:86)
- [x] `TLS-CIPHER-NO-FORWARD-SECRECY` — fail path doesn't list the negotiated suite per probed version. Tags: d (tls/protocol_checks.go:138)
- [x] `TLS-ALPN-NO-HTTP2` — fail path returns nil Evidence (negotiated ALPN not captured). Tags: a (tls/protocol_checks.go:175)
- [x] `TLS-OCSP-STAPLING-MISSING` — fail path returns nil Evidence (probed versions not enumerated). Tags: a (tls/protocol_checks.go:211)
- [x] `TLS-PROTOCOL-LEGACY-SSL2` — fail path returns nil Evidence. Tags: a (tls/legacy_checks.go:40)
- [x] `TLS-PROTOCOL-LEGACY-SSL3` — fail path returns nil Evidence. Tags: a (tls/legacy_checks.go:68)
- [x] `TLS-CIPHER-NULL` — pass path returns nil Evidence. Tags: a (tls/legacy_checks.go:149)
- [x] `TLS-CIPHER-EXPORT` — pass path returns nil Evidence. Tags: a (tls/legacy_checks.go:177)
- [x] `TLS-CIPHER-RC4` — pass path returns nil Evidence. Tags: a (tls/legacy_checks.go:205)
- [x] `TLS-CIPHER-DES` — pass path returns nil Evidence. Tags: a (tls/legacy_checks.go:233)
- [x] `TLS-CIPHER-3DES` — pass path returns nil Evidence. Tags: a (tls/legacy_checks.go:261)
- [x] `TLS-CIPHER-CBC-TLS10` — pass path returns nil Evidence. Tags: a (tls/legacy_checks.go:289)
- [x] `TLS-CERT-CHAIN-INCOMPLETE` — fail path returns nil Evidence; the verify error string is in Description but no chain length / missing-issuer info. Tags: a (tls/cert_checks.go:131)
- [x] `TLS-CERT-NAME-MISMATCH` — already correct: Description quotes hostname + SANs inline via fmt.Sprintf. Tags: d (tls/cert_checks.go:163)
- [x] `TLS-CERT-NO-CT` — Evidence is generic counts (`tls_extension_scts: 0`, `x509_embedded_scts: false`) without explaining which delivery methods were checked. Tags: b,d (tls/cert_checks.go:410)

## WELLKNOWN

- [x] `WELLKNOWN-SECURITY-TXT-NO-CONTACT` — fail path omits Evidence (no parsed file shown, no list of fields seen). Tags: a (wellknown/securitytxt.go:151)
- [x] `WELLKNOWN-SECURITY-TXT-NO-EXPIRES` — fail path omits Evidence. Tags: a (wellknown/securitytxt.go:188)
- [x] `WELLKNOWN-SECURITY-TXT-NO-SIGNATURE` — warn path omits Evidence (no indication signature was checked or how). Tags: a (wellknown/securitytxt.go:271)
- [x] `WELLKNOWN-CHANGE-PASSWORD-MISSING` — fail-on-unexpected-status path returns nil Evidence; other paths inconsistent. Tags: a (http/change_password.go:27)
