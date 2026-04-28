# Checks catalog

126 checks across 7 families. Generated from `GET /api/v1/checks`
by `scripts/gen-checks-docs.sh`. The live catalog is the source of truth.

> Run `scripts/gen-checks-docs.sh` after adding or modifying a check
> to refresh this directory.

## By family

### Family: cookies

7 checks.

| ID | Severity | Title |
|---|---|---|
| [COOKIE-HTTPONLY-MISSING-SESSION](./COOKIE-HTTPONLY-MISSING-SESSION.md) | `high` | Session cookies are HttpOnly |
| [COOKIE-NO-SECURITY-FLAGS](./COOKIE-NO-SECURITY-FLAGS.md) | `medium` | Every cookie has at least one security flag |
| [COOKIE-PREFIX-HOST-MISSING](./COOKIE-PREFIX-HOST-MISSING.md) | `low` | Session cookies use the __Host- prefix |
| [COOKIE-PREFIX-SECURE-MISSING](./COOKIE-PREFIX-SECURE-MISSING.md) | `low` | Session cookies use the __Secure- prefix |
| [COOKIE-SAMESITE-MISSING](./COOKIE-SAMESITE-MISSING.md) | `medium` | Cookies declare SameSite explicitly |
| [COOKIE-SAMESITE-NONE-WITHOUT-SECURE](./COOKIE-SAMESITE-NONE-WITHOUT-SECURE.md) | `medium` | SameSite=None cookies also carry Secure |
| [COOKIE-SECURE-MISSING](./COOKIE-SECURE-MISSING.md) | `medium` | All cookies carry Secure |

### Family: dns

10 checks.

| ID | Severity | Title |
|---|---|---|
| [DNS-AAAA-MISSING](./DNS-AAAA-MISSING.md) | `low` | Hostname publishes IPv6 |
| [DNS-CAA-MISSING](./DNS-CAA-MISSING.md) | `low` | Zone declares CAA records |
| [DNS-CAA-NO-IODEF](./DNS-CAA-NO-IODEF.md) | `info` | CAA includes an iodef contact |
| [DNS-DANGLING-CNAME](./DNS-DANGLING-CNAME.md) | `high` | No dangling CNAME (subdomain takeover risk) |
| [DNS-DNSSEC-BROKEN](./DNS-DNSSEC-BROKEN.md) | `critical` | DNSSEC validation succeeds |
| [DNS-DNSSEC-MISSING](./DNS-DNSSEC-MISSING.md) | `medium` | Zone is signed with DNSSEC |
| [DNS-DNSSEC-WEAK-ALGO](./DNS-DNSSEC-WEAK-ALGO.md) | `high` | DNSSEC uses a modern signing algorithm |
| [DNS-NS-DIVERSITY-LOW](./DNS-NS-DIVERSITY-LOW.md) | `low` | Zone has ≥ 2 distinct nameservers |
| [DNS-TTL-ABERRANT](./DNS-TTL-ABERRANT.md) | `info` | A/AAAA TTL is in a sensible range |
| [DNS-WILDCARD-DETECTED](./DNS-WILDCARD-DETECTED.md) | `info` | Zone does not wildcard-resolve |

### Family: email

31 checks.

| ID | Severity | Title |
|---|---|---|
| [EMAIL-BIMI-INVALID-SVG](./EMAIL-BIMI-INVALID-SVG.md) | `low` | BIMI logo is a valid SVG Tiny PS document |
| [EMAIL-BIMI-MISSING](./EMAIL-BIMI-MISSING.md) | `info` | Domain publishes BIMI |
| [EMAIL-DANE-INVALID-PARAMS](./EMAIL-DANE-INVALID-PARAMS.md) | `high` | DANE/TLSA records have valid parameters |
| [EMAIL-DANE-MISMATCH](./EMAIL-DANE-MISMATCH.md) | `high` | DANE/TLSA records match the MX certificate |
| [EMAIL-DANE-MISSING](./EMAIL-DANE-MISSING.md) | `low` | DANE/TLSA records published for MX hosts |
| [EMAIL-DKIM-NONE-FOUND](./EMAIL-DKIM-NONE-FOUND.md) | `medium` | DKIM key published on at least one common selector |
| [EMAIL-DKIM-SHA1](./EMAIL-DKIM-SHA1.md) | `medium` | DKIM uses SHA-256 (not SHA-1) |
| [EMAIL-DKIM-TEST-MODE](./EMAIL-DKIM-TEST-MODE.md) | `low` | DKIM records are not in test mode |
| [EMAIL-DKIM-WEAK-KEY](./EMAIL-DKIM-WEAK-KEY.md) | `medium` | DKIM keys are at least 1024 bits |
| [EMAIL-DMARC-INVALID-SYNTAX](./EMAIL-DMARC-INVALID-SYNTAX.md) | `high` | DMARC record is syntactically valid |
| [EMAIL-DMARC-MISALIGNED-DKIM](./EMAIL-DMARC-MISALIGNED-DKIM.md) | `medium` | DMARC DKIM alignment is strict |
| [EMAIL-DMARC-MISALIGNED-SPF](./EMAIL-DMARC-MISALIGNED-SPF.md) | `medium` | DMARC SPF alignment is strict |
| [EMAIL-DMARC-MISSING](./EMAIL-DMARC-MISSING.md) | `high` | Domain publishes DMARC |
| [EMAIL-DMARC-NO-RUA](./EMAIL-DMARC-NO-RUA.md) | `low` | DMARC defines an aggregate-report endpoint (rua=) |
| [EMAIL-DMARC-POLICY-NONE](./EMAIL-DMARC-POLICY-NONE.md) | `medium` | DMARC policy is enforcing (not `p=none`) |
| [EMAIL-DMARC-POLICY-WEAK](./EMAIL-DMARC-POLICY-WEAK.md) | `low` | DMARC policy is `p=reject` |
| [EMAIL-MTASTS-MAX-AGE-LOW](./EMAIL-MTASTS-MAX-AGE-LOW.md) | `low` | MTA-STS max_age is at least 30 days |
| [EMAIL-MTASTS-MISSING](./EMAIL-MTASTS-MISSING.md) | `medium` | Domain publishes MTA-STS |
| [EMAIL-MTASTS-MODE-TESTING](./EMAIL-MTASTS-MODE-TESTING.md) | `medium` | MTA-STS mode is `enforce` |
| [EMAIL-MTASTS-MX-MISMATCH](./EMAIL-MTASTS-MX-MISMATCH.md) | `high` | MTA-STS policy covers all DNS MX entries |
| [EMAIL-SPF-INVALID-SYNTAX](./EMAIL-SPF-INVALID-SYNTAX.md) | `high` | SPF record is syntactically valid |
| [EMAIL-SPF-MISSING](./EMAIL-SPF-MISSING.md) | `high` | Domain publishes an SPF record |
| [EMAIL-SPF-MULTIPLE-RECORDS](./EMAIL-SPF-MULTIPLE-RECORDS.md) | `high` | Single SPF record per RFC 7208 §3.2 |
| [EMAIL-SPF-NO-ALL-MECHANISM](./EMAIL-SPF-NO-ALL-MECHANISM.md) | `medium` | SPF record terminates with an `all` mechanism |
| [EMAIL-SPF-PASS-ALL](./EMAIL-SPF-PASS-ALL.md) | `high` | SPF doesn't end with `+all` |
| [EMAIL-SPF-PTR-MECHANISM](./EMAIL-SPF-PTR-MECHANISM.md) | `medium` | SPF avoids the deprecated `ptr` mechanism |
| [EMAIL-SPF-SOFTFAIL-ALL](./EMAIL-SPF-SOFTFAIL-ALL.md) | `low` | SPF ends with hard fail (`-all`) |
| [EMAIL-SPF-TOO-MANY-LOOKUPS](./EMAIL-SPF-TOO-MANY-LOOKUPS.md) | `high` | SPF evaluation stays within the 10-lookup limit |
| [EMAIL-STARTTLS-FAIL](./EMAIL-STARTTLS-FAIL.md) | `high` | MX server advertises STARTTLS |
| [EMAIL-STARTTLS-WEAK-TLS](./EMAIL-STARTTLS-WEAK-TLS.md) | `medium` | STARTTLS negotiates TLS 1.2 or higher |
| [EMAIL-TLSRPT-MISSING](./EMAIL-TLSRPT-MISSING.md) | `low` | Domain publishes TLS-RPT |

### Family: headers

26 checks.

| ID | Severity | Title |
|---|---|---|
| [HEADER-COEP-MISSING](./HEADER-COEP-MISSING.md) | `low` | Cross-Origin-Embedder-Policy is set |
| [HEADER-COOP-MISSING](./HEADER-COOP-MISSING.md) | `low` | Cross-Origin-Opener-Policy is set |
| [HEADER-CORP-MISSING](./HEADER-CORP-MISSING.md) | `low` | Cross-Origin-Resource-Policy is set |
| [HEADER-CSP-MISSING](./HEADER-CSP-MISSING.md) | `medium` | Content-Security-Policy is set |
| [HEADER-CSP-NO-BASE-URI](./HEADER-CSP-NO-BASE-URI.md) | `low` | CSP locks <base> elements |
| [HEADER-CSP-NO-FRAME-ANCESTORS](./HEADER-CSP-NO-FRAME-ANCESTORS.md) | `medium` | CSP restricts framing |
| [HEADER-CSP-NO-OBJECT-SRC](./HEADER-CSP-NO-OBJECT-SRC.md) | `low` | CSP restricts plugin sources |
| [HEADER-CSP-UNSAFE-EVAL](./HEADER-CSP-UNSAFE-EVAL.md) | `high` | CSP forbids 'unsafe-eval' |
| [HEADER-CSP-UNSAFE-INLINE](./HEADER-CSP-UNSAFE-INLINE.md) | `high` | CSP forbids 'unsafe-inline' for scripts |
| [HEADER-CSP-WILDCARD-SRC](./HEADER-CSP-WILDCARD-SRC.md) | `medium` | CSP avoids wildcard sources for active content |
| [HEADER-EXPECT-CT-DEPRECATED](./HEADER-EXPECT-CT-DEPRECATED.md) | `info` | Expect-CT is not set |
| [HEADER-FEATURE-POLICY-DEPRECATED](./HEADER-FEATURE-POLICY-DEPRECATED.md) | `info` | Feature-Policy header is not used |
| [HEADER-HPKP-DEPRECATED](./HEADER-HPKP-DEPRECATED.md) | `medium` | Public-Key-Pins is not set |
| [HEADER-INFO-SERVER](./HEADER-INFO-SERVER.md) | `info` | Server header omitted or genericised |
| [HEADER-INFO-SERVER-TIMING](./HEADER-INFO-SERVER-TIMING.md) | `low` | Server-Timing not exposed in production |
| [HEADER-INFO-X-ASPNET-VERSION](./HEADER-INFO-X-ASPNET-VERSION.md) | `low` | X-AspNet-Version header is absent |
| [HEADER-INFO-X-GENERATOR](./HEADER-INFO-X-GENERATOR.md) | `info` | X-Generator header is absent |
| [HEADER-INFO-X-POWERED-BY](./HEADER-INFO-X-POWERED-BY.md) | `low` | X-Powered-By header is absent |
| [HEADER-NEL-NONE](./HEADER-NEL-NONE.md) | `info` | NEL (Network Error Logging) is set |
| [HEADER-PERMISSIONS-POLICY-MISSING](./HEADER-PERMISSIONS-POLICY-MISSING.md) | `low` | Permissions-Policy is set |
| [HEADER-REFERRER-POLICY-MISSING](./HEADER-REFERRER-POLICY-MISSING.md) | `low` | Referrer-Policy is set |
| [HEADER-REFERRER-POLICY-UNSAFE](./HEADER-REFERRER-POLICY-UNSAFE.md) | `medium` | Referrer-Policy avoids `unsafe-url` |
| [HEADER-REPORTING-ENDPOINTS-NONE](./HEADER-REPORTING-ENDPOINTS-NONE.md) | `info` | Reporting endpoints are configured |
| [HEADER-XCTO-MISSING](./HEADER-XCTO-MISSING.md) | `medium` | X-Content-Type-Options: nosniff is set |
| [HEADER-XFO-MISSING](./HEADER-XFO-MISSING.md) | `medium` | X-Frame-Options is set |
| [HEADER-XSS-PROTECTION-DEPRECATED](./HEADER-XSS-PROTECTION-DEPRECATED.md) | `info` | X-XSS-Protection is absent or `0` |

### Family: http

14 checks.

| ID | Severity | Title |
|---|---|---|
| [HTTP-404-DEFAULT-ERROR-PAGE](./HTTP-404-DEFAULT-ERROR-PAGE.md) | `low` | 404 page is customised |
| [HTTP-404-STACK-TRACE](./HTTP-404-STACK-TRACE.md) | `high` | 404 page does not leak a stack trace |
| [HTTP-COMPRESSION-NONE](./HTTP-COMPRESSION-NONE.md) | `info` | Responses are compressed |
| [HTTP-CORS-NULL-ORIGIN](./HTTP-CORS-NULL-ORIGIN.md) | `high` | CORS does not allow `null` origin |
| [HTTP-CORS-ORIGIN-REFLECTED](./HTTP-CORS-ORIGIN-REFLECTED.md) | `high` | CORS does not reflect arbitrary origins |
| [HTTP-CORS-WILDCARD-CREDENTIALS](./HTTP-CORS-WILDCARD-CREDENTIALS.md) | `high` | CORS does not combine wildcard origin with credentials |
| [HTTP-HTTP2-MISSING](./HTTP-HTTP2-MISSING.md) | `low` | HTTP/2 is negotiated |
| [HTTP-HTTP3-MISSING](./HTTP-HTTP3-MISSING.md) | `info` | HTTP/3 advertised via Alt-Svc |
| [HTTP-MIXED-CONTENT](./HTTP-MIXED-CONTENT.md) | `high` | Homepage has no mixed-content references |
| [HTTP-OPTIONS-DANGEROUS-METHODS](./HTTP-OPTIONS-DANGEROUS-METHODS.md) | `medium` | OPTIONS does not advertise dangerous methods |
| [HTTP-TRACE-ENABLED](./HTTP-TRACE-ENABLED.md) | `medium` | TRACE is disabled |
| [ROBOTS-TXT-INVALID](./ROBOTS-TXT-INVALID.md) | `info` | robots.txt parses correctly when present |
| [SRI-EXTERNAL-RESOURCE-NO-INTEGRITY](./SRI-EXTERNAL-RESOURCE-NO-INTEGRITY.md) | `medium` | External scripts/stylesheets carry SRI integrity |
| [WELLKNOWN-CHANGE-PASSWORD-MISSING](./WELLKNOWN-CHANGE-PASSWORD-MISSING.md) | `info` | Site exposes /.well-known/change-password |

### Family: tls

32 checks.

| ID | Severity | Title |
|---|---|---|
| [TLS-ALPN-NO-HTTP2](./TLS-ALPN-NO-HTTP2.md) | `low` | HTTP/2 is advertised via ALPN |
| [TLS-CERT-CHAIN-INCOMPLETE](./TLS-CERT-CHAIN-INCOMPLETE.md) | `high` | Certificate chain validates against system roots |
| [TLS-CERT-EXPIRED](./TLS-CERT-EXPIRED.md) | `critical` | Certificate is not expired |
| [TLS-CERT-EXPIRES-SOON-14D](./TLS-CERT-EXPIRES-SOON-14D.md) | `high` | Certificate has runway |
| [TLS-CERT-EXPIRES-SOON-30D](./TLS-CERT-EXPIRES-SOON-30D.md) | `medium` | Certificate has runway |
| [TLS-CERT-NAME-MISMATCH](./TLS-CERT-NAME-MISMATCH.md) | `high` | Certificate covers the requested hostname |
| [TLS-CERT-NO-CT](./TLS-CERT-NO-CT.md) | `low` | Certificate is logged in Certificate Transparency |
| [TLS-CERT-SELF-SIGNED](./TLS-CERT-SELF-SIGNED.md) | `critical` | Leaf is signed by a CA, not itself |
| [TLS-CERT-WEAK-ECC](./TLS-CERT-WEAK-ECC.md) | `high` | ECC key size meets modern guidance |
| [TLS-CERT-WEAK-RSA](./TLS-CERT-WEAK-RSA.md) | `high` | RSA key size meets modern guidance |
| [TLS-CERT-WEAK-SIGNATURE](./TLS-CERT-WEAK-SIGNATURE.md) | `high` | Certificate signed with a strong hash |
| [TLS-CIPHER-3DES](./TLS-CIPHER-3DES.md) | `medium` | 3DES cipher suites are rejected |
| [TLS-CIPHER-CBC-TLS10](./TLS-CIPHER-CBC-TLS10.md) | `medium` | CBC ciphers not accepted under TLS 1.0 |
| [TLS-CIPHER-DES](./TLS-CIPHER-DES.md) | `high` | DES cipher suites are rejected |
| [TLS-CIPHER-DH-WEAK](./TLS-CIPHER-DH-WEAK.md) | `high` | DHE key exchange uses at least 2048-bit parameters |
| [TLS-CIPHER-EXPORT](./TLS-CIPHER-EXPORT.md) | `critical` | EXPORT cipher suites are rejected |
| [TLS-CIPHER-NO-FORWARD-SECRECY](./TLS-CIPHER-NO-FORWARD-SECRECY.md) | `high` | Forward secrecy is in use |
| [TLS-CIPHER-NULL](./TLS-CIPHER-NULL.md) | `critical` | NULL cipher suites are rejected |
| [TLS-CIPHER-RC4](./TLS-CIPHER-RC4.md) | `high` | RC4 cipher suites are rejected |
| [TLS-HSTS-MAX-AGE-LOW](./TLS-HSTS-MAX-AGE-LOW.md) | `medium` | HSTS max-age is at least one year |
| [TLS-HSTS-MISSING](./TLS-HSTS-MISSING.md) | `high` | HSTS is set |
| [TLS-HSTS-NO-INCLUDESUBDOMAINS](./TLS-HSTS-NO-INCLUDESUBDOMAINS.md) | `low` | HSTS covers subdomains |
| [TLS-HSTS-NO-PRELOAD](./TLS-HSTS-NO-PRELOAD.md) | `info` | HSTS preload is configured |
| [TLS-OCSP-STAPLING-MISSING](./TLS-OCSP-STAPLING-MISSING.md) | `low` | OCSP stapling is enabled |
| [TLS-PROTOCOL-LEGACY-SSL2](./TLS-PROTOCOL-LEGACY-SSL2.md) | `critical` | SSLv2 is disabled |
| [TLS-PROTOCOL-LEGACY-SSL3](./TLS-PROTOCOL-LEGACY-SSL3.md) | `critical` | SSLv3 is disabled |
| [TLS-PROTOCOL-LEGACY-TLS10](./TLS-PROTOCOL-LEGACY-TLS10.md) | `high` | TLS 1.0 is disabled |
| [TLS-PROTOCOL-LEGACY-TLS11](./TLS-PROTOCOL-LEGACY-TLS11.md) | `high` | TLS 1.1 is disabled |
| [TLS-PROTOCOL-TLS12-MISSING](./TLS-PROTOCOL-TLS12-MISSING.md) | `high` | TLS 1.2 is supported |
| [TLS-PROTOCOL-TLS13-MISSING](./TLS-PROTOCOL-TLS13-MISSING.md) | `medium` | TLS 1.3 is supported |
| [TLS-REDIRECT-HTTP-TO-HTTPS](./TLS-REDIRECT-HTTP-TO-HTTPS.md) | `high` | Plain HTTP redirects to HTTPS |
| [TLS-VULN-HEARTBLEED](./TLS-VULN-HEARTBLEED.md) | `critical` | Server is not vulnerable to Heartbleed |

### Family: wellknown

6 checks.

| ID | Severity | Title |
|---|---|---|
| [WELLKNOWN-SECURITY-TXT-EXPIRED](./WELLKNOWN-SECURITY-TXT-EXPIRED.md) | `high` | security.txt has not expired |
| [WELLKNOWN-SECURITY-TXT-MISSING](./WELLKNOWN-SECURITY-TXT-MISSING.md) | `medium` | security.txt is published |
| [WELLKNOWN-SECURITY-TXT-NO-CONTACT](./WELLKNOWN-SECURITY-TXT-NO-CONTACT.md) | `high` | security.txt declares Contact |
| [WELLKNOWN-SECURITY-TXT-NO-EXPIRES](./WELLKNOWN-SECURITY-TXT-NO-EXPIRES.md) | `medium` | security.txt declares Expires |
| [WELLKNOWN-SECURITY-TXT-NO-SIGNATURE](./WELLKNOWN-SECURITY-TXT-NO-SIGNATURE.md) | `low` | security.txt is OpenPGP-signed |
| [WELLKNOWN-SECURITY-TXT-NOT-HTTPS](./WELLKNOWN-SECURITY-TXT-NOT-HTTPS.md) | `medium` | security.txt is served over HTTPS |

<!-- Generated by scripts/gen-checks-docs.sh — do not edit by hand. -->
