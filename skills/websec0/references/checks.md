# Check catalog (condensed)

126 checks across 7 families. The live source is
`GET /api/v1/checks` (machine-readable) — re-fetch it for
authoritative metadata. This file is the in-context summary the
skill loads when the agent needs to know which IDs exist before
acting on a scan body.

## Contents

- [Family: cookies](#family-cookies)
- [Family: dns](#family-dns)
- [Family: email](#family-email)
- [Family: headers](#family-headers)
- [Family: http](#family-http)
- [Family: tls](#family-tls)
- [Family: wellknown](#family-wellknown)
- [Severity legend](#severity-legend)
- [How to fetch a single check](#how-to-fetch-a-single-check)

## Family: cookies

7 checks.

| ID | Severity | Title |
|---|---|---|
| COOKIE-HTTPONLY-MISSING-SESSION | `high` | Session cookies are HttpOnly |
| COOKIE-NO-SECURITY-FLAGS | `medium` | Every cookie has at least one security flag |
| COOKIE-PREFIX-HOST-MISSING | `low` | Session cookies use the __Host- prefix |
| COOKIE-PREFIX-SECURE-MISSING | `low` | Session cookies use the __Secure- prefix |
| COOKIE-SAMESITE-MISSING | `medium` | Cookies declare SameSite explicitly |
| COOKIE-SAMESITE-NONE-WITHOUT-SECURE | `medium` | SameSite=None cookies also carry Secure |
| COOKIE-SECURE-MISSING | `medium` | All cookies carry Secure |

## Family: dns

10 checks.

| ID | Severity | Title |
|---|---|---|
| DNS-AAAA-MISSING | `low` | Hostname publishes IPv6 |
| DNS-CAA-MISSING | `low` | Zone declares CAA records |
| DNS-CAA-NO-IODEF | `info` | CAA includes an iodef contact |
| DNS-DANGLING-CNAME | `high` | No dangling CNAME (subdomain takeover risk) |
| DNS-DNSSEC-BROKEN | `critical` | DNSSEC validation succeeds |
| DNS-DNSSEC-MISSING | `medium` | Zone is signed with DNSSEC |
| DNS-DNSSEC-WEAK-ALGO | `high` | DNSSEC uses a modern signing algorithm |
| DNS-NS-DIVERSITY-LOW | `low` | Zone has ≥ 2 distinct nameservers |
| DNS-TTL-ABERRANT | `info` | A/AAAA TTL is in a sensible range |
| DNS-WILDCARD-DETECTED | `info` | Zone does not wildcard-resolve |

## Family: email

31 checks.

| ID | Severity | Title |
|---|---|---|
| EMAIL-BIMI-INVALID-SVG | `low` | BIMI logo is a valid SVG Tiny PS document |
| EMAIL-BIMI-MISSING | `info` | Domain publishes BIMI |
| EMAIL-DANE-INVALID-PARAMS | `high` | DANE/TLSA records have valid parameters |
| EMAIL-DANE-MISMATCH | `high` | DANE/TLSA records match the MX certificate |
| EMAIL-DANE-MISSING | `low` | DANE/TLSA records published for MX hosts |
| EMAIL-DKIM-NONE-FOUND | `medium` | DKIM key published on at least one common selector |
| EMAIL-DKIM-SHA1 | `medium` | DKIM uses SHA-256 (not SHA-1) |
| EMAIL-DKIM-TEST-MODE | `low` | DKIM records are not in test mode |
| EMAIL-DKIM-WEAK-KEY | `medium` | DKIM keys are at least 1024 bits |
| EMAIL-DMARC-INVALID-SYNTAX | `high` | DMARC record is syntactically valid |
| EMAIL-DMARC-MISALIGNED-DKIM | `medium` | DMARC DKIM alignment is strict |
| EMAIL-DMARC-MISALIGNED-SPF | `medium` | DMARC SPF alignment is strict |
| EMAIL-DMARC-MISSING | `high` | Domain publishes DMARC |
| EMAIL-DMARC-NO-RUA | `low` | DMARC defines an aggregate-report endpoint (rua=) |
| EMAIL-DMARC-POLICY-NONE | `medium` | DMARC policy is enforcing (not `p=none`) |
| EMAIL-DMARC-POLICY-WEAK | `low` | DMARC policy is `p=reject` |
| EMAIL-MTASTS-MAX-AGE-LOW | `low` | MTA-STS max_age is at least 30 days |
| EMAIL-MTASTS-MISSING | `medium` | Domain publishes MTA-STS |
| EMAIL-MTASTS-MODE-TESTING | `medium` | MTA-STS mode is `enforce` |
| EMAIL-MTASTS-MX-MISMATCH | `high` | MTA-STS policy covers all DNS MX entries |
| EMAIL-SPF-INVALID-SYNTAX | `high` | SPF record is syntactically valid |
| EMAIL-SPF-MISSING | `high` | Domain publishes an SPF record |
| EMAIL-SPF-MULTIPLE-RECORDS | `high` | Single SPF record per RFC 7208 §3.2 |
| EMAIL-SPF-NO-ALL-MECHANISM | `medium` | SPF record terminates with an `all` mechanism |
| EMAIL-SPF-PASS-ALL | `high` | SPF doesn't end with `+all` |
| EMAIL-SPF-PTR-MECHANISM | `medium` | SPF avoids the deprecated `ptr` mechanism |
| EMAIL-SPF-SOFTFAIL-ALL | `low` | SPF ends with hard fail (`-all`) |
| EMAIL-SPF-TOO-MANY-LOOKUPS | `high` | SPF evaluation stays within the 10-lookup limit |
| EMAIL-STARTTLS-FAIL | `high` | MX server advertises STARTTLS |
| EMAIL-STARTTLS-WEAK-TLS | `medium` | STARTTLS negotiates TLS 1.2 or higher |
| EMAIL-TLSRPT-MISSING | `low` | Domain publishes TLS-RPT |

## Family: headers

26 checks.

| ID | Severity | Title |
|---|---|---|
| HEADER-COEP-MISSING | `low` | Cross-Origin-Embedder-Policy is set |
| HEADER-COOP-MISSING | `low` | Cross-Origin-Opener-Policy is set |
| HEADER-CORP-MISSING | `low` | Cross-Origin-Resource-Policy is set |
| HEADER-CSP-MISSING | `medium` | Content-Security-Policy is set |
| HEADER-CSP-NO-BASE-URI | `low` | CSP locks <base> elements |
| HEADER-CSP-NO-FRAME-ANCESTORS | `medium` | CSP restricts framing |
| HEADER-CSP-NO-OBJECT-SRC | `low` | CSP restricts plugin sources |
| HEADER-CSP-UNSAFE-EVAL | `high` | CSP forbids 'unsafe-eval' |
| HEADER-CSP-UNSAFE-INLINE | `high` | CSP forbids 'unsafe-inline' for scripts |
| HEADER-CSP-WILDCARD-SRC | `medium` | CSP avoids wildcard sources for active content |
| HEADER-EXPECT-CT-DEPRECATED | `info` | Expect-CT is not set |
| HEADER-FEATURE-POLICY-DEPRECATED | `info` | Feature-Policy header is not used |
| HEADER-HPKP-DEPRECATED | `medium` | Public-Key-Pins is not set |
| HEADER-INFO-SERVER | `info` | Server header omitted or genericised |
| HEADER-INFO-SERVER-TIMING | `low` | Server-Timing not exposed in production |
| HEADER-INFO-X-ASPNET-VERSION | `low` | X-AspNet-Version header is absent |
| HEADER-INFO-X-GENERATOR | `info` | X-Generator header is absent |
| HEADER-INFO-X-POWERED-BY | `low` | X-Powered-By header is absent |
| HEADER-NEL-NONE | `info` | NEL (Network Error Logging) is set |
| HEADER-PERMISSIONS-POLICY-MISSING | `low` | Permissions-Policy is set |
| HEADER-REFERRER-POLICY-MISSING | `low` | Referrer-Policy is set |
| HEADER-REFERRER-POLICY-UNSAFE | `medium` | Referrer-Policy avoids `unsafe-url` |
| HEADER-REPORTING-ENDPOINTS-NONE | `info` | Reporting endpoints are configured |
| HEADER-XCTO-MISSING | `medium` | X-Content-Type-Options: nosniff is set |
| HEADER-XFO-MISSING | `medium` | X-Frame-Options is set |
| HEADER-XSS-PROTECTION-DEPRECATED | `info` | X-XSS-Protection is absent or `0` |

## Family: http

14 checks.

| ID | Severity | Title |
|---|---|---|
| HTTP-404-DEFAULT-ERROR-PAGE | `low` | 404 page is customised |
| HTTP-404-STACK-TRACE | `high` | 404 page does not leak a stack trace |
| HTTP-COMPRESSION-NONE | `info` | Responses are compressed |
| HTTP-CORS-NULL-ORIGIN | `high` | CORS does not allow `null` origin |
| HTTP-CORS-ORIGIN-REFLECTED | `high` | CORS does not reflect arbitrary origins |
| HTTP-CORS-WILDCARD-CREDENTIALS | `high` | CORS does not combine wildcard origin with credentials |
| HTTP-HTTP2-MISSING | `low` | HTTP/2 is negotiated |
| HTTP-HTTP3-MISSING | `info` | HTTP/3 advertised via Alt-Svc |
| HTTP-MIXED-CONTENT | `high` | Homepage has no mixed-content references |
| HTTP-OPTIONS-DANGEROUS-METHODS | `medium` | OPTIONS does not advertise dangerous methods |
| HTTP-TRACE-ENABLED | `medium` | TRACE is disabled |
| ROBOTS-TXT-INVALID | `info` | robots.txt parses correctly when present |
| SRI-EXTERNAL-RESOURCE-NO-INTEGRITY | `medium` | External scripts/stylesheets carry SRI integrity |
| WELLKNOWN-CHANGE-PASSWORD-MISSING | `info` | Site exposes /.well-known/change-password |

## Family: tls

32 checks.

| ID | Severity | Title |
|---|---|---|
| TLS-ALPN-NO-HTTP2 | `low` | HTTP/2 is advertised via ALPN |
| TLS-CERT-CHAIN-INCOMPLETE | `high` | Certificate chain validates against system roots |
| TLS-CERT-EXPIRED | `critical` | Certificate is not expired |
| TLS-CERT-EXPIRES-SOON-14D | `high` | Certificate has runway |
| TLS-CERT-EXPIRES-SOON-30D | `medium` | Certificate has runway |
| TLS-CERT-NAME-MISMATCH | `high` | Certificate covers the requested hostname |
| TLS-CERT-NO-CT | `low` | Certificate is logged in Certificate Transparency |
| TLS-CERT-SELF-SIGNED | `critical` | Leaf is signed by a CA, not itself |
| TLS-CERT-WEAK-ECC | `high` | ECC key size meets modern guidance |
| TLS-CERT-WEAK-RSA | `high` | RSA key size meets modern guidance |
| TLS-CERT-WEAK-SIGNATURE | `high` | Certificate signed with a strong hash |
| TLS-CIPHER-3DES | `medium` | 3DES cipher suites are rejected |
| TLS-CIPHER-CBC-TLS10 | `medium` | CBC ciphers not accepted under TLS 1.0 |
| TLS-CIPHER-DES | `high` | DES cipher suites are rejected |
| TLS-CIPHER-DH-WEAK | `high` | DHE key exchange uses at least 2048-bit parameters |
| TLS-CIPHER-EXPORT | `critical` | EXPORT cipher suites are rejected |
| TLS-CIPHER-NO-FORWARD-SECRECY | `high` | Forward secrecy is in use |
| TLS-CIPHER-NULL | `critical` | NULL cipher suites are rejected |
| TLS-CIPHER-RC4 | `high` | RC4 cipher suites are rejected |
| TLS-HSTS-MAX-AGE-LOW | `medium` | HSTS max-age is at least one year |
| TLS-HSTS-MISSING | `high` | HSTS is set |
| TLS-HSTS-NO-INCLUDESUBDOMAINS | `low` | HSTS covers subdomains |
| TLS-HSTS-NO-PRELOAD | `info` | HSTS preload is configured |
| TLS-OCSP-STAPLING-MISSING | `low` | OCSP stapling is enabled |
| TLS-PROTOCOL-LEGACY-SSL2 | `critical` | SSLv2 is disabled |
| TLS-PROTOCOL-LEGACY-SSL3 | `critical` | SSLv3 is disabled |
| TLS-PROTOCOL-LEGACY-TLS10 | `high` | TLS 1.0 is disabled |
| TLS-PROTOCOL-LEGACY-TLS11 | `high` | TLS 1.1 is disabled |
| TLS-PROTOCOL-TLS12-MISSING | `high` | TLS 1.2 is supported |
| TLS-PROTOCOL-TLS13-MISSING | `medium` | TLS 1.3 is supported |
| TLS-REDIRECT-HTTP-TO-HTTPS | `high` | Plain HTTP redirects to HTTPS |
| TLS-VULN-HEARTBLEED | `critical` | Server is not vulnerable to Heartbleed |

## Family: wellknown

6 checks.

| ID | Severity | Title |
|---|---|---|
| WELLKNOWN-SECURITY-TXT-EXPIRED | `high` | security.txt has not expired |
| WELLKNOWN-SECURITY-TXT-MISSING | `medium` | security.txt is published |
| WELLKNOWN-SECURITY-TXT-NO-CONTACT | `high` | security.txt declares Contact |
| WELLKNOWN-SECURITY-TXT-NO-EXPIRES | `medium` | security.txt declares Expires |
| WELLKNOWN-SECURITY-TXT-NO-SIGNATURE | `low` | security.txt is OpenPGP-signed |
| WELLKNOWN-SECURITY-TXT-NOT-HTTPS | `medium` | security.txt is served over HTTPS |

## Severity legend

| Severity   | Meaning                                                              |
|------------|----------------------------------------------------------------------|
| `critical` | Trivially exploitable, direct impact on confidentiality or integrity |
| `high`     | Exploitable with moderate effort, significant impact                 |
| `medium`   | Defence-in-depth weakness, conditional exploitation                  |
| `low`      | Best practice not respected, minor information disclosure            |
| `info`     | Informational, no direct impact                                      |

## How to fetch a single check

```bash
curl -s "$WEBSEC0_SERVER/api/v1/checks/<ID>" | jq
```

Returns the full `CheckMeta` for that ID (description, RFC refs,
default severity). The runtime registry is the source of truth — this
file is regenerated by `scripts/gen-checks-docs.sh` and may lag the
running server by one release.

<!-- Generated by scripts/gen-checks-docs.sh — do not edit by hand. -->
