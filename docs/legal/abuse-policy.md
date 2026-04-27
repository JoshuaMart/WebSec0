# WebSec0 — Abuse Policy

> **Version**: 0.1 · **Last updated**: 2026-04-27

This document describes the technical and organisational measures in place to prevent
misuse of the WebSec0 public scanning service.

---

## Measures in place

| Measure | Detail |
|---------|--------|
| **Captcha** | hCaptcha or Cloudflare Turnstile on the web form. Not required for direct API use. |
| **Rate limit per IP** | 10 scans per hour per anonymised IP address (last octet zeroed). Configurable for self-hosters. |
| **Re-scan cooldown** | Minimum 5 minutes between two scans of the same target hostname (all source IPs combined). |
| **Domain blocklist** | `.gov`, `.mil`, `.gouv.fr`, `.gc.ca`, `.gov.uk`, `.bund.de`, `europa.eu`, and equivalent TLDs. Returns HTTP 451. |
| **IP range blocklist** | RFC 1918 private ranges, loopback, link-local, CGNAT (`100.64.0.0/10`), IPv6 ULA and link-local. Returns HTTP 422. |
| **Abuse pattern detection** | > 5 distinct targets from the same IP in < 5 minutes → 429 `abuse_flagged`, temporary block applied. |
| **Audit log** | Immutable JSON-line log retained for 7 days. Contains: timestamp, anonymised IP (/24 for IPv4, /64 for IPv6), SHA-256 hash of the target (not in plaintext), HTTP status returned. No domain stored in plaintext in logs. |
| **robots.txt compliance** | If a target's `robots.txt` disallows `User-agent: WebSec0`, the scan is cancelled with an explanatory message. |
| **GUIDv4 report IDs** | 122-bit entropy via `crypto/rand`. Non-enumerable, non-guessable. |
| **Private report mode** | `options.private: true` requires a 256-bit token for report retrieval. Token returned once on creation. |
| **Response commitment** | Abuse reports sent to `abuse@websec0.example` are acknowledged within 72 hours. |

## Reporting abuse

If you believe this scanner has been used to scan your infrastructure without authorisation, or
if you wish to report any other form of misuse, contact:

**`abuse@websec0.example`**

Please include:
- The target domain or IP address
- Date and time of the scan (UTC)
- Any log excerpts or evidence
- Your contact details for follow-up

We will investigate and respond within 72 hours.

## Requesting opt-out

To permanently opt out your domain from being scanned by the public WebSec0 instance:

1. Add the following to your `robots.txt`:
   ```
   User-agent: WebSec0
   Disallow: /
   ```
2. Or contact `abuse@websec0.example` with your domain name to be added to the blocklist.

## Legal references

The following laws apply to unauthorised use of this scanner:

- **CFAA** (Computer Fraud and Abuse Act) — United States
- **CMA 1990** (Computer Misuse Act) — United Kingdom
- **§202c StGB** (Vorbereiten des Ausspähens und Abfangens von Daten) — Germany
- **Art. 323-1 du Code pénal** — France

WebSec0 is a passive scanner. Misuse of this tool to scan systems without authorisation may constitute a criminal offence under these and equivalent laws in other jurisdictions.
