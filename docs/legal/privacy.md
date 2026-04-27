# WebSec0 — Privacy Policy

> **Version**: 0.1 · **Last updated**: 2026-04-27
> This policy applies to the public instance at `websec0.example`.
> Self-hosters are the data controller for their own deployment.

---

## 1. Data collected

| Data | Retention | Legal basis |
|------|-----------|-------------|
| **Target domain** | Stored with the scan report for the configured TTL (24 h on the public instance). | Performance of a service (GDPR art. 6(1)(b)) |
| **Client IP** | Last octet zeroed for IPv4 (e.g. `192.168.1.0`), /64 prefix for IPv6. Retained ≤ 7 days for rate-limiting. | Legitimate interest (GDPR art. 6(1)(f)) |
| **User-Agent** | Stored in access logs. Retained ≤ 7 days. | Legitimate interest |
| **Scan report** | GUIDv4-keyed JSON blob. Auto-deleted after TTL. | Performance of a service |

No full client IP addresses are stored in persistent storage. No user accounts or authentication cookies are created.

## 2. What we do not collect

- Analytics, tracking pixels, or heatmaps
- Third-party advertising cookies
- Browser fingerprinting data
- Content of HTTP responses from the scanned target, except metadata needed to produce findings
- Email addresses or personal identifiers of any kind

## 3. Sub-processors

The public instance is hosted on infrastructure located within the EU/EEA. No personal data is shared with third parties for advertising, profiling, or any purpose other than operating the service. Self-hosters choose their own infrastructure and become the independent data controller; this policy does not apply to their deployment.

## 4. Your GDPR rights

Under GDPR arts. 15–17, you have the following rights regarding data held about you:

- **Art. 15** — Right of access: request a copy of the data held.
- **Art. 16** — Right to rectification: request correction of inaccurate data.
- **Art. 17** — Right to erasure ("right to be forgotten"): request deletion of your data.

To exercise these rights, contact `privacy@websec0.example`. We will respond within 30 calendar days. Where the request relates to a specific scan report, include the scan GUID.

## 5. Data Protection Officer (DPO)

A DPO has not been formally designated for the public instance (the volume of personal data processed does not trigger mandatory designation under GDPR art. 37 in most interpretations). Privacy inquiries are handled at `privacy@websec0.example`.

*Self-hosters processing personal data at scale should assess whether DPO designation is required for their jurisdiction.*

## 6. Breach notification

In the event of a personal data breach affecting the rights and freedoms of natural persons, we will notify the relevant supervisory authority within 72 hours where feasible (GDPR art. 33). If the breach is likely to result in high risk to individuals, affected parties will be notified without undue delay (GDPR art. 34).

## 7. Changes to this policy

This policy may be updated to reflect changes in our practices or applicable law. The version number and date at the top of this document reflect the last revision. Continued use of the service after a material change constitutes acceptance of the updated policy. Major changes will be announced in the repository changelog.

---

**Contact**: `privacy@websec0.example`
