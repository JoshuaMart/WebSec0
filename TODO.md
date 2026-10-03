# WebSec0 — Implementation TODO

> Living checklist for v1.1 Tracks the work from empty repo to shippable binary.
> Each phase builds on the previous one; respect the order.

---

## TLS probes

### Modern (`internal/tls`)

- [x] Embed the Go project's Mozilla/NSS root fallback for environments without system trust — system roots remain preferred; validation can still differ across OSes
- [x] SCT extraction from `state.SignedCertificateTimestamps` (count + unique log IDs, unparsed count, API + certificate tab) — informational; signatures and inclusion not verified
- [x] SCT extraction from the leaf cert's X.509 extension (OID 1.3.6.1.4.1.11129.2.4.2) — count, unique log IDs and decoding status, separate from handshake SCTs; informational only
- [ ] 0-RTT (early data) detection on TLS 1.3 — **complex / passive** (requires real early-data send, not directly exposed)

#### TLS weakness heuristics

- [ ] **FREAK** (CVE-2015-0204) — placeholder *Not assessed* — **moderate / passive** (export cipher enumeration; not in stdlib, needs raw ClientHello)
- [ ] **Logjam** (CVE-2015-4000) — placeholder *Not assessed* — **complex / passive** (parse ServerKeyExchange DH group, reject < 1024 bits)
- [ ] **CRIME** (CVE-2012-4929) — placeholder *Not assessed* — **complex / passive** (TLS compression detection; stdlib disables it client-side, so requires raw probing)
- [ ] **Raccoon Attack** (CVE-2020-1968) — placeholder *Not assessed* — **complex / passive** (multi-handshake DH-share comparison)

## Scoring TLS

- [x] Reference fixtures: five synthetic TLS report profiles with fixed dates, exact sub-scores and grade expectations in CI — no live network; see `internal/scoring/testdata/tls/README.md`

## API layer

- [ ] `internal/api/cors.go`: CORS for the frontend — *deferred; same-origin works out of the box with the embedded frontend*

## Frontend (Astro 6 + Preact)

- [ ] Implement copy-button on every remediation snippet — *deferred to v1.x once a remediation tab exists*
