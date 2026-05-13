# WebSec0 — Implementation TODO

> Living checklist for v1.1 Tracks the work from empty repo to shippable binary.
> Each phase builds on the previous one; respect the order.

---

## TLS probes

### Modern (`internal/tls`)

- [ ] Bundle a CCADB Mozilla root fallback so the binary validates chains identically across host OSes — **moderate / passive** (embed a curated PEM, fall back when system pool is empty)
- [ ] SCT extraction from `state.SignedCertificateTimestamps` (count + log IDs) — **moderate / passive**
- [ ] SCT extraction from the leaf cert's X.509 extension (OID 1.3.6.1.4.1.11129.2.4.2) — **complex / passive** (ASN.1 OctetString of SignedCertificateTimestampList)
- [ ] 0-RTT (early data) detection on TLS 1.3 — **complex / passive** (requires real early-data send, not directly exposed)

#### TLS weakness heuristics

- [ ] **FREAK** (CVE-2015-0204) — placeholder *Not assessed* — **moderate / passive** (export cipher enumeration; not in stdlib, needs raw ClientHello)
- [ ] **Logjam** (CVE-2015-4000) — placeholder *Not assessed* — **complex / passive** (parse ServerKeyExchange DH group, reject < 1024 bits)
- [ ] **CRIME** (CVE-2012-4929) — placeholder *Not assessed* — **complex / passive** (TLS compression detection; stdlib disables it client-side, so requires raw probing)
- [ ] **Raccoon Attack** (CVE-2020-1968) — placeholder *Not assessed* — **complex / passive** (multi-handshake DH-share comparison)

## Scoring TLS

- [ ] Reference fixtures: snapshot scores for 5 well-known sites in CI (no live network, replay captured handshakes) — *deferred to v1.1*

## API layer

- [ ] `internal/api/cors.go`: CORS for the frontend — *deferred; same-origin works out of the box with the embedded frontend*

## Frontend (Astro 6 + Preact)

- [ ] Implement copy-button on every remediation snippet — *deferred to v1.x once a remediation tab exists*
