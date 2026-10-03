# WebSec0 — Implementation TODO

## TLS probes

### Modern (`internal/tls`)

- [ ] 0-RTT (early data) detection on TLS 1.3 — **complex / passive** (requires real early-data send, not directly exposed)

#### TLS weakness heuristics

- [ ] **FREAK** (CVE-2015-0204) — placeholder *Not assessed* — **moderate / passive** (export cipher enumeration; not in stdlib, needs raw ClientHello)
- [ ] **Logjam** (CVE-2015-4000) — placeholder *Not assessed* — **complex / passive** (parse ServerKeyExchange DH group, reject < 1024 bits)
- [ ] **CRIME** (CVE-2012-4929) — placeholder *Not assessed* — **complex / passive** (TLS compression detection; stdlib disables it client-side, so requires raw probing)
- [ ] **Raccoon Attack** (CVE-2020-1968) — placeholder *Not assessed* — **complex / passive** (multi-handshake DH-share comparison)

## API layer

- [ ] `internal/api/cors.go`: CORS for the frontend — *deferred; same-origin works out of the box with the embedded frontend*

## Frontend (Astro 6 + Preact)

- [ ] Implement copy-button on every remediation snippet — *deferred to v1.x once a remediation tab exists*
