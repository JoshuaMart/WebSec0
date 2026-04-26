# WebSec101 — TODO

Plan d'exécution séquentiel vers la release **0.1.0**. Les phases sont ordonnées : chaque phase suppose que les précédentes sont closes (ou suffisamment avancées pour ne pas bloquer). Les **milestones** marquent les états testables en bout de chaîne.

## Phase 0 — Bootstrap et licence

- [ ] Créer le repo GitHub `your-org/websec101` (public, MIT)
- [x] Ajouter `LICENSE` (MIT, 2026 + nom du copyright holder)
- [x] Ajouter `.gitignore` (Go + Node + IDE + binaries + dist)
- [x] Ajouter `.gitattributes` (line-endings, linguist hints)
- [x] Créer `README.md` minimal (titre, badge "WIP", lien vers `SPECIFICATIONS.md`)
- [x] Copier `SPECIFICATIONS.md` à la racine
- [x] Initialiser `go.mod` (`go mod init github.com/your-org/websec101`, Go 1.23)
- [x] Créer la structure de dossiers vide conforme au layout §2.2
- [x] Premier commit `chore: bootstrap repository`
- [ ] Ajouter `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1)
- [ ] Ajouter `CONTRIBUTING.md` (workflow PR, conventional commits, dev setup)
- [ ] Ajouter `SECURITY.md` (canal de divulgation, GPG key, délai 90j)
- [ ] Ajouter `CHANGELOG.md` (format Keep a Changelog, vide initialement)
- [x] Ajouter `.editorconfig`
- [ ] Configurer branch protection sur `main` (require PR review, require status checks, signed commits)
- [ ] Activer Dependabot security updates dans Settings GitHub

## Phase 1 — CI minimale et outillage du repo

- [x] Créer `.github/workflows/ci.yml` minimal (lint Go + test Go)
- [x] Configurer `golangci-lint` via `.golangci.yml` (preset opinionated)
- [x] Ajouter `gosec` au pipeline lint
- [x] Ajouter `commitlint` config (`commitlint.config.js`) + workflow PR title check
- [x] Créer `Makefile` racine (`build`, `test`, `lint`, `clean`, `run`, `gen`, `test-race`)
- [ ] Configurer `dependabot.yml` (gomod weekly + github-actions weekly + npm weekly)
- [ ] Ajouter le workflow `codeql.yml` (Go + JavaScript, hebdo + PR sensibles)
- [ ] Ajouter `.github/PULL_REQUEST_TEMPLATE.md`
- [ ] Ajouter `.github/ISSUE_TEMPLATE/{bug_report,feature_request}.md`
- [ ] Activer OSSF Scorecard workflow

## Phase 2 — Foundation backend

- [x] `internal/version/version.go` : variables `Version`, `Commit`, `BuildDate` injectables via ldflags
- [x] `internal/config/config.go` : structure typée + chargement koanf (YAML + env + flags)
- [x] `internal/config/defaults.go` : valeurs par défaut conformes §4.6
- [x] Test unitaire chargement config + override env + override flag
- [x] Configuration logging via `log/slog` (JSON, niveau, format)
- [x] `internal/storage/store.go` : interface `ScanStore` conforme §9.1
- [x] `internal/storage/memory/store.go` : implémentation `patrickmn/go-cache`
- [x] Tests storage memory (Put/Get/Delete/UpdateStatus, TTL, expiration, concurrence)
- [x] `cmd/websec101/main.go` : skeleton qui charge config, init logger, ne fait rien d'autre
- [x] Vérifier `go run ./cmd/websec101 --help` fonctionne

## Phase 3 — API skeleton (spec-first via ogen)

- [x] `api/openapi.yaml` : spec OpenAPI 3.0 initiale avec endpoints §5.3
  - [x] Schémas `Scan`, `ScanRequest`, `Finding`, `Report`, `Check`, `Error`
  - [x] `POST /api/v1/scans` (202 Accepted)
  - [x] `GET /api/v1/scans/{guid}` (200)
  - [x] `GET /api/v1/scans/{guid}/markdown` (text/markdown)
  - [x] `GET /api/v1/scans/{guid}/sarif` (application/sarif+json)
  - [x] `DELETE /api/v1/scans/{guid}` (204)
  - [x] `GET /api/v1/checks` (200)
  - [x] `GET /api/v1/checks/{check_id}` (200)
  - [x] `GET /api/v1/health`
  - [x] `GET /api/v1/version`
  - [x] `GET /api/v1/openapi.json`
- [x] Configurer `ogen` avec `go generate` + `tools.go` pinning de version
- [x] Générer `internal/api/oas/` (serveur Go) et `pkg/client/` (client Go) — ogen v1.20 ne sépare plus serveur/client en CLI ; tout est généré dans `pkg/client/` et réutilisé côté serveur
- [x] Configurer Spectral lint dans `ci.yml` (style guide opinionated)
- [x] Workflow `verify-codegen.yml` : check anti-dérive ogen ↔ openapi.yaml
- [x] Implémenter le routeur HTTP (`net/http` + `chi/v5`) qui monte les handlers ogen
- [x] Middlewares : `request-id`, `recover`, `slog-access-log`, `cors` (allowlist)
- [x] Embed de `api/openapi.yaml` via `go:embed` et serve sur `/api/v1/openapi.json`
- [x] Implémenter `GET /api/v1/health` et `/api/v1/version` (real)
- [x] Stub des autres handlers (501 Not Implemented avec message clair)
- [x] Test d'intégration httptest sur health/version

## Phase 4 — Scanner orchestrator

- [x] `internal/checks/registry.go` : interface `Check` + registre central
  ```go
  type Check interface {
    ID() string
    Family() Family
    DefaultSeverity() Severity
    Run(ctx context.Context, target *Target) (*Finding, error)
  }
  ```
- [x] `internal/checks/catalog.go` : alimente `GET /api/v1/checks`
- [x] `internal/scanner/runner.go` : orchestrateur avec semaphore global + errgroup intra-scan + per-check timeout (cf. §4.5)
- [x] ~~`internal/scanner/target.go`~~ → `internal/checks/target.go` : type `Target` + cache DNS partagé (déplacé dans `checks/` pour éviter le cycle d'import scanner ↔ checks)
- [x] `internal/scanner/progress.go` : émetteur de progression typé pour SSE
- [x] `internal/api/handlers/scans.go` : implémenter `POST /scans` (génération GUIDv4, lancement async, retour 202)
- [x] Implémenter `GET /scans/{guid}` (toujours 200, status running/completed/failed)
- [x] `internal/api/sse/sse.go` : helper SSE avec `Last-Event-ID`, retry, heartbeat keepalive
- [x] Implémenter `GET /scans/{guid}/events` (SSE)
- [x] Mode `?wait=30s` synchrone bloquant (via `options.wait_seconds` sur POST, plus simple que query GET)
- [x] Test d'intégration : POST scan → GET → SSE → status completed

## Phase 5 — Premier check end-to-end (proof of orchestrator)

- [x] `internal/scanner/wellknown/securitytxt.go` : check `WELLKNOWN-SECURITY-TXT-MISSING`
- [x] Parser security.txt RFC 9116 (champs Contact, Expires, Signature, Encryption, etc.)
- [x] Checks dérivés : `WELLKNOWN-SECURITY-TXT-EXPIRED`, `*-NO-CONTACT`, `*-NO-EXPIRES`, `*-NOT-HTTPS`, `*-NO-SIGNATURE`
- [x] Enregistrer dans le registry
- [x] Tests unitaires (fichiers fixtures valides/invalides/expirés)
- [x] Test E2E via API : `POST /scans` sur exemple connu → finding remonte
- [x] **🎯 Milestone 1 : un scan via l'API retourne un findings sur security.txt**

## Phase 6 — Famille TLS

### 6.1 Modern TLS (stdlib)

- [x] `internal/scanner/tls/handshake.go` : handshake `crypto/tls` configurable par version (cf. spec §2.2 ; renommé de `modern.go`)
- [x] Énumération des versions supportées (TLS 1.2, TLS 1.3) → checks `TLS-PROTOCOL-TLS12-MISSING`, `*-TLS13-MISSING`
- [ ] Énumération exhaustive des cipher suites par version (différé : stdlib ne facilite pas ; via zcrypto en 6.3)
- [x] Détection Forward Secrecy (ECDHE/DHE) → `TLS-CIPHER-NO-FORWARD-SECRECY`
- [x] Détection ALPN (h2) → `TLS-ALPN-NO-HTTP2` (`h3` reporté avec QUIC)
- [x] Détection OCSP stapling → `TLS-OCSP-STAPLING-MISSING`

### 6.2 Validation certificat

- [x] Parsing de la chaîne complète, validation contre roots système
- [x] `TLS-CERT-EXPIRED`, `*-EXPIRES-SOON-14D`, `*-EXPIRES-SOON-30D`
- [x] `TLS-CERT-CHAIN-INCOMPLETE`
- [x] `TLS-CERT-NAME-MISMATCH` (SAN matching)
- [x] `TLS-CERT-SELF-SIGNED`
- [x] `TLS-CERT-WEAK-RSA` (< 2048), `TLS-CERT-WEAK-ECC` (< 256)
- [x] `TLS-CERT-WEAK-SIGNATURE` (MD5/SHA1)
- [ ] `TLS-CERT-NO-CT` (différé — besoin de `google/certificate-transparency-go`)

### 6.3 Legacy TLS (zcrypto)

- [ ] `internal/scanner/tls/legacy.go` : handshake via `zmap/zcrypto` pour TLS 1.0/1.1
- [ ] `TLS-PROTOCOL-LEGACY-TLS10`, `*-LEGACY-TLS11`
- [ ] Énumération ciphers anciens : NULL, EXPORT, RC4, DES, 3DES, CBC en TLS 1.0
- [ ] `TLS-CIPHER-NULL`, `*-EXPORT`, `*-RC4`, `*-DES`, `*-3DES`, `*-CBC-TLS10`
- [ ] `TLS-CIPHER-DH-WEAK` (DH params < 2048)

### 6.4 Probes raw SSLv2 / SSLv3

- [ ] `internal/scanner/tls/probes/sslv3.go` : ClientHello SSLv3 craft + analyse réponse (cf. §4.3)
- [ ] `internal/scanner/tls/probes/sslv2.go` : ClientHello SSLv2 (record format Netscape)
- [ ] Tests unitaires probes (mock TCP server répondant ServerHello/Alert/RST)
- [ ] Tests d'intégration contre `tls-v1-0.badssl.com`, `tls-v1-1.badssl.com`, `null.badssl.com`, `rc4.badssl.com`, etc.
- [ ] `TLS-PROTOCOL-LEGACY-SSL2`, `*-LEGACY-SSL3`

### 6.5 Heartbleed actif

- [ ] `internal/scanner/tls/heartbleed.go` : wrapper sur `zmap/zgrab2/modules/tls`
- [ ] `TLS-VULN-HEARTBLEED`
- [ ] Test contre `dh1024.badssl.com` ou cible vulnérable connue

### 6.6 HSTS et redirect HTTP→HTTPS

- [x] Parsing `Strict-Transport-Security` (max-age, includeSubDomains, preload)
- [x] `TLS-HSTS-MISSING`, `*-MAX-AGE-LOW`, `*-NO-INCLUDESUBDOMAINS`
- [ ] `TLS-HSTS-NO-PRELOAD` : check API hstspreload.org (différé — appel externe)
- [x] `TLS-REDIRECT-HTTP-TO-HTTPS` : test HTTP → 301 → HTTPS

### 6.7 Validation famille

- [ ] Tests d'intégration contre badssl.com (suite complète)
- [ ] Tests d'intégration contre `cloudflare.com`, `github.com`, `mozilla.org` (références A+)
- [ ] **🎯 Milestone 2 : famille TLS complète passe sur badssl.com**

## Phase 7 — Famille Headers HTTP

- [x] `internal/scanner/headers/fetcher.go` : GET homepage avec User-Agent identifiable
- [x] `internal/scanner/headers/csp.go` : parser CSP + checks
  - [x] `HEADER-CSP-MISSING`, `*-UNSAFE-INLINE`, `*-UNSAFE-EVAL`
  - [x] `HEADER-CSP-WILDCARD-SRC`, `*-NO-OBJECT-SRC`, `*-NO-BASE-URI`, `*-NO-FRAME-ANCESTORS`
  - [x] Logique inspirée de `google/csp-evaluator` (réimplémentation pragmatique : effective() avec fallback default-src)
- [x] X-Content-Type-Options (`HEADER-XCTO-MISSING`)
- [x] X-Frame-Options (`HEADER-XFO-MISSING`) — passe automatiquement si CSP `frame-ancestors` est posé
- [x] Referrer-Policy (`HEADER-REFERRER-POLICY-MISSING`, `*-UNSAFE`)
- [x] Permissions-Policy (`HEADER-PERMISSIONS-POLICY-MISSING`)
- [x] Feature-Policy déprécié (`HEADER-FEATURE-POLICY-DEPRECATED`)
- [x] COOP/COEP/CORP (`HEADER-COOP-MISSING`, `*-COEP-MISSING`, `*-CORP-MISSING`)
- [x] Reporting-Endpoints / Report-To (`HEADER-REPORTING-ENDPOINTS-NONE`)
- [x] NEL (`HEADER-NEL-NONE`)
- [x] Headers obsolètes : X-XSS-Protection, HPKP, Expect-CT
- [x] Info disclosure : Server, X-Powered-By, X-AspNet-Version, X-Generator, Server-Timing
- [x] Tests unitaires sur fixtures HTTP
- [x] Tests d'intégration sur securityheaders.com test sites — fait via fixtures httptest + smoke test contre github.com / cloudflare.com / mozilla.org

## Phase 8 — Famille Cookies

- [x] `internal/scanner/cookies/analyzer.go` : parsing `Set-Cookie` (multi-headers) — réutilise le fetch homepage de la famille headers
- [x] Détection heuristique cookie de session (substring + liste de noms connus)
- [x] `COOKIE-SECURE-MISSING`, `*-HTTPONLY-MISSING-SESSION`
- [x] `COOKIE-SAMESITE-MISSING`, `*-SAMESITE-NONE-WITHOUT-SECURE`
- [x] `COOKIE-NO-SECURITY-FLAGS`
- [x] `COOKIE-PREFIX-SECURE-MISSING`, `*-PREFIX-HOST-MISSING`
- [x] Tests unitaires sur fixtures de Set-Cookie

## Phase 9 — Famille DNS

- [x] `internal/scanner/dns/resolver.go` : helper `miekg/dns` avec retry léger + upgrade UDP→TCP sur troncature
- [x] DNSSEC chain validation (`DNS-DNSSEC-MISSING`, `*-WEAK-ALGO`, `*-BROKEN` via AD bit du resolver validating)
- [x] CAA records (`DNS-CAA-MISSING`, `*-NO-IODEF`)
- [x] AAAA / IPv6 (`DNS-AAAA-MISSING`)
- [x] Wildcard detection (`DNS-WILDCARD-DETECTED`)
- [x] Dangling CNAME / takeover (`DNS-DANGLING-CNAME`)
  - [x] Liste de signatures hardcodée (S3, Heroku, GitHub Pages, Vercel, Netlify, Azure, Fastly, Shopify, Tumblr, Zendesk)
  - [x] Source d'inspiration : `EdOverflow/can-i-take-over-xyz`
- [x] Nameserver diversity (`DNS-NS-DIVERSITY-LOW`)
- [x] TTL aberrants (`DNS-TTL-ABERRANT`)
- [x] Tests unitaires (mock DNS server in-process via miekg/dns)
- [x] Tests d'intégration contre `dnssec-failed.org`, `internetsociety.org` — fait via fixtures mock + smoke contre cloudflare.com (signé) / github.com (non signé)

## Phase 10 — Famille Email (gated MX)

- [x] ~~`internal/scanner/email/mx.go`~~ → fold into `fetcher.go` : récupération MX, gating de toute la famille via `gateOnMX()`
- [x] **SPF** (`internal/scanner/email/spf.go`)
  - [x] Parsing RFC 7208
  - [x] `EMAIL-SPF-MISSING`, `*-MULTIPLE-RECORDS`, `*-INVALID-SYNTAX`
  - [ ] `EMAIL-SPF-TOO-MANY-LOOKUPS` (différé — nécessite un compteur récursif d'includes)
  - [x] `EMAIL-SPF-NO-ALL-MECHANISM`, `*-PASS-ALL`, `*-SOFTFAIL-ALL`, `*-PTR-MECHANISM`
- [x] **DKIM** (`internal/scanner/email/dkim.go`)
  - [x] Liste de ~25 sélecteurs courants en parallèle
  - [x] `EMAIL-DKIM-NONE-FOUND`, `*-WEAK-KEY`, `*-SHA1`, `*-TEST-MODE`
- [x] **DMARC** (`internal/scanner/email/dmarc.go`)
  - [x] `EMAIL-DMARC-MISSING`, `*-INVALID-SYNTAX`, `*-POLICY-NONE`, `*-POLICY-WEAK`
  - [x] `EMAIL-DMARC-NO-RUA` ; `*-MISALIGNED-SPF`/`*-MISALIGNED-DKIM` différés (besoin d'un mail de test réel)
- [x] **MTA-STS** (`internal/scanner/email/mtasts.go`)
  - [x] Record TXT `_mta-sts.X` + fetch HTTPS `/.well-known/mta-sts.txt`
  - [x] `EMAIL-MTASTS-MISSING`, `*-MODE-TESTING`, `*-MAX-AGE-LOW` ; `*-MX-MISMATCH` différé
- [x] **TLS-RPT** (`EMAIL-TLSRPT-MISSING`)
- [ ] **STARTTLS** sur port 25 (`EMAIL-STARTTLS-FAIL`, `*-WEAK-TLS`) — différé (sonde active port 25 souvent bloquée)
- [ ] **DANE/TLSA** (`EMAIL-DANE-MISSING`, `*-INVALID-PARAMS`, `*-MISMATCH`) — différé (dépend du STARTTLS probe)
- [x] **BIMI** (`EMAIL-BIMI-MISSING`) ; `*-INVALID-SVG` différé
- [x] Tests d'intégration sur domaines de référence (mock fixtures + smoke contre google.com, protonmail.com, microsoft.com)

## Phase 11 — Famille Web / Custom

- [x] HTTP→HTTPS redirect (déjà couvert par `TLS-REDIRECT-HTTP-TO-HTTPS` en Phase 6)
- [x] HTTP/2 / HTTP/3 detection (`HTTP-HTTP2-MISSING` via `resp.ProtoMajor`, `*-HTTP3-MISSING` via `Alt-Svc`)
- [x] Mixed content (parsing HTML homepage avec `golang.org/x/net/html`) → `HTTP-MIXED-CONTENT`
- [x] OPTIONS / TRACE
  - [x] `HTTP-OPTIONS-DANGEROUS-METHODS`
  - [x] `HTTP-TRACE-ENABLED`
- [x] CORS misconfiguration (request avec `Origin: https://websec101-test.invalid`)
  - [x] `HTTP-CORS-WILDCARD-CREDENTIALS`
  - [x] `HTTP-CORS-ORIGIN-REFLECTED`
  - [x] `HTTP-CORS-NULL-ORIGIN`
- [x] 404 probe (single GET vers path random)
  - [x] `HTTP-404-STACK-TRACE`
  - [x] `HTTP-404-DEFAULT-ERROR-PAGE`
- [x] Compression (`HTTP-COMPRESSION-NONE`)
- [x] robots.txt validity (`ROBOTS-TXT-INVALID`)
- [x] /.well-known/change-password RFC 8615 (`WELLKNOWN-CHANGE-PASSWORD-MISSING`)
- [x] SRI sur ressources externes (`SRI-EXTERNAL-RESOURCE-NO-INTEGRITY`)
- [ ] **Fichiers sensibles exposés** (`internal/scanner/exposures/`)
  - [ ] Liste des ~40 paths du §3.7
  - [ ] Probe HEAD puis GET partiel sur confirmation
  - [ ] Heuristique upgrade `high` → `critical` sur détection de pattern de secret (AWS keys, JWT, etc.)
  - [ ] `EXPOSURE-DOTGIT-CONFIG`, `EXPOSURE-DOTENV`, etc.

## Phase 12 — Engine de rapport

- [x] `internal/report/grade.go` : algorithme de scoring §6.3 (penalties — bonuses différés)
- [x] ~~`internal/report/score_per_family.go`~~ → fold into `grade.go` : scores par famille pondérés
- [x] Quick wins detector (`severity ≥ medium && status == fail|warn` — `effort` non encore présent dans `Finding`)
- [x] `internal/report/markdown.go` : export Markdown conforme §6.5
- [x] `internal/report/sarif.go` : export SARIF 2.1.0 conforme §6.6
- [x] Tests unitaires sur fixtures de rapports (7 cas)
- [ ] Test SARIF : valider contre schema OASIS officiel — différé (besoin d'un validator JSON Schema en CI)
- [x] Implémenter `GET /scans/{guid}/markdown` et `*/sarif`
- [x] **🎯 Milestone 3 : un scan complet produit JSON + Markdown + SARIF cohérents**

## Phase 13 — Sécurité opérationnelle

- [ ] `internal/scanner/safety/ssrf.go` : refus IPs privées (IPv4/IPv6)
- [ ] `internal/scanner/safety/blocklist.go` : domain blocklist (.gov/.mil/etc.)
- [ ] Réponses 422 / 451 typées avec messages clairs
- [ ] `internal/ratelimit/ip.go` : rate limit par IP via `tollbooth`
- [ ] `internal/ratelimit/target.go` : cooldown 5 min par hostname (toutes IPs)
- [ ] Cache 24 h des rapports précédents avec param `refresh=true`
- [ ] Détection pattern d'abus (>5 cibles distinctes / <5 min → captcha forcé)
- [ ] Audit log immutable (rotation 7 j, IPs anonymisées, target hashé)
- [ ] Configuration `security:` dans config.yaml
- [ ] Tests unitaires SSRF + blocklist (CIDR matching exhaustif)

## Phase 14 — Frontend Astro

- [ ] `web/` init Astro 5 + Tailwind + Alpine
- [ ] `web/astro.config.mjs` : output static, base path
- [ ] Layout principal + theme
- [ ] Page d'accueil `/` avec formulaire de scan + Turnstile
- [ ] Page `/scan/{guid}` lecture seule
  - [ ] Mode SSE pendant le scan (Alpine island)
  - [ ] Vue statique du rapport quand completed
- [ ] Page `/about` (description scanner, User-Agent, opt-out)
- [ ] Page `/checks` (catalogue interactif, filtrage par famille/sévérité)
- [ ] Page `/checks/{id}` (détail check, snippets par stack avec onglets)
- [ ] Page `/docs/api` (Scalar UI ou Swagger UI sur openapi.json)
- [ ] Pages `/legal/{tos,privacy}`
- [ ] Build → `web/dist/`
- [ ] `internal/webfs/embed.go` : `//go:embed all:dist` + handler statique
- [ ] Mode dégradé : route Go `/scan/{guid}.html` rendu via `html/template`
- [ ] Audit accessibilité (WCAG 2.1 AA, contraste, navigation clavier)

## Phase 15 — CLI

- [x] `cmd/websec101-cli/main.go` : entry point cobra
- [x] Commande `scan [target]`
  - [x] Mode online (appel API distante)
  - [x] Mode `--standalone` (scan in-process sans serveur)
  - [x] Output formats : `--json`, `--markdown`, `--sarif`
  - [x] `--fail-on critical,high` (codes de sortie pour CI/CD)
  - [ ] Barre de progression (différé — mode synchrone via `wait_seconds` suffit pour CI)
- [x] Commande `report [guid]` (re-rendu d'un scan stocké)
- [x] Commande `catalog` (dump des checks supportés)
- [x] Commande `version`
- [x] `--server`, `--api-key` (env `WEBSEC101_API_KEY`)
- [x] Tests E2E CLI sur cible badssl.com (smoke `expired.badssl.com --fail-on critical` → exit 2)

## Phase 16 — Distribution

- [ ] `deploy/docker/Dockerfile` : multi-stage avec `gcr.io/distroless/static-debian12:nonroot`
- [ ] `deploy/docker/docker-compose.yml` : template auto-hébergement
- [ ] `.goreleaser.yaml`
  - [ ] Cross-compilation Linux/macOS/Windows × amd64/arm64
  - [ ] Strip symboles `-s -w`
  - [ ] Archives tar.gz / zip
  - [ ] **Cosign v3 keyless OIDC** (vérifier breaking change `--bundle`)
  - [ ] **Syft SBOM SPDX**
  - [ ] **SLSA Level 3 provenance**
  - [ ] Push image GHCR multi-arch
  - [ ] Mise à jour Homebrew tap
  - [ ] CHANGELOG auto depuis Conventional Commits
- [ ] Repo séparé `your-org/homebrew-tap` (formula auto-générée)
- [ ] `scripts/install.sh` (one-liner avec vérification cosign + SHA256)
- [ ] Documenter installation manuelle alternative dans `docs/self-hosting.md`

## Phase 17 — CI/CD complet

- [ ] `.github/workflows/release.yml` (déclenchée sur tag `v*`)
  - [ ] Lance goreleaser
  - [ ] Permissions OIDC (id-token: write)
  - [ ] Vérifie l'image Docker post-push
- [ ] Branch protection : require `ci.yml`, `verify-codegen.yml` checks
- [ ] Test du release flow sur tag pré-release `v0.0.1-rc1` (release brouillon)

## Phase 18 — Documentation

- [ ] `README.md` complet (intro, install, quickstart, démo, badges, lien specs)
- [ ] `docs/architecture.md` (synthèse §2)
- [ ] `docs/api/` (générée depuis OpenAPI ou liens Scalar/Redoc)
- [ ] `docs/self-hosting.md` (Docker, docker-compose, binaire, env vars, reverse proxy)
- [ ] `docs/checks/` (un fichier .md par check, généré depuis le catalog)
- [ ] Script de génération `scripts/gen-checks-docs.sh`
- [ ] `docs/ai-agents.md` (guide d'intégration agent IA, exemples Claude/Codex/Cursor)
- [ ] `docs/contributing/checks.md` (comment ajouter un nouveau check)
- [ ] Captures d'écran / GIFs dans le README

## Phase 19 — SKILL.md pour agents IA

- [ ] `skills/websec101/SKILL.md` (frontmatter + workflow + exemples §10.2)
- [ ] `skills/websec101/scripts/scan.sh` (wrapper curl ou CLI)
- [ ] `skills/websec101/scripts/apply_remediation.sh` (snippet picker pour stack donné)
- [ ] `skills/websec101/references/api.md` (référence API complète)
- [ ] `skills/websec101/references/checks.md` (généré depuis `GET /api/v1/checks`)
- [ ] `skills/websec101/references/stacks.md` (mapping stack → conventions snippet)
- [ ] `skills/websec101/references/safety.md` (règles éthiques étendues)
- [ ] Test du skill avec Claude Code et avec Cursor
- [ ] PR vers `anthropics/skills` pour visibilité (optionnel)

## Phase 20 — Légal

- [ ] `docs/legal/tos.md` (conforme §14.3, 10 sections)
- [ ] `docs/legal/privacy.md` (conforme §14.4, RGPD-compatible)
- [ ] `docs/legal/abuse-policy.md` (conforme §14.5)
- [ ] Disclaimer §14.6 dans le footer du frontend et de tous les rapports Markdown/HTML
- [ ] Définir adresses `abuse@`, `security@`, `privacy@` (à instancier au déploiement)
- [ ] Page `/legal/tos` et `/legal/privacy` linkées depuis le footer

## Phase 21 — Tests d'intégration et qualité

- [ ] Test suite end-to-end contre badssl.com (toutes les variantes)
- [ ] Tests E2E contre cibles de référence (mozilla.org, github.com, cloudflare.com → A+)
- [ ] Tests E2E contre cibles « legacy » connues (à identifier sans nuire, ou container fixture local)
- [ ] Test fixtures dockerisées : nginx 1.18 mal configuré, Apache vulnérable, etc.
- [ ] Couverture de tests Go ≥ 70 % sur `internal/`
- [ ] Tests `go test -race` propres
- [ ] Bench critiques (`internal/scanner/tls/probes`, parsing CSP, parsing SPF)
- [ ] Audit `gosec` : zéro `HIGH`
- [ ] Audit dépendances : `govulncheck`, `osv-scanner`
- [ ] Audit licences (`go-licenses` : pas de GPL/AGPL en deps)

## Phase 22 — Pré-release 0.1.0

- [ ] Walkthrough manuel du SPECIFICATIONS.md : tout ce qui est marqué MVP est implémenté ou explicitement reporté
- [ ] Walkthrough sécurité (anti-SSRF, blocklist, rate-limit, anonymisation IPs)
- [ ] Walkthrough légal (ToS / Privacy / Abuse en place)
- [ ] OSSF Scorecard score ≥ 7
- [ ] CHANGELOG.md à jour avec la section 0.1.0
- [ ] Annonce préparée (HN / lobste.rs / r/netsec / Mastodon / Twitter)
- [ ] Démo en ligne sur `websec101.example` (instance publique)
- [ ] Tag `v0.1.0` poussé → release goreleaser
- [ ] Vérification post-release : binaires téléchargeables, image Docker pull, Homebrew formula, install.sh fonctionne
- [ ] **🎯 Milestone final : release 0.1.0 publique**

## Backlog (post-0.1.0, hors scope MVP)

- [ ] Tech detection riche (Fingerprinter sidecar Chromium ou wappalyzergo pure Go)
- [ ] Scan de ports actif (22, 25, 80, 443, 3306, 5432, 6379, 8080, 27017)
- [ ] Open redirects par fuzzing de paramètres
- [ ] Clear-Site-Data sur logout (nécessite crawl auth léger)
- [ ] HTTP/3 handshake complet via `quic-go`
- [ ] DROWN, ROBOT, Ticketbleed, Lucky13, RACCOON actifs
- [ ] Readiness post-quantique (X25519MLKEM768)
- [ ] MCP server `websec101-mcp`
- [ ] OAuth/OIDC + multi-tenancy + comptes utilisateurs
- [ ] GitHub Action officielle, GitLab CI template, Jenkins plugin
- [ ] Helm chart Kubernetes
- [ ] Plugins WebSec101 (framework de checks tiers)
- [ ] Corrélation stack détectée ↔ CVE actives (OSV/NVD)
- [ ] Mode authenticated scan
- [ ] Scoring contextuel (e-commerce vs blog vs app interne)
- [ ] Dashboard d'observabilité métier (Grafana template)
