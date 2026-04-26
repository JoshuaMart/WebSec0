# WebSec101 — Specifications

> **Statut** : Spécification de référence pour la version 0.1.0 (MVP).
> **Licence** : MIT.
> **Stack** : Go (backend) + Astro/Alpine (frontend) + monorepo.
> **Auto-hébergement** : single binary + Docker distroless multi-arch.
> **Dernière révision** : 2026-04-25.

## 1. Vision et périmètre

### 1.1 Objectif

WebSec101 est un scanner de configuration de sécurité web open-source qui combine, dans un seul outil léger et auto-hébergeable, la couverture qu'offrent séparément SSL Labs (TLS), Hardenize (TLS+DNS+email+headers), securityheaders.com (headers HTTP) et internet.nl (compliance), enrichie de checks customs (security.txt, fichiers sensibles exposés, CORS misconfig, etc.). Il produit un rapport orienté **« quick wins »** — c'est-à-dire priorisé par ROI sécurité/effort plutôt qu'exhaustif — accompagné de **snippets de remédiation copy-paste-ready par stack** (Nginx, Apache, Caddy, HAProxy, Cloudflare, Express, Fastify, Spring Security, IIS).

### 1.2 Audience

Deux audiences de premier rang, traitées à parité dès la conception :

1. **Humains** (développeurs, sysadmins, RSSI, devs solo) qui veulent un rapport clair, actionnable, sans jargon inutile.
2. **Agents IA** (Claude, ChatGPT, Codex, Cursor, etc.) qui consomment l'API ou le rapport Markdown pour proposer ou appliquer des remédiations. Tous les findings sont auto-suffisants : un agent peut produire une réponse correcte sans re-fetcher de pages externes.

### 1.3 Périmètre passif strict

WebSec101 reste un **scanner de configuration passif**. Cette discipline de scope est non-négociable pour le MVP : elle simplifie radicalement les aspects légaux, l'ergonomie produit, et les dépendances opérationnelles.

**Sont autorisés au MVP** :

- TLS handshakes (modernes via stdlib, legacy via zcrypto, SSLv2/SSLv3 via raw probes maison) sur le port 443 (et 25/465/587 pour STARTTLS email)
- Requêtes HTTP `GET` / `OPTIONS` / `TRACE` sur la homepage
- Une requête HTTP supplémentaire vers un path random pour le 404 probe
- Probes single-shot vers `/.well-known/security.txt`, `/robots.txt`, `/.well-known/*`, et la liste fermée d'environ 40 fichiers sensibles
- Une requête CORS avec `Origin` factice
- Lookups DNS publics (A/AAAA/MX/TXT/CAA/TLSA/DNSSEC chain)
- Fetch HTTPS de `/.well-known/mta-sts.txt` si MTA-STS est annoncé en TXT
- Fetch HTTPS du logo BIMI si BIMI annoncé

Total ≤ **~50 requêtes HTTP par scan**, étalées dans le temps (cf. §11.3).

**Sont hors périmètre du MVP** (cf. §15 pour la roadmap V2) :

- Crawling profond, suivi de liens, parsing JS/SPA dynamique
- Fuzzing de paramètres (open redirects, IDOR, etc.)
- Auth flows, login, parcours utilisateur
- Scan de ports TCP arbitraires (uniquement 443/25/465/587 au MVP)
- Tests actifs de vulnérabilités CVE génériques façon Nuclei
- Rendering de page via Chromium headless (donc tech detection avancée à la Wappalyzer/Fingerprinter)
- DAST (proxy intercepteur, injection, XSS scanner)

### 1.4 Différenciateurs

WebSec101 ne cherche pas à inventer la roue. Le créneau est qu'aucun outil OSS ne combine **simultanément** :

1. **Couverture multi-domaines** (TLS + Headers + Cookies + DNS + Email + Custom)
2. **Snippets de remédiation indexés par stack** (le différenciateur produit principal)
3. **Format agent-IA-first** : `description.long` self-suffisant, catalogue exposé via `GET /api/v1/checks`, export Markdown propre, SKILL.md livré
4. **Export SARIF 2.1.0** pour intégration GitHub Code Scanning et CI/CD
5. **Auto-hébergement trivial** : single binary statique, Docker distroless ≤ 15 Mo, MIT
6. **Privacy by design** : aucun log de domaine scanné, GUIDv4 pour les rapports, mode `private` avec token

## 2. Architecture générale

### 2.1 Vue d'ensemble

```
                   ┌─────────────────────────────────────────────┐
                   │              websec101 (single binary)      │
                   │                                             │
  ┌──────────┐     │  ┌─────────────┐  ┌─────────────────────┐   │
  │ CLI      │────▶│  │ HTTP API    │  │ Frontend (embedded  │   │
  │ (cobra)  │     │  │ (chi/stdlib)│  │  Astro static dist) │   │
  └──────────┘     │  └──────┬──────┘  └──────┬──────────────┘   │
                   │         │                │                   │
  ┌──────────┐     │         ▼                ▼                   │
  │ Agent IA │────▶│  ┌──────────────────────────────────┐        │
  │ + SKILL  │     │  │      Scan orchestrator           │        │
  └──────────┘     │  │   (semaphore + errgroup)         │        │
                   │  └──────────────┬───────────────────┘        │
                   │                 │                            │
                   │   ┌─────────────┼──────────────────────┐     │
                   │   ▼             ▼                      ▼     │
                   │ ┌────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐  │
                   │ │TLS │ │Hdrs  │ │ DNS  │ │Email │ │Custom│  │
                   │ └────┘ └──────┘ └──────┘ └──────┘ └──────┘  │
                   │                                              │
                   │   ┌──────────────────────────────────┐      │
                   │   │  ScanStore (in-memory / Redis)   │      │
                   │   │  TTL 24h, GUIDv4 keys             │      │
                   │   └──────────────────────────────────┘      │
                   └─────────────────────────────────────────────┘
```

Un seul artefact à déployer. Pas de Redis externe au MVP. Pas de base de données. Pas de Chromium. Pas de Postfix. Le frontend statique est embarqué via `go:embed all:dist`.

### 2.2 Layout monorepo

Pas de Nx, Turborepo ou Bazel — overkill pour un projet Go avec un petit frontend statique. Layout Go standard, conforme aux pratiques de Caddy, Grafana k6, Gitea, ProjectDiscovery.

```
websec101/
├── api/
│   └── openapi.yaml                  # source de vérité pour l'API
├── cmd/
│   ├── websec101/                    # binaire serveur (HTTP API + frontend)
│   │   └── main.go
│   └── websec101-cli/                # binaire CLI standalone
│       └── main.go
├── internal/
│   ├── api/
│   │   ├── oas/                      # code généré par ogen
│   │   ├── handlers/                 # implémentation des handlers
│   │   ├── middleware/               # auth, rate-limit, request-id, recover
│   │   └── sse/                      # Server-Sent Events
│   ├── checks/
│   │   ├── registry.go               # registre central des checks
│   │   └── catalog.go                # alimente GET /api/v1/checks
│   ├── scanner/
│   │   ├── tls/
│   │   │   ├── modern.go             # stdlib crypto/tls (TLS 1.2/1.3)
│   │   │   ├── legacy.go             # zcrypto (TLS 1.0/1.1)
│   │   │   ├── probes/               # raw probes SSLv2/SSLv3
│   │   │   └── heartbleed.go         # zgrab2 wrapper
│   │   ├── headers/
│   │   ├── cookies/
│   │   ├── dns/
│   │   ├── email/
│   │   ├── wellknown/
│   │   ├── exposures/                # ~40 fichiers sensibles
│   │   └── http/                     # CORS, OPTIONS/TRACE, 404 probe, mixed content
│   ├── report/
│   │   ├── grade.go                  # scoring lettre + 0-100
│   │   ├── markdown.go               # export Markdown
│   │   └── sarif.go                  # export SARIF 2.1.0
│   ├── storage/
│   │   ├── store.go                  # interface ScanStore
│   │   ├── memory/                   # patrickmn/go-cache
│   │   ├── ristretto/                # haute concurrence
│   │   └── redis/                    # multi-replica (optionnel)
│   ├── ratelimit/
│   ├── config/                       # koanf
│   ├── version/
│   └── webfs/                        # go:embed du frontend
├── pkg/
│   └── client/                       # client Go généré par ogen, importable
├── web/                              # frontend Astro
│   ├── src/
│   ├── public/
│   ├── astro.config.mjs
│   ├── tailwind.config.js
│   └── package.json
├── deploy/
│   ├── docker/
│   │   └── Dockerfile                # distroless multi-stage
│   └── helm/                         # chart Kubernetes (V2)
├── docs/
│   ├── api/
│   ├── architecture.md
│   ├── checks/                       # un .md par check, généré
│   ├── self-hosting.md
│   ├── ai-agents.md                  # comment intégrer un agent IA
│   └── legal/
│       ├── tos.md
│       ├── privacy.md
│       └── abuse-policy.md
├── skills/
│   └── websec101/
│       ├── SKILL.md
│       ├── scripts/
│       └── references/
├── scripts/
│   ├── install.sh                    # one-liner d'installation
│   └── dev.sh
├── .github/
│   ├── workflows/
│   │   ├── ci.yml
│   │   ├── release.yml
│   │   ├── codeql.yml
│   │   └── dependabot.yml
│   └── ISSUE_TEMPLATE/
├── .goreleaser.yaml
├── Makefile
├── go.mod
├── go.sum
├── LICENSE                           # MIT
├── README.md
├── SECURITY.md
├── CODE_OF_CONDUCT.md
├── CONTRIBUTING.md
└── SPECIFICATIONS.md                 # ce document
```

## 3. Catalogue des checks

### 3.1 Système de finding

Chaque check produit un *finding* qui suit le schéma suivant. Tout finding possède un identifiant stable, machine-readable, qui ne change jamais après publication.

**Conventions sur l'`id`** : `{FAMILY}-{SUBCATEGORY}-{CHECK}` en SCREAMING-KEBAB-CASE. Exemples :
- `TLS-PROTOCOL-LEGACY-SSL3`
- `TLS-CERT-EXPIRED`
- `HEADER-CSP-MISSING`
- `HEADER-CSP-UNSAFE-INLINE`
- `COOKIE-SECURE-MISSING`
- `DNS-DNSSEC-MISSING`
- `EMAIL-SPF-MISSING`
- `EMAIL-DMARC-WEAK-POLICY`
- `WELLKNOWN-SECURITY-TXT-MISSING`
- `EXPOSURE-DOTGIT-CONFIG`

**Sévérités** (5 niveaux, alignés GitHub Code Scanning et CVSS) :

| Sévérité   | Définition                                                              | Couleur UI |
|------------|-------------------------------------------------------------------------|------------|
| `critical` | Exploitation triviale, impact direct sur confidentialité ou intégrité   | rouge      |
| `high`     | Exploitation possible avec effort modéré, impact significatif           | orange     |
| `medium`   | Affaiblissement défense en profondeur, exploitation conditionnelle      | jaune      |
| `low`      | Bonne pratique non respectée, exposition d'information mineure          | bleu       |
| `info`     | Informationnel, pas d'impact direct (ex : version IPv6 absente)         | gris       |

**Statuts** d'un check après exécution : `pass` / `fail` / `warn` / `skipped` / `error`.

### 3.2 Famille TLS

| ID                                  | Sévérité  | Notes                                                         |
|-------------------------------------|-----------|---------------------------------------------------------------|
| `TLS-PROTOCOL-LEGACY-SSL2`          | critical  | Probe raw socket, accepted = critical                         |
| `TLS-PROTOCOL-LEGACY-SSL3`          | critical  | Probe raw socket, accepted = critical (POODLE)                |
| `TLS-PROTOCOL-LEGACY-TLS10`         | high      | zcrypto handshake, accepted = high (BEAST)                    |
| `TLS-PROTOCOL-LEGACY-TLS11`         | high      | zcrypto handshake                                             |
| `TLS-PROTOCOL-TLS12-MISSING`        | medium    | Devrait être présent en parallèle de TLS 1.3                  |
| `TLS-PROTOCOL-TLS13-MISSING`        | low       | Recommandé, bonus si présent                                  |
| `TLS-CIPHER-NULL`                   | critical  | NULL ciphers acceptés                                         |
| `TLS-CIPHER-EXPORT`                 | critical  | EXPORT ciphers acceptés (FREAK)                               |
| `TLS-CIPHER-RC4`                    | high      | RC4 accepté                                                   |
| `TLS-CIPHER-DES`                    | high      | DES accepté                                                   |
| `TLS-CIPHER-3DES`                   | medium    | 3DES accepté (Sweet32)                                        |
| `TLS-CIPHER-CBC-TLS10`              | medium    | CBC ciphers en TLS 1.0 (BEAST)                                |
| `TLS-CIPHER-NO-FORWARD-SECRECY`     | medium    | Aucun cipher ECDHE/DHE                                        |
| `TLS-CIPHER-DH-WEAK`                | high      | DH parameter < 2048 bits (Logjam)                             |
| `TLS-VULN-HEARTBLEED`               | critical  | zgrab2 active probe                                           |
| `TLS-CERT-EXPIRED`                  | critical  | Certificat expiré                                             |
| `TLS-CERT-EXPIRES-SOON-14D`         | high      | Expire dans < 14 jours                                        |
| `TLS-CERT-EXPIRES-SOON-30D`         | medium    | Expire dans < 30 jours                                        |
| `TLS-CERT-CHAIN-INCOMPLETE`         | high      | Chaîne d'intermédiaires manquante                             |
| `TLS-CERT-NAME-MISMATCH`            | critical  | SAN ne correspond pas à l'hôte                                |
| `TLS-CERT-SELF-SIGNED`              | high      | Auto-signé (sauf si site interne déclaré)                     |
| `TLS-CERT-WEAK-RSA`                 | high      | RSA < 2048 bits                                               |
| `TLS-CERT-WEAK-ECC`                 | high      | ECC < 256 bits                                                |
| `TLS-CERT-WEAK-SIGNATURE`           | high      | Signature MD5 ou SHA1                                         |
| `TLS-CERT-NO-CT`                    | low       | Pas de SCT dans CT logs                                       |
| `TLS-OCSP-STAPLING-MISSING`         | low       | OCSP stapling non activé                                      |
| `TLS-HSTS-MISSING`                  | high      | Pas d'header `Strict-Transport-Security`                      |
| `TLS-HSTS-MAX-AGE-LOW`              | medium    | `max-age` < 1 an (31536000)                                   |
| `TLS-HSTS-NO-INCLUDESUBDOMAINS`     | low       | Recommandé pour usage défensif                                |
| `TLS-HSTS-NO-PRELOAD`               | info      | Bonus si `preload` + inscription hstspreload.org              |
| `TLS-ALPN-NO-HTTP2`                 | info      | Pas de h2 advertisement                                       |
| `TLS-REDIRECT-HTTP-TO-HTTPS`        | high      | HTTP doit rediriger en 301 vers HTTPS                         |

### 3.3 Famille Headers HTTP

| ID                                  | Sévérité  | Notes                                                         |
|-------------------------------------|-----------|---------------------------------------------------------------|
| `HEADER-CSP-MISSING`                | high      | Pas de Content-Security-Policy                                |
| `HEADER-CSP-UNSAFE-INLINE`          | medium    | `script-src` contient `'unsafe-inline'`                       |
| `HEADER-CSP-UNSAFE-EVAL`            | medium    | `script-src` contient `'unsafe-eval'`                         |
| `HEADER-CSP-WILDCARD-SRC`           | medium    | Wildcard sans `'strict-dynamic'`                              |
| `HEADER-CSP-NO-OBJECT-SRC`          | low       | `object-src 'none'` recommandé                                |
| `HEADER-CSP-NO-BASE-URI`            | low       | `base-uri` recommandé                                         |
| `HEADER-CSP-NO-FRAME-ANCESTORS`     | low       | `frame-ancestors` recommandé                                  |
| `HEADER-XCTO-MISSING`               | medium    | `X-Content-Type-Options: nosniff` absent                      |
| `HEADER-XFO-MISSING`                | medium    | `X-Frame-Options` ou `frame-ancestors` absent                 |
| `HEADER-REFERRER-POLICY-MISSING`    | low       | Recommander `strict-origin-when-cross-origin`                 |
| `HEADER-REFERRER-POLICY-UNSAFE`     | medium    | `unsafe-url` ou `no-referrer-when-downgrade`                  |
| `HEADER-PERMISSIONS-POLICY-MISSING` | low       |                                                               |
| `HEADER-FEATURE-POLICY-DEPRECATED`  | info      | Migrer vers Permissions-Policy                                |
| `HEADER-COOP-MISSING`               | low       | `Cross-Origin-Opener-Policy: same-origin` recommandé          |
| `HEADER-COEP-MISSING`               | info      | `require-corp`/`credentialless` requis pour isolation forte   |
| `HEADER-CORP-MISSING`               | info      | Sur ressources servies cross-origin                           |
| `HEADER-REPORTING-ENDPOINTS-NONE`   | info      | Recommandation rapport CSP                                    |
| `HEADER-NEL-NONE`                   | info      | Network Error Logging (optionnel)                             |
| `HEADER-XXSS-DEPRECATED`            | info      | `X-XSS-Protection` est obsolète et nuisible                   |
| `HEADER-HPKP-DEPRECATED`            | info      | `Public-Key-Pins` obsolète                                    |
| `HEADER-EXPECT-CT-DEPRECATED`       | info      | Obsolète depuis 2024                                          |
| `HEADER-SERVER-DISCLOSURE`          | low       | `Server: nginx/1.18.0` divulgue la version                    |
| `HEADER-X-POWERED-BY-DISCLOSURE`    | low       | `X-Powered-By: PHP/8.0.1` divulgue la stack                   |
| `HEADER-X-ASPNET-VERSION-DISCLOSURE`| low       |                                                               |
| `HEADER-X-GENERATOR-DISCLOSURE`     | low       | Souvent CMS                                                   |
| `HEADER-SERVER-TIMING-DISCLOSURE`   | info      | Présence d'info implémentation                                |

### 3.4 Famille Cookies

Tous les cookies présents en réponse de la homepage sont analysés.

| ID                                  | Sévérité  |
|-------------------------------------|-----------|
| `COOKIE-SECURE-MISSING`             | high      |
| `COOKIE-HTTPONLY-MISSING-SESSION`   | high      |
| `COOKIE-SAMESITE-MISSING`           | medium    |
| `COOKIE-SAMESITE-NONE-WITHOUT-SECURE`| high     |
| `COOKIE-NO-SECURITY-FLAGS`          | high      |
| `COOKIE-PREFIX-SECURE-MISSING`      | info      | bonus si `__Secure-` |
| `COOKIE-PREFIX-HOST-MISSING`        | info      | bonus si `__Host-`   |

Détection « cookie de session » : nom contenant `session`, `sess`, `sid`, `auth`, `token`, `jwt`, ou flag heuristique sur la longueur/randomité de la valeur.

### 3.5 Famille DNS

| ID                                  | Sévérité  | Notes                                                         |
|-------------------------------------|-----------|---------------------------------------------------------------|
| `DNS-DNSSEC-MISSING`                | medium    | Pas de chaîne DNSSEC validable                                |
| `DNS-DNSSEC-WEAK-ALGO`              | medium    | RSASHA1, NSEC1                                                |
| `DNS-DNSSEC-BROKEN`                 | high      | Chaîne cassée (clé invalide)                                  |
| `DNS-CAA-MISSING`                   | low       | Pas de record CAA                                             |
| `DNS-CAA-NO-IODEF`                  | info      | Pas de `iodef` pour reporting                                 |
| `DNS-AAAA-MISSING`                  | info      | IPv6 absent (informatif, pas pénalité)                        |
| `DNS-WILDCARD-DETECTED`             | low       | Wildcard A/AAAA peut masquer des subdomain takeovers          |
| `DNS-DANGLING-CNAME`                | high      | CNAME pointe vers ressource non-revendiquée (S3/Heroku/etc.)  |
| `DNS-NS-DIVERSITY-LOW`              | info      | < 2 NS sur réseaux différents                                 |
| `DNS-TTL-ABERRANT`                  | info      | TTL < 60s ou > 7 jours                                        |

Détection takeover (DNS-DANGLING-CNAME) : pattern matching sur signatures connues (S3 bucket inexistant, Heroku no-such-app, GitHub Pages 404, Vercel/Netlify, Azure Web Apps, Fastly, Shopify, Tumblr, Zendesk, etc.). Liste hardcodée éditable, alimentée par EdOverflow's `can-i-take-over-xyz`.

### 3.6 Famille Email (gated MX)

Tous les checks de cette famille sont conditionnés par la présence d'un record MX. Si absent, la famille est `skipped` avec note explicative.

**SPF** :

| ID                                  | Sévérité  |
|-------------------------------------|-----------|
| `EMAIL-SPF-MISSING`                 | high      |
| `EMAIL-SPF-MULTIPLE-RECORDS`        | high      |
| `EMAIL-SPF-INVALID-SYNTAX`          | high      |
| `EMAIL-SPF-TOO-MANY-LOOKUPS`        | high      | > 10 lookups DNS                                              |
| `EMAIL-SPF-NO-ALL-MECHANISM`        | medium    |
| `EMAIL-SPF-PASS-ALL`                | critical  | `+all`                                                        |
| `EMAIL-SPF-SOFTFAIL-ALL`            | medium    | `~all` (recommander `-all`)                                   |
| `EMAIL-SPF-PTR-MECHANISM`           | medium    | `ptr` est déprécié (RFC 7208)                                 |

**DKIM** : test parallèle d'environ 20 sélecteurs courants : `default`, `google`, `selector1`, `selector2`, `k1`, `k2`, `mail`, `dkim`, `s1`, `s2`, `mxvault`, `mandrill`, `sm`, `spop1024`, `everlytickey1`, `everlytickey2`, `dkim-ed25519`, `key1`, `key2`, `mta`, plus dérivés `*.amazonses.com`, `*.mailgun.org`, `*.sendgrid.net`.

| ID                                  | Sévérité  |
|-------------------------------------|-----------|
| `EMAIL-DKIM-NONE-FOUND`             | medium    |
| `EMAIL-DKIM-WEAK-KEY`               | high      | clé < 1024                                                    |
| `EMAIL-DKIM-SHA1`                   | medium    |
| `EMAIL-DKIM-TEST-MODE`              | medium    | `t=y` en production                                           |

**DMARC** :

| ID                                  | Sévérité  |
|-------------------------------------|-----------|
| `EMAIL-DMARC-MISSING`               | high      |
| `EMAIL-DMARC-INVALID-SYNTAX`        | high      |
| `EMAIL-DMARC-POLICY-NONE`           | medium    | `p=none` n'enforce rien                                       |
| `EMAIL-DMARC-POLICY-WEAK`           | low       | `p=quarantine`, recommander `reject`                          |
| `EMAIL-DMARC-NO-RUA`                | low       |
| `EMAIL-DMARC-MISALIGNED-SPF`        | medium    | `aspf=r` au lieu de `s`                                       |
| `EMAIL-DMARC-MISALIGNED-DKIM`       | medium    |

**MTA-STS / TLS-RPT / DANE / STARTTLS** :

| ID                                  | Sévérité  |
|-------------------------------------|-----------|
| `EMAIL-MTASTS-MISSING`              | medium    |
| `EMAIL-MTASTS-MODE-TESTING`         | low       | `mode: testing`, recommander `enforce`                        |
| `EMAIL-MTASTS-MAX-AGE-LOW`          | low       | < 86400                                                       |
| `EMAIL-MTASTS-MX-MISMATCH`          | high      | `mx:` ne correspond pas aux MX réels                          |
| `EMAIL-TLSRPT-MISSING`              | low       |
| `EMAIL-STARTTLS-FAIL`               | high      | Port 25 sans STARTTLS                                         |
| `EMAIL-STARTTLS-WEAK-TLS`           | medium    | TLS < 1.2 sur port 25                                         |
| `EMAIL-DANE-MISSING`                | low       | Recommandé si DNSSEC actif                                    |
| `EMAIL-DANE-INVALID-PARAMS`         | high      |
| `EMAIL-DANE-MISMATCH`               | high      |
| `EMAIL-BIMI-MISSING`                | info      | Optionnel, requiert DMARC strict                              |
| `EMAIL-BIMI-INVALID-SVG`            | low       | SVG Tiny PS non conforme                                      |

### 3.7 Famille Web / HTTP / Custom

| ID                                  | Sévérité  | Notes                                                         |
|-------------------------------------|-----------|---------------------------------------------------------------|
| `HTTP-NO-HTTPS-REDIRECT`            | high      | http:// ne redirige pas en 301 vers https://                  |
| `HTTP-HTTPS-REDIRECT-WRONG-CODE`    | low       | 302 au lieu de 301                                            |
| `HTTP-HTTP2-MISSING`                | low       |                                                               |
| `HTTP-HTTP3-MISSING`                | info      | Detection via `Alt-Svc: h3=":443"`                            |
| `HTTP-MIXED-CONTENT`                | high      | Ressources `http://` dans page HTTPS                          |
| `HTTP-OPTIONS-DANGEROUS-METHODS`    | medium    | PUT, DELETE, PATCH exposés sur la racine                      |
| `HTTP-TRACE-ENABLED`                | medium    | TRACE répond OK (XST)                                         |
| `HTTP-CORS-WILDCARD-CREDENTIALS`    | critical  | `Access-Control-Allow-Origin: *` + `Allow-Credentials: true`  |
| `HTTP-CORS-ORIGIN-REFLECTED`        | high      | Origin réfléchi sans validation                               |
| `HTTP-CORS-NULL-ORIGIN`             | high      | `Access-Control-Allow-Origin: null` accepté                   |
| `HTTP-404-STACK-TRACE`              | medium    | Stack trace dans réponse 404                                  |
| `HTTP-404-DEFAULT-ERROR-PAGE`       | low       | Page d'erreur par défaut révèle stack/version                 |
| `HTTP-COMPRESSION-NONE`             | info      | Ni Brotli ni Gzip                                             |

**security.txt et /.well-known/** :

| ID                                  | Sévérité  | Notes                                                         |
|-------------------------------------|-----------|---------------------------------------------------------------|
| `WELLKNOWN-SECURITY-TXT-MISSING`    | medium    |                                                               |
| `WELLKNOWN-SECURITY-TXT-EXPIRED`    | high      | Champ `Expires:` dépassé                                      |
| `WELLKNOWN-SECURITY-TXT-NO-CONTACT` | high      | Champ `Contact:` manquant (requis)                            |
| `WELLKNOWN-SECURITY-TXT-NO-EXPIRES` | high      | Champ `Expires:` manquant (requis depuis RFC 9116)            |
| `WELLKNOWN-SECURITY-TXT-NOT-HTTPS`  | medium    | Servi en HTTP                                                 |
| `WELLKNOWN-SECURITY-TXT-NO-SIGNATURE`| info     | Signature PGP recommandée mais non requise                    |
| `WELLKNOWN-CHANGE-PASSWORD-MISSING` | info      | RFC 8615                                                      |
| `ROBOTS-TXT-INVALID`                | info      |                                                               |
| `SRI-EXTERNAL-RESOURCE-NO-INTEGRITY`| medium    | `<script src="cdn">` sans `integrity=`                        |

**Fichiers sensibles exposés** : liste fermée d'environ 40 entrées, probes single-shot via `HEAD` puis `GET` partiel sur première confirmation. Sévérité `critical` si secret avéré (`.env*`, `wp-config.php.bak`, `.git/config`), `high` sinon. Liste indicative :

```
# Secrets et configurations
/.env  /.env.local  /.env.production  /.env.development
/.git/config  /.git/HEAD  /.git/index
/.svn/entries  /.hg/store
/wp-config.php.bak  /wp-config.php~  /wp-config.old
/web.config  /.htaccess  /.htpasswd

# Dumps et backups
/database.sql  /backup.sql  /dump.sql
/index.php.bak  /config.php.old

# Métadonnées éditeur
/.DS_Store  /.idea/  /.vscode/  /.project

# Info disclosure
/phpinfo.php  /info.php  /test.php

# API/Docs/Actuator (Spring Boot, Symfony, etc.)
/actuator  /actuator/env  /actuator/heapdump  /actuator/threaddump
/_profiler/  /_profiler/latest
/server-status  /server-info

# Manifestes/Lockfiles susceptibles d'exposer la stack
/composer.json  /composer.lock
/package.json  /package-lock.json
/Gemfile  /Gemfile.lock

# OpenAPI/Swagger
/swagger  /swagger-ui  /swagger.json  /openapi.json  /api-docs
/v2/api-docs  /v3/api-docs

# Generic backup patterns
/index.html.bak  /index.html~
```

Pour chaque hit, la heuristique de sévérité s'applique : si la réponse contient un pattern de secret (clé AWS `AKIA...`, mot de passe en clair, JWT, etc.), upgrade à `critical`.

### 3.8 Total MVP

Environ **70 checks distincts** répartis en 6 familles. C'est l'ordre de grandeur du leader historique securityheaders.com (15 checks) plus de SSL Labs (~30 critères TLS) plus de Hardenize (~25 sur DNS/email), avec la couverture custom en supplément. C'est dimensionné pour livrer la promesse « rapport actionnable » sans diluer l'expérience.

## 4. Stack technique backend

### 4.1 Choix du langage : Go

Décision tranchée. Go gagne sur Rust/Python/Node.js pour ce cas d'usage :

- Goroutines + `errgroup.SetLimit` rendent triviale la parallélisation des ~10 checks par scan et des ~50 scans concurrents par instance
- L'écosystème offensif moderne est en Go (nuclei, trivy, gitleaks, osv-scanner, syft, projectdiscovery suite) — vivier de contributeurs et libs riches
- Binaire statique unique (`CGO_ENABLED=0`) = distribution triviale
- `crypto/tls` stdlib couvre TLS 1.2/1.3 modernes correctement, le manque sur les anciens protocoles est comblé par zcrypto (TLS 1.0/1.1) et par des probes maison (SSLv2/SSLv3)

Rust est exclu car rustls refuse par design les vieux protocoles (impasse pour audit legacy). Python (sslyze) est imbattable en richesse mais mauvais en distribution. Node disqualifié pour TLS bas niveau.

### 4.2 Stack TLS hybride

| Couche                                | Implémentation                              |
|---------------------------------------|---------------------------------------------|
| TLS 1.2 / 1.3, validation de chaîne, ALPN, OCSP stapling | `crypto/tls` stdlib            |
| TLS 1.0 / 1.1 (handshake, ciphers)    | `github.com/zmap/zcrypto/tls`               |
| **SSLv3 / SSLv2 (probe yes/no)**      | **probes raw socket maison**                |
| Heartbleed                            | `github.com/zmap/zgrab2/modules/tls`        |
| Parsing certificats permissif (alt)   | `github.com/zmap/zcrypto/x509`              |
| CT logs / SCT validation              | `github.com/google/certificate-transparency-go` |

Tous masqués derrière une interface `internal/scanner/tls.Scanner`. Les implémentations sont sélectionnées par la version cible.

### 4.3 Probes raw maison pour SSLv2 et SSLv3

zcrypto a explicitement abandonné SSLv3 (constante `VersionSSL30` marquée *Deprecated: SSLv3 is cryptographically broken, and is no longer supported by this package*) et SSLv2 n'a jamais été supporté côté zcrypto. Le PR #206 qui devait réintroduire SSLv3 a été abandonné en 2020.

L'implémentation maison repose sur le constat suivant : pour détecter qu'un serveur **accepte** SSLv2 ou SSLv3, il n'est pas nécessaire de compléter le handshake. Il suffit d'envoyer un ClientHello bien formé et d'observer la première réponse :

- réception d'un `ServerHello` à la version demandée → protocole accepté = `fail`
- réception d'un `Alert` (handshake failure / protocol version) → protocole rejeté = `pass`
- TCP RST ou timeout → traité comme rejet (avec confidence `medium`)

Pseudo-implémentation pour SSLv3 (~80 LOC effectives) :

```go
// internal/scanner/tls/probes/sslv3.go
package probes

import (
    "context"
    "crypto/rand"
    "encoding/binary"
    "errors"
    "io"
    "net"
    "time"
)

type ProtocolStatus int

const (
    StatusRejected ProtocolStatus = iota
    StatusAccepted
    StatusUnknown
)

// craftSSLv3ClientHello renvoie un ClientHello SSLv3 valide proposant
// les ciphers SSLv3 historiques (RC4, DES, 3DES, NULL).
func craftSSLv3ClientHello() []byte {
    body := make([]byte, 0, 80)

    // Version SSLv3 (0x0300)
    body = append(body, 0x03, 0x00)

    // Random (32 octets)
    random := make([]byte, 32)
    _, _ = rand.Read(random)
    body = append(body, random...)

    // Session ID length (0)
    body = append(body, 0x00)

    // Cipher suites (liste ciblant SSLv3)
    ciphers := []uint16{
        0x000A, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
        0x0005, // TLS_RSA_WITH_RC4_128_SHA
        0x0004, // TLS_RSA_WITH_RC4_128_MD5
        0x0009, // TLS_RSA_WITH_DES_CBC_SHA
        0x0003, // TLS_RSA_EXPORT_WITH_RC4_40_MD5
    }
    csLen := uint16(len(ciphers) * 2)
    body = binary.BigEndian.AppendUint16(body, csLen)
    for _, c := range ciphers {
        body = binary.BigEndian.AppendUint16(body, c)
    }

    // Compression methods
    body = append(body, 0x01, 0x00)

    // Handshake header: type=ClientHello(0x01), length 24-bit
    handshake := make([]byte, 0, 4+len(body))
    handshake = append(handshake, 0x01)
    handshake = append(handshake, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
    handshake = append(handshake, body...)

    // Record header: type=Handshake(0x16), version SSLv3(0x0300), length 16-bit
    record := make([]byte, 0, 5+len(handshake))
    record = append(record, 0x16, 0x03, 0x00)
    record = binary.BigEndian.AppendUint16(record, uint16(len(handshake)))
    record = append(record, handshake...)

    return record
}

func ProbeSSLv3(ctx context.Context, addr string) (ProtocolStatus, error) {
    d := net.Dialer{Timeout: 5 * time.Second}
    conn, err := d.DialContext(ctx, "tcp", addr)
    if err != nil {
        return StatusUnknown, err
    }
    defer conn.Close()

    _ = conn.SetDeadline(time.Now().Add(5 * time.Second))

    if _, err := conn.Write(craftSSLv3ClientHello()); err != nil {
        return StatusUnknown, err
    }

    header := make([]byte, 5)
    if _, err := io.ReadFull(conn, header); err != nil {
        if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
            return StatusRejected, nil
        }
        return StatusUnknown, err
    }

    // header[0] = record type, header[1..2] = version, header[3..4] = length
    recordType := header[0]
    version := binary.BigEndian.Uint16(header[1:3])

    switch recordType {
    case 0x16: // Handshake
        if version == 0x0300 {
            return StatusAccepted, nil
        }
        return StatusRejected, nil
    case 0x15: // Alert
        return StatusRejected, nil
    default:
        return StatusUnknown, nil
    }
}
```

Pour SSLv2, l'implémentation est analogue mais utilise le format de record Netscape original (longueur sur 2 ou 3 octets selon le bit de poids fort, pas de version dans le header). ~80 LOC supplémentaires. La validation s'effectue contre badssl.com et les variantes legacy similaires.

### 4.4 Autres dépendances Go

| Domaine                       | Bibliothèque                                    |
|-------------------------------|-------------------------------------------------|
| DNS / DNSSEC / CAA / TLSA     | `github.com/miekg/dns`                          |
| HTTP framework                | `net/http` stdlib (Go 1.22+) + `github.com/go-chi/chi/v5` pour middlewares composables |
| HTML parsing (mixed content)  | `golang.org/x/net/html`                         |
| Concurrence                   | `golang.org/x/sync/errgroup`, `golang.org/x/sync/semaphore` |
| OpenAPI codegen               | `github.com/ogen-go/ogen`                       |
| CLI                           | `github.com/spf13/cobra`                        |
| Configuration                 | `github.com/knadh/koanf/v2`                     |
| Logging                       | `log/slog` stdlib                               |
| Cache mémoire MVP             | `github.com/patrickmn/go-cache`                 |
| Cache haute concurrence (alt) | `github.com/dgraph-io/ristretto`                |
| Redis (storage alt)           | `github.com/redis/go-redis/v9`                  |
| UUIDv4                        | `github.com/google/uuid`                        |
| Rate limiting                 | `golang.org/x/time/rate` + `github.com/didip/tollbooth/v8` |

### 4.5 Concurrence

Pattern à trois niveaux, appliqué uniformément sur tout le scanner :

1. **Niveau global** : `semaphore.NewWeighted(maxConcurrentScans)` borne les scans en parallèle au niveau du processus (par défaut 50, configurable).
2. **Niveau scan** : `errgroup.WithContext` + `g.SetLimit(10)` (Go 1.20+) borne les checks concurrents au sein d'un scan.
3. **Niveau check individuel** : `context.WithTimeout(ctx, 8*time.Second)` par check.

Le cache DNS (`map[string][]net.IP` protégé par `sync.RWMutex`) est partagé pour la durée d'un scan afin d'éviter les lookups redondants. Pas de retry agressif : un timeout est lui-même une information à reporter (`status: "error"` sur le finding concerné), pas à masquer. `errors.Join` collecte les erreurs partielles.

### 4.6 Configuration

Fichier YAML par défaut, surchargeable par variables d'environnement préfixées `WEBSEC101_*`, surchargeables par flags CLI :

```yaml
# /etc/websec101/config.yaml
server:
  listen: ":8080"
  read_timeout: 30s
  write_timeout: 60s

scanner:
  max_concurrent_scans: 50
  max_concurrent_checks_per_scan: 10
  per_check_timeout: 8s
  per_scan_timeout: 120s
  user_agent: "WebSec101/1.0 (+https://websec101.example/about; passive-scan)"

storage:
  backend: memory      # memory | ristretto | redis
  ttl: 24h
  redis:
    url: ""

ratelimit:
  per_ip:
    rate: 10
    period: 1h
  per_target:
    cooldown: 5m

security:
  refuse_private_ranges: true
  refuse_loopback: true
  domain_blocklist:
    - ".gov"
    - ".mil"
    - ".gouv.fr"
    - ".gc.ca"

reports:
  default_visibility: public   # public | private
  private_token_bytes: 32

logging:
  level: info
  format: json
  log_targets: false           # zero-log domain par défaut
```

## 5. API REST

### 5.1 Versioning

Versioning dans l'URL (`/api/v1/`), pas de header `Accept-Version`. Lisibilité, debug, et meilleur fit pour les agents IA qui lisent directement la spec OpenAPI.

### 5.2 Pattern asynchrone

Un scan complet prend 30 s à 2 min. Tenir une connexion HTTP synchrone est un anti-pattern (timeouts proxy, mauvaise UX agent IA). Le pattern *Asynchronous Request-Reply* (Microsoft Azure Architecture Center, RFC 9110) s'applique :

- `POST /api/v1/scans` répond **`202 Accepted`** immédiatement avec headers `Location: /api/v1/scans/{guid}` et `Retry-After: 5`
- `GET /api/v1/scans/{guid}` retourne **toujours `200 OK`** avec un body structuré contenant `status`. Pas de `404`/`202` ambigus sur le polling
- Un mode `?wait=30s` synchrone bloquant est utile pour les CLI/CI courts. Si le scan dépasse `wait`, l'API revient à l'état asynchrone et renvoie le body en cours

### 5.3 Endpoints

```
POST   /api/v1/scans                  → 202, body {id, status, links}
GET    /api/v1/scans/{guid}           → 200 toujours, body avec status
GET    /api/v1/scans/{guid}/events    → SSE (text/event-stream)
GET    /api/v1/scans/{guid}/markdown  → text/markdown
GET    /api/v1/scans/{guid}/sarif     → application/sarif+json
DELETE /api/v1/scans/{guid}           → 204 (mode privé uniquement, requiert token)
GET    /api/v1/checks                 → catalogue complet (manifest pour agents IA)
GET    /api/v1/checks/{check_id}      → détails d'un check (description, remediation template)
GET    /api/v1/health                 → 200, body {status, uptime, version}
GET    /api/v1/version                → 200, body {version, commit, build_date}
GET    /api/v1/openapi.json           → spec OpenAPI 3.1 embarquée
```

### 5.4 POST /api/v1/scans — request

```json
{
  "target": "example.com",
  "options": {
    "skip_categories": [],
    "private": false,
    "wait_seconds": 0
  }
}
```

`target` accepte un hostname pur ou une URL complète. Si une URL est fournie, le hostname est extrait, le scheme est ignoré (le scan teste systématiquement HTTP+HTTPS).

### 5.5 GET /api/v1/scans/{guid} — response (en cours)

```json
{
  "id": "f3a1c2b8-9e4d-4f6a-bcde-0123456789ab",
  "status": "running",
  "target": "example.com",
  "started_at": "2026-04-25T15:30:00Z",
  "progress": {
    "total": 70,
    "completed": 23,
    "current_phase": "headers"
  },
  "links": {
    "self": "/api/v1/scans/f3a1...",
    "events": "/api/v1/scans/f3a1.../events",
    "markdown": "/api/v1/scans/f3a1.../markdown",
    "sarif": "/api/v1/scans/f3a1.../sarif"
  }
}
```

États possibles : `queued`, `running`, `completed`, `failed`. En `completed`, le body inclut le rapport entier (cf. §6).

### 5.6 Server-Sent Events

Format `text/event-stream` standard, avec `Last-Event-ID` et reconnexion native côté navigateur via `EventSource` :

```
event: progress
id: 1
data: {"completed":1,"total":70,"current":"TLS-PROTOCOL-LEGACY-SSL3"}

event: finding
id: 2
data: {"id":"TLS-PROTOCOL-LEGACY-SSL3","status":"pass"}

event: progress
id: 3
data: {"completed":2,"total":70,"current":"TLS-PROTOCOL-LEGACY-TLS10"}

...

event: completed
id: 71
data: {"grade":"B+","score":78}
```

WebSocket exclu : flux unidirectionnel, SSE est plus simple à proxifier et compatible directement avec `curl -N` (atout agent IA).

### 5.7 OpenAPI 3.1 spec-first

`api/openapi.yaml` est la **source de vérité**. Toute évolution d'endpoint se fait dans ce fichier en premier.

- `go generate` produit serveur + client Go fortement typés via `ogen` dans `internal/api/oas/` et `pkg/client/`
- Spectral lint en CI bloque les régressions (style guide, breaking changes)
- La spec est embedded via `go:embed` et servie sur `/api/v1/openapi.json`
- Workflow CI dédié `verify-codegen` détecte la dérive entre la spec et le code généré (échec si différence)

### 5.8 Authentification et rate limiting

**MVP** :

- Aucune auth requise pour l'usage de base
- Rate limit IP : 10 scans/h/IP anonyme (`golang.org/x/time/rate` + `tollbooth`), configurable
- Cooldown re-scan : 5 min minimum entre deux scans de la même cible (toutes IPs confondues), pour éviter la consommation excessive de ressources des sites tiers
- Captcha (hCaptcha ou Cloudflare Turnstile) sur le formulaire web public uniquement, pas sur l'API
- API key optionnelle (`Authorization: Bearer wsk_xxxxx`) pour quotas élevés sur l'instance publique

**V2** : OAuth/OIDC, multi-tenancy, équipes, comptes utilisateurs.

## 6. Format du rapport

### 6.1 Schéma d'enveloppe

```json
{
  "schema_version": "1.0",
  "scan": {
    "id": "f3a1c2b8-9e4d-4f6a-bcde-0123456789ab",
    "target": "example.com",
    "started_at": "2026-04-25T15:30:00Z",
    "completed_at": "2026-04-25T15:31:42Z",
    "duration_seconds": 102,
    "scanner_version": "0.1.0",
    "scanner_user_agent": "WebSec101/1.0 (+...)"
  },
  "summary": {
    "grade": "B+",
    "score": 82,
    "scores_per_family": {
      "tls": 95,
      "headers": 60,
      "cookies": 80,
      "dns": 90,
      "email": 75,
      "custom": 85
    },
    "counts": {
      "critical": 0,
      "high": 2,
      "medium": 5,
      "low": 4,
      "info": 1,
      "passed": 58,
      "skipped": 0,
      "errored": 0
    },
    "quick_wins": [
      "HEADER-CSP-MISSING",
      "TLS-HSTS-MISSING",
      "WELLKNOWN-SECURITY-TXT-MISSING"
    ]
  },
  "findings": [ /* cf. §6.2 */ ],
  "passed_checks": [ "TLS-PROTOCOL-LEGACY-SSL3", "..." ],
  "skipped_checks": [
    {
      "id": "EMAIL-SPF-MISSING",
      "reason": "no MX record found"
    }
  ],
  "tech_stack_detected": {
    "server": "nginx",
    "powered_by": null,
    "cms": null
  },
  "links": {
    "html_report": "https://example.com/scan/f3a1.../",
    "markdown": "/api/v1/scans/f3a1.../markdown",
    "sarif": "/api/v1/scans/f3a1.../sarif",
    "openapi_spec": "/api/v1/openapi.json"
  }
}
```

### 6.2 Schéma d'un finding

C'est le différenciateur produit principal : tout finding contient ce dont un humain ou un agent IA a besoin pour comprendre, vérifier et remédier, sans aller chercher ailleurs.

```json
{
  "id": "TLS-PROTOCOL-LEGACY-TLS10",
  "title": "TLS 1.0 is enabled",
  "severity": "high",
  "confidence": "high",
  "effort": "low",
  "is_quick_win": true,
  "category": "tls",
  "subcategory": "protocol",
  "status": "fail",
  "cwe": ["CWE-326"],
  "cvss": {
    "version": "3.1",
    "score": 5.9,
    "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
  },
  "description": {
    "short": "Server accepts TLS 1.0, deprecated by RFC 8996 (March 2021).",
    "long": "TLS 1.0 was published in 1999 and contains structural cryptographic weaknesses, notably a vulnerability to the BEAST attack on CBC ciphers. It was formally deprecated by IETF RFC 8996 in March 2021 and is no longer compliant with PCI-DSS, NIST SP 800-52 Rev. 2, or major browser policies. Modern browsers have removed TLS 1.0/1.1 support since 2020-2021. Continuing to accept TLS 1.0 weakens the security of clients that would otherwise negotiate TLS 1.2/1.3, by allowing protocol downgrade in some misconfigured intermediaries."
  },
  "impact": {
    "cia": ["confidentiality", "integrity"],
    "summary": "An attacker capable of MitM may force clients to negotiate weak ciphers via downgrade and intercept or tamper with traffic."
  },
  "evidence": {
    "observed": {
      "protocols_enabled": ["TLSv1.0", "TLSv1.2", "TLSv1.3"],
      "tls10_handshake_completed": true,
      "tls10_cipher_negotiated": "TLS_RSA_WITH_AES_128_CBC_SHA"
    },
    "expected": {
      "protocols_enabled": ["TLSv1.2", "TLSv1.3"]
    },
    "raw_excerpt": "ServerHello version: 0x0301 (TLSv1.0)"
  },
  "remediation": {
    "summary": "Disable TLS 1.0 and TLS 1.1; require TLS 1.2 minimum, prefer TLS 1.3.",
    "steps": [
      "Identify the TLS termination layer (web server, load balancer, CDN).",
      "Set minimum TLS version to 1.2 in its configuration.",
      "Reload the service and re-run a scan to verify."
    ],
    "snippets": {
      "nginx": "ssl_protocols TLSv1.2 TLSv1.3;",
      "apache": "SSLProtocol -all +TLSv1.2 +TLSv1.3",
      "caddy": "tls {\n  protocols tls1.2 tls1.3\n}",
      "haproxy": "ssl-min-ver TLSv1.2",
      "cloudflare_dashboard": "SSL/TLS → Edge Certificates → Minimum TLS Version → TLS 1.2",
      "express_helmet": "// Helmet does not control TLS version; configure it on the reverse proxy or HTTPS server options.",
      "spring_boot": "server.ssl.enabled-protocols=TLSv1.2,TLSv1.3",
      "iis_web_config": "Disable via Registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server → Enabled=0"
    },
    "verification": "curl -sI --tls-max 1.0 https://example.com  # expect connection failure"
  },
  "references": [
    { "title": "RFC 8996: Deprecating TLS 1.0 and TLS 1.1", "url": "https://www.rfc-editor.org/rfc/rfc8996", "type": "rfc" },
    { "title": "Mozilla SSL Configuration Generator", "url": "https://ssl-config.mozilla.org/", "type": "tool" },
    { "title": "MDN: HTTP Strict Transport Security", "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security", "type": "documentation" }
  ],
  "tags": ["tls", "crypto", "deprecated", "rfc8996"]
}
```

Champ par champ :

- `id`, `title`, `severity`, `confidence`, `effort`, `is_quick_win`, `category`, `subcategory`, `status` : métadonnées de base
- `cwe`, `cvss` : références standards optionnelles, présentes quand applicable
- `description.short` : une phrase pour les humains
- `description.long` : suffisant pour qu'un LLM réponde sans re-fetcher de pages externes
- `impact` : explication de la conséquence en cas d'exploitation
- `evidence` : ce qui a été observé, ce qui était attendu, extrait brut
- `remediation` : résumé, étapes, **snippets indexés par stack**, commande de vérification
- `references` : liens externes pertinents (RFC, MDN, OWASP, outils Mozilla, etc.)
- `tags` : libres, exploitables pour filtrer côté UI ou agent

### 6.3 Scoring

Système hybride : **lettre A+ → F** plus **score numérique 0-100**, calqué sur la combinaison Mozilla Observatory v2 + SSL Labs.

Score baseline = 100. Penalties par finding selon sévérité :

| Sévérité | Penalty |
|----------|---------|
| critical | -25     |
| high     | -10     |
| medium   | -5      |
| low      | -2      |
| info     | 0       |

Bonus pour excellence (max +5 par bonus, plafonné à 100) :

- HSTS preload effectif (inscrit hstspreload.org) : +3
- CSP strict (pas d'`unsafe-inline`, `'strict-dynamic'`) : +3
- DNSSEC + CAA + iodef : +2
- DMARC `p=reject` aligné strict : +2
- security.txt avec signature PGP valide : +1

Mapping score → lettre :

| Score      | Lettre |
|------------|--------|
| 95-100     | A+     |
| 85-94      | A      |
| 75-84      | B      |
| 65-74      | C      |
| 50-64      | D      |
| < 50       | F      |

Score par famille calculé indépendamment avec la même formule, normalisé sur les checks de la famille. Score global pondéré : TLS 25 %, Headers 25 %, DNS 20 %, Email 15 % (si MX), Cookies 10 %, Custom 5 %.

### 6.4 Catalogue des checks (GET /api/v1/checks)

Endpoint qui expose **le catalogue complet des checks supportés**, avec leurs métadonnées statiques (id, sévérité par défaut, description, références). C'est le manifest que les agents IA chargent pour comprendre l'API sans hallucination. Réponse :

```json
{
  "schema_version": "1.0",
  "scanner_version": "0.1.0",
  "checks": [
    {
      "id": "TLS-PROTOCOL-LEGACY-TLS10",
      "title": "TLS 1.0 is enabled",
      "category": "tls",
      "subcategory": "protocol",
      "default_severity": "high",
      "supported_stacks": ["nginx", "apache", "caddy", "haproxy", "cloudflare", "spring_boot", "iis"],
      "references": [ ... ]
    },
    ...
  ]
}
```

### 6.5 Export Markdown

Endpoint `GET /api/v1/scans/{guid}/markdown` retourne `text/markdown; charset=utf-8`. Format optimisé pour la lecture humaine **et** la consommation par un agent IA. Structure :

```markdown
# WebSec101 Scan Report — example.com

**Date**: 2026-04-25T15:30:00Z  
**Grade**: B+ (82/100)  
**Duration**: 102s  
**Scanner**: WebSec101 0.1.0

## Summary

| Severity | Count |
|----------|------:|
| Critical | 0     |
| High     | 2     |
| Medium   | 5     |
| Low      | 4     |
| Info     | 1     |
| Passed   | 58    |

## Quick wins

The following findings are low-effort, high-impact:

1. **HEADER-CSP-MISSING** — Add a Content-Security-Policy header.
2. **TLS-HSTS-MISSING** — Add Strict-Transport-Security header.
3. **WELLKNOWN-SECURITY-TXT-MISSING** — Publish a /.well-known/security.txt.

## Findings

### TLS-PROTOCOL-LEGACY-TLS10 — TLS 1.0 is enabled
**Severity**: high · **Effort**: low · **Quick win**: yes

TLS 1.0 was deprecated by RFC 8996 (March 2021). Server currently accepts TLS 1.0 with `TLS_RSA_WITH_AES_128_CBC_SHA`.

**Remediation**:
- Nginx: `ssl_protocols TLSv1.2 TLSv1.3;`
- Apache: `SSLProtocol -all +TLSv1.2 +TLSv1.3`
- Caddy: `tls { protocols tls1.2 tls1.3 }`

**Verify**: `curl -sI --tls-max 1.0 https://example.com` (expect failure)

**References**: [RFC 8996](...), [Mozilla SSL Config](...)

---
...
```

### 6.6 Export SARIF 2.1.0

Endpoint `GET /api/v1/scans/{guid}/sarif` retourne `application/sarif+json`. Format adapté pour l'intégration GitHub Code Scanning (Code Quality), Azure DevOps, Sonatype, et tout outil DevSecOps standard. Mappings :

- `runs[].tool.driver.name` = `"WebSec101"`
- `runs[].tool.driver.version` = version du scanner
- `runs[].tool.driver.rules` = catalogue des checks (un rule par check ID)
- `runs[].results` = findings avec `level` (mapping `critical`/`high` → `error`, `medium` → `warning`, `low`/`info` → `note`)
- `runs[].results[].properties` = bag personnalisé pour `effort`, `is_quick_win`, `confidence`, `cvss`, `remediation.snippets`
- `runs[].results[].locations` = vide (les targets sont des hostnames, pas des fichiers source)

SARIF est utile mais inadapté comme format primaire : conçu pour SAST avec `physicalLocation` ligne/colonne, n'a que 3 niveaux de sévérité (vs 5), et les snippets multi-stack tombent dans `properties` (bag libre).

## 7. CLI

Binaire séparé `websec101-cli` (peut aussi être invoqué via `websec101 scan` quand le serveur est utilisé en mode local).

```
$ websec101-cli --help
WebSec101 CLI — passive web security scanner

Usage:
  websec101-cli [command]

Available Commands:
  scan        Run a scan against a target
  report      Render a stored scan as markdown or SARIF
  catalog     Print the catalog of supported checks
  version     Print version information
  help        Help about any command

Flags:
  -s, --server string    WebSec101 server URL (default "http://localhost:8080")
  -k, --api-key string   API key (env: WEBSEC101_API_KEY)
      --json             output JSON
      --markdown         output Markdown (default for `report`)
      --sarif            output SARIF
  -h, --help             help

$ websec101-cli scan example.com
Scanning example.com...
[████████████████████████████████████████] 70/70 (102s)

Grade: B+ (82/100)

Critical: 0    High: 2    Medium: 5    Low: 4    Info: 1

Quick wins:
  · HEADER-CSP-MISSING
  · TLS-HSTS-MISSING
  · WELLKNOWN-SECURITY-TXT-MISSING

Full report: http://localhost:8080/scan/f3a1c2b8-9e4d-4f6a-bcde-0123456789ab
```

Modes :

- **Mode online** (défaut) : appelle un serveur WebSec101 via son API. `--server` et `--api-key` configurables.
- **Mode standalone** : `websec101-cli scan --standalone example.com` lance un scan sans serveur, en process unique. Pratique pour CI/CD.
- **Mode CI** : `websec101-cli scan --standalone --sarif example.com > report.sarif` produit du SARIF directement consommable par GitHub Code Scanning. Code de sortie 0 si pass, 1 si findings critical/high, configurable via `--fail-on=critical,high`.

## 8. Frontend

### 8.1 Stack

- **Astro 5** en mode statique (output: 'static'), pas de SSR
- **Tailwind CSS** pour le style
- **Alpine.js** (15 ko) chargé en island uniquement sur les pages qui en ont besoin (page de progression SSE)
- Build → `web/dist/` → embarqué dans le binaire via `//go:embed all:dist`

Single binary garanti. Pas de Node requis à runtime.

### 8.2 Routes

| Route                 | Description                                                  |
|-----------------------|--------------------------------------------------------------|
| `/`                   | Page d'accueil avec formulaire de scan + Turnstile           |
| `/scan/{guid}`        | Vue lecture seule d'un rapport via SSE pendant le scan, puis statique |
| `/about`              | Description du scanner, User-Agent, opt-out                  |
| `/checks`             | Catalogue interactif des checks supportés                    |
| `/checks/{id}`        | Détail d'un check (description, snippets, références)        |
| `/docs/api`           | Docs API (lien vers `/api/v1/openapi.json` + Swagger UI ou Scalar) |
| `/legal/tos`          | Terms of Service                                             |
| `/legal/privacy`      | Privacy Policy                                               |

### 8.3 Mode dégradé

Pour les agents qui ne supportent pas JavaScript (Lynx, screen readers, agents IA basiques), une route serveur `/scan/{guid}.html` rend le rapport en HTML pur via `html/template` côté Go. ~200 LOC, alimenté par le même JSON que la route Astro.

### 8.4 Accessibilité

- WCAG 2.1 AA visé sur les pages statiques
- Pas de couleur seule pour transmettre une information de sévérité (ajouter texte/icône)
- Navigation clavier supportée
- Contraste minimum 4.5:1

## 9. Stockage

### 9.1 Interface

```go
// internal/storage/store.go
type ScanStore interface {
    Put(ctx context.Context, scan *Scan, ttl time.Duration) error
    Get(ctx context.Context, id string) (*Scan, error)
    Delete(ctx context.Context, id string) error
    UpdateStatus(ctx context.Context, id string, fn func(*Scan) error) error
}
```

### 9.2 Implémentations

| Backend                        | Cas d'usage                                              |
|--------------------------------|----------------------------------------------------------|
| `memory` (`patrickmn/go-cache`) | MVP, instance unique, simplicité maximale (par défaut) |
| `ristretto`                    | Haute concurrence, TinyLFU, bornage strict en mémoire    |
| `redis`                        | Multi-replica, scale horizontal (V2)                     |

### 9.3 TTL et cycle de vie

- TTL par défaut **24 heures**, configurable via `storage.ttl`
- GC périodique toutes les 5 minutes (cleanup des entrées expirées)
- Pas de persistance sur disque au MVP (memory/ristretto). Avec Redis, AOF/RDB possibles selon la config Redis du déployeur

### 9.4 Privacy by design

- **Zero-log domain** : par défaut, le domaine scanné n'est **jamais** loggé. Les access logs HTTP n'incluent que les IDs de scans (GUIDv4) — pas le domaine cible. Configurable via `logging.log_targets: false`.
- **GUIDv4** : 122 bits d'entropie via `crypto/rand`. Non-énumérable, non-devinable.
- **Pas de listing public** : aucun endpoint ne liste les scans existants.
- `robots.txt` du frontend : `Disallow: /scan/`, `Disallow: /api/v1/scans/`.
- **Mode privé** : `POST /api/v1/scans` avec `options.private: true` génère un token 256 bits supplémentaire requis pour `GET`/`DELETE` du scan. Le token est retourné une seule fois dans la réponse de création.
- **Anti-SSRF** : refus des ranges privés (RFC 1918, link-local, loopback, IPv6 ULA, CGNAT) côté instance publique. Liste hardcodée vérifiée à la résolution DNS de la cible.

### 9.5 IP anonymization

Pour le rate-limiting, l'IP source est conservée pendant **7 jours maximum**, **dernier octet zeroé** (`192.168.1.0` au lieu de `192.168.1.42` pour IPv4, `/64` pour IPv6). Base légale RGPD : intérêt légitime art. 6(1)(f).

## 10. SKILL.md pour agents IA

WebSec101 livre un dossier Skill conforme à la spécification Agent Skills d'Anthropic (publiée le 18 décembre 2025, désormais adoptée par Claude, Codex CLI, Cursor, Copilot, OpenCode).

### 10.1 Layout

```
skills/websec101/
├── SKILL.md                    # frontmatter + instructions courtes (≤500 lignes)
├── scripts/
│   ├── scan.sh                 # wrapper curl/websec101-cli
│   └── apply_remediation.sh    # snippet picker (read JSON, output snippet for stack)
└── references/
    ├── api.md                  # référence API complète
    ├── checks.md               # généré depuis GET /api/v1/checks
    ├── stacks.md               # mapping stack → snippet conventions
    └── safety.md               # règles éthiques étendues
```

### 10.2 SKILL.md (frontmatter et structure)

```markdown
---
name: websec101
description: |
  Use this skill to scan a web property for security misconfigurations
  (TLS, HTTP headers, cookies, DNS, email security, security.txt, exposed
  files) and propose copy-paste remediation snippets adapted to the user's
  stack. Triggers: "scan", "audit", "security check", "TLS test",
  "headers check", "SSL Labs equivalent", "Hardenize equivalent",
  "securityheaders.com equivalent", "DMARC", "SPF", "CSP".
---

# WebSec101 Skill

## Safety and ethics

- Only scan properties the user owns or is authorized to test.
- Do not scan .gov, .mil, banking, or critical infrastructure domains.
- This is a passive scanner. Do not combine with active exploitation tools.

## Workflow

1. Validate the target with the user (confirm ownership / authorization).
2. POST /api/v1/scans with the target.
3. Poll GET /api/v1/scans/{guid} every 5 seconds until status="completed".
4. Read findings, prioritize quick_wins.
5. For each quick win, identify the user's stack (ask if unclear).
6. Pull the matching snippet from `remediation.snippets[stack]`.
7. Propose the change. Optionally edit files and open a PR via
   `scripts/apply_remediation.sh`.

## API reference

(see `references/api.md` for full details)

POST /api/v1/scans
GET  /api/v1/scans/{guid}
GET  /api/v1/scans/{guid}/markdown

## Examples

### Scan and summarize
> User: "Scan example.com and tell me what to fix first."
> Agent: [POSTs scan, polls, returns top 3 quick wins with snippets]

### Apply CSP fix
> User: "Add the recommended CSP to my Nginx config."
> Agent: [reads HEADER-CSP-MISSING.remediation.snippets.nginx,
>         locates nginx.conf, edits, runs `nginx -t`]
```

### 10.3 MCP server (V2)

Un serveur MCP `websec101-mcp` exposant les tools `scan_target`, `get_scan_status`, `get_findings`, `get_remediation_snippet` est planifié pour V2. Au MVP, le SKILL.md + appels HTTP via `curl` ou `fetch` couvrent 100 % du besoin. Position alignée avec Anthropic : *« MCP gives Claude access to tools, while Skills teach Claude how to use those tools effectively »*.

## 11. Sécurité opérationnelle

### 11.1 Anti-SSRF

À la création d'un scan :

1. Résolution DNS de la cible
2. Vérification de chaque IP retournée contre une liste de ranges interdits :
   - IPv4 : `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, `100.64.0.0/10` (CGNAT), `0.0.0.0/8`, `224.0.0.0/4` (multicast), `240.0.0.0/4`
   - IPv6 : `::1/128`, `fc00::/7` (ULA), `fe80::/10` (link-local), `ff00::/8` (multicast)
3. Si match → refus, statut HTTP 422 avec `{"error":"target_in_private_range"}`

Configuration `security.refuse_private_ranges: true` (défaut sur instance publique). Désactivable explicitement pour l'auto-hébergement intranet.

### 11.2 Blacklist de domaines

Liste hardcodée mais éditable dans la config :

```yaml
security:
  domain_blocklist:
    - ".gov"
    - ".mil"
    - ".gouv.fr"
    - ".gc.ca"
    - ".gov.uk"
    - ".bund.de"
    - "europa.eu"
    # Critical infrastructure : à enrichir
```

Refus avec statut HTTP 451 (`Unavailable For Legal Reasons`) avec message expliquant la politique. Liste publique et éditable par PR sur le repo.

### 11.3 Rate limiting et étiquette de scan

- **User-Agent identifiable** : `WebSec101/{version} (+https://websec101.example/about; passive-scan)`. La page `/about` explique le scanner et permet l'opt-out (instructions pour bloquer ce User-Agent côté serveur scanné).
- **Rate limiting par IP cliente** : 10 scans/h/IP anonyme, 100 scans/h avec API key valide.
- **Rate limiting par cible scannée** : 1 scan tous les 5 minutes par hostname (toutes IPs sources confondues).
- **Étalement intra-scan** : ~50 requêtes étalées sur 30-60 secondes, max 5 requêtes simultanées vers la même cible.
- **Cache 24 h** : un re-scan dans les 24 h sur la même cible peut renvoyer le rapport précédent (paramètre `refresh=true` pour forcer).

### 11.4 robots.txt côté cible

WebSec101 ne respecte **pas** `robots.txt` pour le scan single-domain initié manuellement par l'utilisateur. C'est l'approche universelle des scanners de sécurité (SSL Labs, Mozilla Observatory, securityheaders.com, Hardenize, Internet.nl). Exception : si un User-Agent `WebSec101` est explicitement disallowed dans le `robots.txt` de la cible, le scan est annulé avec un message expliquant pourquoi. Détection via fetch de `/robots.txt` en première étape du scan, parsing des règles `User-agent: WebSec101` ou `User-agent: *` avec `Disallow: /`.

### 11.5 Détection d'abus

- Pattern `>5 cibles distinctes en <5 minutes` depuis une IP → captcha forcé sur les requêtes suivantes
- Pattern `requêtes API en boucle sans backoff` → ban temporaire 1h
- Audit log immutable conservé 7 jours (rotation), incluant : timestamp, IP anonymisée, target hash, status code retourné. Pas le domaine en clair.
- Adresse `abuse@` documentée dans `/about`, `/legal/abuse-policy`, et tous les rapports. Réponse engagée < 72 h.

## 12. Distribution et build

### 12.1 Conventions de versioning

[SemVer 2.0.0](https://semver.org/). Pré-1.0 = breaking changes possibles entre minor (0.1 → 0.2). Tags Git `vX.Y.Z`.

### 12.2 Conventional Commits

Tous les commits suivent [Conventional Commits 1.0.0](https://www.conventionalcommits.org/). Validation par `commitlint` en CI. Génération automatique du CHANGELOG via goreleaser.

### 12.3 goreleaser

Pipeline de release déclaratif via `.goreleaser.yaml`. Sur push d'un tag `v*` :

1. Cross-compilation : Linux/macOS/Windows × amd64/arm64
2. Strip symboles (`-s -w`) → binaires ~12 Mo gzippés
3. Archive `.tar.gz` (Unix) et `.zip` (Windows)
4. Signature **Cosign v3 keyless OIDC** (octobre 2025, breaking change `--bundle` remplace `--output-certificate`/`--output-signature` à prendre en compte dans la config)
5. SBOM SPDX généré par **Syft**
6. Provenance **SLSA Level 3** via GitHub Actions OIDC
7. Image Docker multi-arch poussée sur **GHCR** avec base `gcr.io/distroless/static-debian12:nonroot` (≤15 Mo, surface d'attaque minimale)
8. Mise à jour automatique du tap **Homebrew**
9. Création de la release GitHub avec changelog généré

### 12.4 Méthodes d'installation

```bash
# One-liner (recommandé)
curl -sSL https://websec101.example/install.sh | sh

# Script alternatif manuel (vérification cosign + SHA256)
# Documenté dans docs/self-hosting.md

# go install
go install github.com/your-org/websec101/cmd/websec101@latest

# Homebrew (macOS / Linux)
brew install your-org/tap/websec101

# Docker
docker run --rm -p 8080:8080 ghcr.io/your-org/websec101:latest

# docker-compose pour auto-hébergement
# (template fourni dans deploy/docker/docker-compose.yml)

# Binaire pré-compilé
# Téléchargement depuis https://github.com/your-org/websec101/releases
```

### 12.5 Dockerfile (extrait)

```dockerfile
# build stage
FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/websec101 ./cmd/websec101

# runtime stage
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/websec101 /websec101
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/websec101"]
```

## 13. CI/CD

GitHub Actions, fichiers dans `.github/workflows/` :

| Workflow         | Déclencheur                  | Étapes                                                                 |
|------------------|------------------------------|------------------------------------------------------------------------|
| `ci.yml`         | push / PR sur main           | golangci-lint, gosec, eslint frontend, spectral lint OpenAPI, `go test -race`, vitest, **verify-codegen** (anti-dérive ogen) |
| `release.yml`    | push tag `v*`                | goreleaser, cosign signing, SBOM, image Docker GHCR, GitHub release    |
| `codeql.yml`     | hebdo + PR sur paths sensibles | CodeQL Go + JS                                                       |
| `dependabot.yml` | hebdo                        | Pull requests automatiques pour les bumps de dépendances               |

Branch protection sur `main` : require PR review (≥1), require status checks (ci.yml), require signed commits.

## 14. Légal

### 14.1 Licence du projet

**MIT License**. Cohérent avec l'écosystème Go OSS (nuclei, trivy, syft, gitleaks, osv-scanner). Texte intégral dans `LICENSE`.

### 14.2 Licence des rapports générés

Les rapports produits par l'instance publique sont publiés sous **Creative Commons BY 4.0** : libre réutilisation avec attribution. Mentionné dans la ToS et en footer de chaque rapport.

### 14.3 Terms of Service (ToS) — clauses essentielles

Le fichier complet vit dans `docs/legal/tos.md`. Sections obligatoires :

1. **Description du service** : nature passive du scanner, périmètre (cf. §1.3)
2. **Acceptable use** : 4 conditions cumulatives d'autorisation à scanner (propriétaire, autorité légitime, ou autorisation écrite ; sites publics dans le cadre de bug bounty programs ; tests sur sa propre infrastructure ; usage à titre éducatif sur des sites de demo type badssl.com)
3. **Interdictions explicites** : avec mention nominative des textes pertinents (CFAA, §202c StGB, CMA 1990, art. 323-1 du Code pénal français), refus de scan sur infrastructure critique
4. **Nature passive du scan + User-Agent identifiable**
5. **No warranty** boilerplate MIT-style
6. **Gestion des reports** : URL UUIDv4, expiration 7 jours par défaut sur l'instance publique, mode `private` avec token 256 bits, suppression sur demande
7. **Licence** : MIT pour le code, CC-BY 4.0 pour les rapports
8. **Terminaison** : motifs (abuse, violation ToS), procédure
9. **Governing law** : juridiction du déployeur (à compléter à l'instanciation)
10. **Contact** : `abuse@`, `security@`, adresse postale du déployeur

### 14.4 Privacy Policy — clauses essentielles

Fichier `docs/legal/privacy.md`. Sections obligatoires :

1. **Données collectées** :
   - Target domain stocké avec le scan (durée : TTL configurable, 7 jours par défaut sur instance publique)
   - IP anonymisée dernier octet zeroé, conservée 7 jours pour rate-limit (base légale art. 6(1)(f) intérêt légitime)
   - User-Agent
   - Rapports de scan
2. **Pas de** : analytics, trackers, third-party cookies, fingerprinting
3. **Sub-processeurs** : hébergeur (à compléter à l'instanciation), idéalement EU/EEA pour l'instance publique européenne
4. **Droits RGPD** : art. 15-17 (accès, rectification, effacement). Procédure d'exercice via `privacy@`
5. **DPO** : si applicable, contact dédié
6. **Notification de breach** : engagement < 72 h (RGPD art. 33-34)
7. **Mises à jour de la policy** : versioning, notification

### 14.5 Documentation des mesures anti-abus (`docs/legal/abuse-policy.md`)

- Captcha (hCaptcha / Cloudflare Turnstile) sur formulaire web
- Rate limit 10 scans/h/IP anonyme
- Refus re-scan d'une cible sous 5 minutes
- Blacklist domaines (`.gov`/`.mil`/banques/santé)
- Refus IPs privées (anti-SSRF)
- Détection pattern d'abus (>5 cibles distinctes en <5 min → captcha forcé)
- Audit log immutable 7 jours
- Email `abuse@` visible partout
- GUIDv4 pour reports
- Mode `private` avec token
- Réponse `abuse@` < 72 h

### 14.6 Disclaimer scanner

Disclaimer visible en footer de tout rapport :

> *WebSec101 is a passive configuration scanner. Findings are based on observed configuration and known best practices; they are not a substitute for a full security assessment. WebSec101 makes no guarantee regarding the absence of vulnerabilities not covered by its checks. The user is responsible for ensuring they have authorization to scan the target.*

## 15. Roadmap V2 et au-delà

### 15.1 V2 (priorité haute, 6-12 mois après 0.1.0)

- **Tech detection riche** via Fingerprinter (sidecar Chromium) ou wappalyzergo en pure Go
- **Scan de ports actif** sur ports usuels (22, 25, 80, 443, 3306, 5432, 6379, 8080, 27017, etc.)
- **Open redirects** par fuzzing de paramètres typiques (`?url=`, `?redirect=`, `?next=`, etc.)
- **Clear-Site-Data sur logout** (nécessite identification de routes auth, donc crawling léger)
- **HTTP/3 handshake complet** via `quic-go/quic-go` (au-delà de la simple détection Alt-Svc)
- **DROWN, ROBOT, Ticketbleed, Lucky13, RACCOON** actifs (au-delà des détections statiques par version/cipher)
- **Readiness post-quantique** : détection X25519MLKEM768 (déjà déployé Cloudflare/Chrome)
- **MCP server** `websec101-mcp` exposant tools structurés pour Claude/Cursor
- **OAuth/OIDC + multi-tenancy** : comptes utilisateurs, équipes, historique, comparaison entre scans
- **Intégrations CI** : GitHub Action officielle, GitLab CI template, Jenkins plugin

### 15.2 V3 et au-delà (long terme)

- Mode authenticated scan (pour détecter Cache-Control sur pages auth, Clear-Site-Data sur logout)
- Détection de subdomain takeover proactive avec brute-force DNS contrôlé
- Crawling profond léger (max 50 pages) pour trouver les endpoints intéressants
- Scoring contextuel : recommandations adaptées au type de site (e-commerce, app interne, blog)
- Plugins WebSec101 : framework pour des checks tiers contribués
- Intégration avec OSV/NVD pour corréler la stack détectée avec des CVE actives
- Helm chart Kubernetes officiel
- Dashboard d'observabilité métier (Grafana template)

## 16. Glossaire et références

### 16.1 Glossaire

- **MVP** : Minimum Viable Product, ici la version 0.1.0
- **Quick win** : finding avec `severity` ≥ medium et `effort: low`, le plus haut ROI sécurité/effort
- **Stack** : ensemble du serveur web + framework + reverse proxy / CDN d'un site
- **Findings** : un check qui ne passe pas, structuré selon §6.2
- **Catalog** : ensemble des checks supportés par le scanner
- **Probe raw** : ClientHello bricolé manuellement et envoyé via socket TCP, sans passer par une lib TLS

### 16.2 RFC référencées

- RFC 8996 : Deprecating TLS 1.0 and TLS 1.1
- RFC 9116 : A File Format to Aid in Security Vulnerability Disclosure (security.txt)
- RFC 8615 : Well-Known URIs
- RFC 7208 : Sender Policy Framework (SPF)
- RFC 6376 : DomainKeys Identified Mail (DKIM)
- RFC 7489 : Domain-based Message Authentication, Reporting, and Conformance (DMARC)
- RFC 8461 : SMTP MTA Strict Transport Security (MTA-STS)
- RFC 8460 : SMTP TLS Reporting (TLS-RPT)
- RFC 7672 : SMTP Security via Opportunistic DNS-Based Authentication of Named Entities (DANE)
- RFC 6844 / 8659 : DNS Certification Authority Authorization (CAA)
- RFC 7633 : X.509v3 Transport Layer Security Feature Extension (OCSP must-staple)
- RFC 9110 : HTTP Semantics

### 16.3 Standards et référentiels

- OWASP HTTP Security Response Headers Cheat Sheet
- Mozilla Web Security Guidelines
- Mozilla SSL Configuration Generator
- NIST SP 800-52 Rev. 2 (TLS Implementation Guidance)
- OASIS SARIF 2.1.0
- Anthropic Agent Skills Specification (agentskills.io)
- Conventional Commits 1.0.0
- Semantic Versioning 2.0.0
- SLSA framework

### 16.4 Outils inspirants étudiés

- SSL Labs (Qualys) — référence historique TLS, scoring en lettres
- Hardenize (Red Sift) — couverture multi-domaines, modèle propriétaire
- securityheaders.com (Snyk, API closing avril 2026) — UX rapport headers
- Mozilla Observatory v2 (MPL-2.0) — scoring algorithm, focus headers
- Internet.nl (NLnet Labs, OSS) — couverture compliance EU, stack lourde
- testssl.sh (GPLv2) — référence d'exhaustivité TLS, Bash
- sslyze (AGPL) — librairie TLS Python
- humble (GPLv3) — analyseur headers Python, 62 headers + 1280 fingerprints
- Nuclei (MIT) — moteur de templates YAML générique
- Fingerprinter (MIT, JoshuaMart) — tech detection via Chromium headless

---

**Fin du document.**

Pour toute évolution majeure de spécification, créer une PR sur ce fichier avec changelog en tête. Les modifications mineures (typos, clarifications) peuvent être commitées directement par les maintainers.
