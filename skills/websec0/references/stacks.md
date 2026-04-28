# Stack conventions

WebSec0 findings expose `remediation.snippets` keyed by **stack key**.
This file documents what each key means: what file to edit, where to
deploy, the conventional context the snippet should live in, and the
verification command.

## Contents

- [Stack key vocabulary](#stack-key-vocabulary)
- [`nginx`](#nginx)
- [`apache`](#apache)
- [`caddy`](#caddy)
- [`haproxy`](#haproxy)
- [`cloudflare` / `cloudflare_dashboard`](#cloudflare)
- [`express_helmet`](#express_helmet)
- [`fastify`](#fastify)
- [`spring_boot`](#spring_boot)
- [`iis_web_config`](#iis_web_config)
- [Detecting the user's stack](#detecting-the-users-stack)
- [Choosing fallback when no exact match](#choosing-a-fallback)

## Stack key vocabulary

| Key                     | What it targets                                           |
|-------------------------|-----------------------------------------------------------|
| `nginx`                 | Nginx config (`nginx.conf` / `sites-enabled/*.conf`)      |
| `apache`                | Apache HTTPD (`httpd.conf` / `.htaccess`)                 |
| `caddy`                 | Caddyfile / JSON config                                   |
| `haproxy`               | HAProxy `frontend`/`backend` blocks                       |
| `cloudflare`            | Cloudflare config-as-code (Wrangler, `cloudflare-workers`)|
| `cloudflare_dashboard`  | Click-path in the Cloudflare dashboard                    |
| `express_helmet`        | Node.js / Express middleware via `helmet`                 |
| `fastify`               | Fastify plugins (`@fastify/helmet`, `@fastify/secure-session`) |
| `spring_boot`           | `application.properties` / `application.yml` / Spring Security DSL |
| `iis_web_config`        | IIS `web.config` system.webServer block, Registry hints   |
| `dns_zone`              | DNS zone file fragment (RFC 1035)                         |
| `python_django`         | Django settings.py / SECURE_* directives                  |
| `php_htaccess`          | `.htaccess` overrides for PHP-served apps                 |

The list grows as new snippets are added. **Never assume a key exists**
— always look at the actual `remediation.snippets` keys for the finding.

## nginx

| Aspect | Value |
|---|---|
| Default config path | `/etc/nginx/nginx.conf`, virtual hosts under `/etc/nginx/sites-enabled/` |
| Insertion point | Inside the relevant `server { … }` block (HTTPS one) for headers, top-level `http { … }` for global TLS |
| Reload command | `sudo nginx -t && sudo systemctl reload nginx` |
| Verification | `curl -sI https://example.com` (look for the new header) |

Header snippets use `add_header` with `always` so they are sent on
non-2xx responses too:

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
```

TLS protocol/cipher snippets go alongside `ssl_certificate`:

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
```

Gotcha: each `add_header` directive in a deeper context **replaces**
the parent-context headers. If you add a header in a `location { }`
block, you must repeat the headers from the parent `server { }`.

## apache

| Aspect | Value |
|---|---|
| Default config path | `/etc/apache2/apache2.conf` (Debian) / `/etc/httpd/conf/httpd.conf` (RHEL) |
| Per-site path | `/etc/apache2/sites-enabled/*.conf` (Debian) |
| Modules required | `mod_headers`, `mod_ssl`, `mod_rewrite` |
| Reload command | `sudo apachectl configtest && sudo systemctl reload apache2` |
| Verification | `curl -sI https://example.com` |

Header snippets use `Header always set`:

```apache
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
```

`.htaccess` works only when `AllowOverride All` (or at least
`AllowOverride FileInfo`) is set on the relevant `<Directory>`.

## caddy

| Aspect | Value |
|---|---|
| Default config path | `/etc/caddy/Caddyfile` |
| Reload command | `sudo caddy validate --config /etc/caddy/Caddyfile && sudo systemctl reload caddy` |
| Verification | `curl -sI https://example.com` |

Caddy v2 prefers global directives:

```caddy
example.com {
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        Content-Security-Policy "default-src 'self'"
    }
    tls {
        protocols tls1.2 tls1.3
    }
}
```

Caddy v1 syntax differs — check `caddy version` first.

## haproxy

| Aspect | Value |
|---|---|
| Default config path | `/etc/haproxy/haproxy.cfg` |
| Reload command | `sudo haproxy -c -f /etc/haproxy/haproxy.cfg && sudo systemctl reload haproxy` |
| Verification | `curl -sI https://example.com` |

Snippets target the `frontend` block for HTTP behaviour and the `bind`
line for TLS:

```haproxy
frontend https-in
    bind *:443 ssl crt /etc/haproxy/certs/example.pem ssl-min-ver TLSv1.2
    http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains"
```

## cloudflare

Two distinct keys cover Cloudflare:

- **`cloudflare`** — config-as-code (Workers, Wrangler, Terraform).
- **`cloudflare_dashboard`** — manual click-path. Use this when the
  user does not have IaC and just wants to fix it now.

Dashboard format example:

```
SSL/TLS → Edge Certificates → Minimum TLS Version → TLS 1.2
```

Workers/Pages snippets manipulate response headers in the worker
script:

```js
response.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload')
```

## express_helmet

| Aspect | Value |
|---|---|
| Package | `helmet` (npm) |
| Insertion point | Top of the Express app, before route handlers |
| Verification | `curl -sI http://localhost:3000` |

```js
import helmet from 'helmet'
app.use(helmet({
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  contentSecurityPolicy: { directives: { defaultSrc: ["'self'"] } },
}))
```

Helmet does **not** control TLS protocol versions — set those on the
HTTPS server options or the reverse proxy in front of Node.

## fastify

```js
import fastify from 'fastify'
import helmet from '@fastify/helmet'

const app = fastify()
await app.register(helmet, {
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  contentSecurityPolicy: { directives: { defaultSrc: ["'self'"] } },
})
```

## spring_boot

| Aspect | Value |
|---|---|
| Config files | `application.properties`, `application.yml`, Spring Security `SecurityFilterChain` |
| Verification | `curl -sI https://localhost:8443` after restart |

Properties form:

```properties
server.ssl.enabled-protocols=TLSv1.2,TLSv1.3
server.ssl.ciphers=TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384
```

Headers via Spring Security:

```java
http.headers(headers -> headers
    .httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(31536000))
    .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'")));
```

## iis_web_config

Headers go in `web.config` under `<system.webServer><httpProtocol>`:

```xml
<system.webServer>
  <httpProtocol>
    <customHeaders>
      <add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains; preload" />
    </customHeaders>
  </httpProtocol>
</system.webServer>
```

TLS protocol changes are at the OS level (Schannel), not in `web.config`:

```
HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server → Enabled=0 (DWORD)
```

A reboot is required after Registry changes.

## Detecting the user's stack

Three signals, in order of reliability:

1. **`scan.tech_stack_detected`** in the scan body — the scanner reads
   `Server:`, `X-Powered-By:`, `X-Generator:`, and CMS fingerprints.
2. **Filesystem evidence** the user already shared (`nginx.conf`,
   `Caddyfile`, `pom.xml`, `package.json` with `helmet`, `web.config`,
   `.htaccess`).
3. **Ask the user.** A single short question is fine: *"What's
   terminating TLS — Nginx, Apache, Caddy, HAProxy, or a CDN?"*

## Choosing a fallback

If the finding's `remediation.snippets` does not contain the user's
stack key, do **not** fabricate a snippet. Either:

- Pick the closest analogue from the available keys (e.g. `nginx` is a
  reasonable model for any reverse-proxy-style config) and tell the user
  *what* the snippet does, so they can translate it.
- Suggest the user open an issue or PR adding the missing stack to the
  check's snippet table.

The `apply_remediation.sh` script enforces this: it exits non-zero
listing the available stacks rather than silently picking one.
