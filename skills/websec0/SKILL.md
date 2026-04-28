---
name: websec0
description: Audits a web property for security misconfigurations (TLS protocols and ciphers, certificates, HTTP security headers, cookie flags, DNS/DNSSEC, email authentication SPF/DKIM/DMARC/MTA-STS/DANE, security.txt, exposed sensitive files, CORS) and proposes copy-paste remediation snippets indexed by stack (Nginx, Apache, Caddy, HAProxy, Cloudflare, Express, Spring Security, IIS). Use when the user asks to scan, audit, or security-check a website, requests an SSL Labs / Hardenize / securityheaders.com / Mozilla Observatory equivalent, or mentions CSP, HSTS, DMARC, SPF, DKIM, TLS configuration, security headers, security.txt, subdomain takeover, or mixed content.
---

# websec0

WebSec0 is a passive web security scanner. It exposes an HTTP API and a
CLI; this skill drives either of them, reads findings, and produces
remediation snippets for the user's stack.

## Safety first — read before scanning anything

The full ruleset is in [references/safety.md](references/safety.md). The
non-negotiable rules:

1. **Authorization gate.** Only scan properties the user owns or is
   authorized to test. If the target ownership is unclear, **ask before
   posting the scan**. Bug-bounty programs in scope count; arbitrary
   third-party domains do not.
2. **Refuse `.gov`, `.mil`, banking, hospitals, ICS / critical
   infrastructure.** The server enforces this at the policy layer (HTTP
   451), but the skill must refuse first so the user gets a clear
   message instead of a bare HTTP error.
3. **Passive only.** WebSec0 is a configuration scanner. Do not chain it
   with active exploitation tools (sqlmap, nuclei, ffuf, brute-forcers).
4. **Never echo secrets.** If a check happens to surface secret content
   (e.g. `EXPOSURE-DOTENV`, leaked API keys), recommend rotation; do
   **not** print the value back to the user or paste it in an issue.

## Workflow

```
Scan workflow:
- [ ] 1. Confirm authorization with the user
- [ ] 2. Pick the endpoint (API server, CLI, or standalone CLI)
- [ ] 3. Start the scan
- [ ] 4. Wait for completion (poll or SSE)
- [ ] 5. Read findings, pick quick wins
- [ ] 6. Detect the user's stack, pull matching snippets
- [ ] 7. Apply or propose the fix; verify with the suggested command
```

### 1. Confirm authorization

Ask the user explicitly. A short phrase is enough: *"I'll be scanning
`example.com` — please confirm you own this domain or are authorized to
test it."* Do not skip this step.

### 2. Pick the endpoint

| Situation | Use |
|---|---|
| WebSec0 server reachable on `$WEBSEC0_SERVER` | `scripts/scan.sh` (default) |
| Local CLI binary, no server | `websec0-cli scan --standalone <target>` |
| Tool-calling environment without bash | Direct HTTP POST to `/api/v1/scans` |

The default flow is `scripts/scan.sh`, which wraps the API.

### 3. Start the scan

**Run** `scripts/scan.sh`:

```bash
scripts/scan.sh example.com
# Optional flags:
#   --server URL       Default: $WEBSEC0_SERVER or http://localhost:8080
#   --api-key KEY      Default: $WEBSEC0_API_KEY
#   --wait SECONDS     Synchronous wait (≤120, default 60)
#   --format FMT       json | markdown | sarif (default json)
#   --private          Mint a private scan with a token
```

The script handles polling, SSE, errors, and retries. It exits non-zero
on any error (rate-limit, blocked target, server failure) and writes a
clear message to stderr.

### 4. Read the result

`scripts/scan.sh` prints the requested format to stdout. JSON has the
shape described in [references/api.md](references/api.md#scan-response).
Markdown is the format from `GET /api/v1/scans/{guid}/markdown`; it is
already structured for direct LLM consumption.

For human summaries, prefer Markdown. For programmatic decisions
(picking quick wins, choosing a stack), parse the JSON.

### 5. Quick wins

`summary.quick_wins` is a list of finding IDs sorted by ROI
(security ÷ effort). Default to those when the user asks "what should I
fix first?".

### 6. Detect the stack

Look at `tech_stack_detected` first (`server`, `powered_by`, `cms`).
Fall back to asking the user. Common values and the snippet keys they
map to are listed in [references/stacks.md](references/stacks.md).

### 7. Apply the fix

**Run** `scripts/apply_remediation.sh` with the finding ID, the stack
name, and either a saved scan JSON or a live scan ID:

```bash
# from a saved JSON file
scripts/apply_remediation.sh --finding HEADER-CSP-MISSING --stack nginx --file scan.json

# from a live scan via the API
scripts/apply_remediation.sh --finding HEADER-CSP-MISSING --stack nginx --scan $GUID
```

The script prints the snippet only — clean enough to redirect into a
config file or pipe through `pbcopy`. It exits 1 with a clear message if
the finding doesn't expose a snippet for the requested stack.

After applying the change, run the `verification` field of the
`remediation` block (a one-line shell command that proves the fix
works). If the verification fails, iterate; do not declare success.

## Examples

### Scan and summarize the top three quick wins

> User: *"Scan `example.com` and tell me what to fix first."*
>
> 1. Confirm authorization.
> 2. `scripts/scan.sh example.com --format json > /tmp/scan.json`
> 3. Read `/tmp/scan.json`. Take `summary.quick_wins[:3]`.
> 4. For each, find the matching object in `findings[]`. Present
>    `title`, one-line `description.short`, and `remediation.summary`.
> 5. Offer to print the snippet for the user's stack.

### Apply a CSP fix to nginx

> User: *"Add the recommended CSP to my Nginx config at
> `/etc/nginx/sites-enabled/example.conf`."*
>
> 1. `scripts/apply_remediation.sh --finding HEADER-CSP-MISSING --stack nginx --file /tmp/scan.json`
> 2. Read the snippet from stdout.
> 3. Edit `/etc/nginx/sites-enabled/example.conf`, insert the snippet
>    inside the relevant `server { … }` block.
> 4. Run `sudo nginx -t` to validate, then `sudo systemctl reload nginx`.
> 5. Run the `verification` command from the finding (a `curl -I` that
>    expects the new header).

### Use the SARIF report in a CI pipeline

> User: *"I want this in GitHub Code Scanning."*
>
> 1. `scripts/scan.sh example.com --format sarif > report.sarif`
> 2. Use `github/codeql-action/upload-sarif` in the workflow.
>
> Mapping: `critical`/`high` → SARIF `error`, `medium` → `warning`,
> `low`/`info` → `note`.

### CI hard gate

> User: *"Fail the build on any high or critical finding."*
>
> ```bash
> websec0-cli scan example.com --standalone --fail-on critical,high
> ```
>
> Exit code 0 = clean. Exit code 2 = at least one finding at the
> requested severity.

## Output format guide

| The user wants… | Use |
|---|---|
| A summary in chat | Markdown report (`--format markdown`) |
| To pick top N quick wins programmatically | JSON (`--format json`) → `summary.quick_wins` |
| To file a GitHub issue | Markdown report |
| To feed GitHub Code Scanning | SARIF (`--format sarif`) |
| To edit a config file | JSON → `findings[i].remediation.snippets[stack]` |

## Common error responses

| HTTP | code | What to do |
|---|---|---|
| 422 | `target_blocked` | Refuse the scan; the IP is private/loopback. Tell the user. |
| 451 | `domain_blocklist` | Refuse the scan; the policy forbids this category (`.gov`, `.mil`, …). Tell the user. |
| 429 | `cooldown` | Same target was scanned <5 min ago. Offer the cached report (`refresh=false`) or wait. |
| 429 | `rate_limited` | Back off. **Do not** retry tighter than the `Retry-After` header. |
| 429 | `abuse_flagged` | Stop scanning. Tell the user the IP has been flagged. |
| 401 | `invalid_token` | Re-check `$WEBSEC0_API_KEY` or the private-mode token. |

## References

- **API reference** — [references/api.md](references/api.md) (full
  endpoints, schemas, SSE format, error envelope)
- **Check catalog** — [references/checks.md](references/checks.md) (all
  126 checks grouped by family; live source is
  `GET /api/v1/checks`)
- **Stack conventions** — [references/stacks.md](references/stacks.md)
  (file paths, deployment commands, gotchas per stack)
- **Safety rules** — [references/safety.md](references/safety.md)
  (authorization, refuse list, secret handling)
