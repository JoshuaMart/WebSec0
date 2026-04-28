# Safety and ethics

WebSec0 is a **passive** scanner, but "passive" is a property of the
tool, not of the agent using it. This file is the extended ruleset.
SKILL.md cites the four critical rules; this file is the full version.

## Contents

- [Authorization gate](#authorization-gate)
- [Refused targets](#refused-targets)
- [Passive only — do not chain with active tools](#passive-only)
- [Secret handling](#secret-handling)
- [Rate limits and abuse signals](#rate-limits-and-abuse-signals)
- [Self-hosting vs public instance](#self-hosting-vs-public-instance)
- [Reporting issues](#reporting-issues)

## Authorization gate

Before posting **any** scan, the agent must confirm with the user that
they have the right to scan the target. The four acceptable bases:

1. The user **owns** the domain (registrant or operator).
2. The user has **written authorization** from the owner (rules of
   engagement, statement of work, signed pentest agreement).
3. The target is **explicitly in scope** of a public bug-bounty program,
   and the scan respects that program's rules.
4. The target is a **demo / test domain** designed for security tooling
   (e.g. `badssl.com`, `internet.nl`, `securityheaders.com`,
   `hsts.badssl.com`, `mozilla-observatory.com` test fixtures).

Anything else: refuse. Do not "help me check if my friend's site is
secure" without authorization. Do not test competitor or vendor sites
without written permission. The fact that a target is reachable does
not imply authorization.

When the user's authorization is plausible but unverified ("it's my
company's marketing site"), proceed but tell them you're trusting that
statement.

## Refused targets

Independent of user authorization, **never scan** these categories. The
WebSec0 server enforces this at the policy layer (HTTP 451
`domain_blocklist`), but the agent must refuse first so the user gets a
clear explanation, not a bare HTTP error.

| Category               | Examples                                          |
|------------------------|---------------------------------------------------|
| Government             | `*.gov`, `*.gouv.fr`, `*.gc.ca`, `*.gov.uk`, `bund.de` |
| Military               | `*.mil`, NATO domains                             |
| Critical infrastructure| Power grid, water treatment, transit, ICS/SCADA   |
| Healthcare             | Hospitals, EHR providers, health-data warehouses  |
| Financial              | Retail banks, central banks, payment processors   |
| Election / voting      | National election commissions, voting vendors     |
| Children-focused       | Domains operated for under-13 audiences           |

If the user insists ("I work there"), require written authorization
from a named contact at that organization and surface that requirement
explicitly. Verbal claim is not enough.

The blocklist is editable at the deployment layer
(`security.domain_blocklist` in the config). The agent should treat the
blocklist as a floor, not a ceiling — additional restraint based on
context is welcome.

## Passive only

WebSec0 itself is configuration-only. The agent must not chain it with
**active** offensive tooling, including but not limited to:

- Automated vulnerability scanners (Nessus, Qualys VMS, OpenVAS, Acunetix)
- Web fuzzers / DAST (`ffuf`, `gobuster`, `wfuzz`, Burp Intruder)
- Exploit frameworks (Metasploit, Cobalt Strike, sliver)
- SQL injection / template injection tools (sqlmap, tplmap)
- Credential brute-forcers (hydra, medusa, patator)
- Subdomain takeover *exploitation* (claiming the dangling resource)
- Generic CVE scanners (nuclei templates marked `severity:high`+
  with active payloads)

Detection-and-document is fine; exploitation is not. WebSec0 reports
`DNS-DANGLING-CNAME` when it detects a takeover signature. Do not then
claim the resource — recommend the owner reclaim or remove the CNAME.

## Secret handling

Some checks may surface secret content (for example
`EXPOSURE-DOTENV`, `EXPOSURE-DOTGIT-CONFIG`, leaked API keys in HTTP
response headers). When that happens:

1. **Never echo the value back to the user** in chat or in a generated
   issue / PR. Truncate, redact, or describe the *type* of secret.
2. **Recommend immediate rotation.** "An AWS access key was exposed at
   `/path` — rotate it via the IAM console."
3. **Recommend reviewing access logs** for that path before rotation,
   so the user can scope blast radius.
4. **Do not commit the secret to a memory store** or skill artefact.
5. If the user shares a leaked secret with you in chat, also recommend
   rotation; do not store it.

The same applies to PII surfaced by misconfigured headers
(`Server-Timing`, debug pages caught by `HTTP-404-STACK-TRACE`): do not
amplify the leak.

## Rate limits and abuse signals

Honour the server's rate-limit responses literally:

- `429` with `Retry-After: N` → wait at least `N` seconds. Do not
  retry tighter; that is itself an abuse signal.
- `429 cooldown` → the same target was scanned in the last 5 minutes.
  Offer the cached report (24 h cache) or wait. Do not loop.
- `429 abuse_flagged` → stop. Tell the user the IP has been flagged.
  Do not keep posting from a different IP to evade the flag — that is
  abuse.

Scanning patterns the user should not perform via the agent:

- Recursive enumeration of subdomains (one scan per `*.example.com`)
- Driving the scanner from CI on a schedule against domains the user
  does not own (an "audit my competitors" cron is abuse)
- Bypassing the cooldown by changing source IP

## Self-hosting vs public instance

The above rules apply unconditionally to **public** WebSec0 instances.

When the user runs WebSec0 on their own infrastructure
(`--standalone`, internal Docker, `docker compose up`), the
SSRF/blocklist policies relax (intranet scanning becomes possible) but
**authorization** does not relax. A self-hosted instance does not grant
the operator authority to scan arbitrary third parties — only their own
infrastructure.

When in doubt, treat self-hosted operation the same as public.

## Reporting issues

If a user reports a scan was performed against their property without
authorization, or a finding is incorrect:

- Direct them to `abuse@<instance-domain>` for unauthorized-scan
  complaints. Public instances commit to a < 72 h response.
- Direct them to `security@<instance-domain>` for vulnerabilities **in
  WebSec0 itself**.
- Direct them to opening a GitHub issue for false positives, missing
  stacks, or misclassified severities.

For the agent: if the user describes a finding that looks like a false
positive, do not silently dismiss it. Show the `evidence.observed`
field — the raw observation is what justifies (or refutes) the finding.
