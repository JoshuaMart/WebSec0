# AI agent integration

WebSec0 is designed for **two audiences at parity** — humans and AI agents.
Every decision in the API and report formats was made so that an LLM can
answer correctly **without re-fetching external documentation**:

- `description.long` is self-sufficient (no "see RFC X" hand-waving).
- `evidence` contains observed values + expected values + a raw excerpt.
- `remediation.snippets` is keyed by stack (Nginx, Apache, Caddy, …).
- `GET /api/v1/checks` is the single manifest of supported checks; agents
  can load it once at session start.
- The Markdown report (`GET /api/v1/scans/{guid}/markdown`) is structured
  for LLM consumption (clear sections, no fluff, copy-paste-ready
  remediations).

## Three integration patterns

### 1. SKILL.md (Anthropic Agent Skills)

Best for: Claude Code, Codex CLI, Cursor, Copilot, OpenCode — anything
that supports the [Anthropic Agent Skills](https://www.anthropic.com/engineering/equipping-agents-for-the-real-world-with-agent-skills)
specification (December 2025).

WebSec0 ships its skill at [`skills/websec0/`](../skills/websec0/):

```
skills/websec0/
├── SKILL.md                 # frontmatter + workflow + safety rules
├── scripts/
│   ├── scan.sh              # curl/CLI wrapper
│   └── apply_remediation.sh # snippet picker for a given stack
└── references/
    ├── api.md
    ├── checks.md            # generated from GET /api/v1/checks
    ├── stacks.md            # mapping stack → snippet conventions
    └── safety.md
```

To load it into Claude Code:

```bash
# Drop the skill into your project (or ~/.claude/skills/)
cp -r skills/websec0 ~/.claude/skills/
```

Claude will autoload the skill when the user mentions "scan", "audit",
"security check", "TLS test", "CSP", "DMARC", etc. (See the `triggers`
list in `SKILL.md`.)

### 2. Direct HTTP API

Best for: ChatGPT custom GPTs, function-calling endpoints, any agent that
already speaks HTTP. The OpenAPI spec is served live at
`/api/v1/openapi.json`. Most function-calling frameworks accept it
directly.

**OpenAI custom GPT** — paste the URL into the GPT builder's *Actions*
section. Set authentication to *None* (or *Bearer* if you've enabled API
keys on your instance).

**Vercel AI SDK / LangChain / LlamaIndex** — generate a typed client from
the OpenAPI spec; expose its methods as tools.

### 3. CLI invocation from a tool-calling agent

Best for: agents that already run shell commands (Cursor agent mode,
aider, Claude Code via the `Bash` tool, Goose, etc.).

```bash
websec0-cli scan example.com --standalone --json
```

Stdout is parseable JSON; the exit code is `0` on pass and `2` if
`--fail-on critical,high` is hit.

## Workflow

A typical end-to-end session for an agent:

1. **Validate authorization** with the user (the user must own the target
   or hold written authorization). The skill enforces this; for direct
   API use, your prompt must include it explicitly.

2. **Start the scan**:
   ```http
   POST /api/v1/scans
   Content-Type: application/json

   {"target": "example.com", "options": {"wait_seconds": 60}}
   ```

3. **Poll** `GET /api/v1/scans/{guid}` every 5 s until
   `status == "completed"` (or stream `…/events` for live feedback).

4. **Read the report**. Parse the JSON body, or pull the Markdown via
   `GET /api/v1/scans/{guid}/markdown` for direct LLM consumption.

5. **Pick quick wins** — items in `summary.quick_wins` are sorted by ROI.

6. **Detect the user's stack** (Nginx/Apache/Caddy/HAProxy/Cloudflare/
   Express/Spring/IIS). Look at `tech_stack_detected` first; fall back to
   asking the user.

7. **Pull `remediation.snippets[stack]`** from the matching finding and
   propose a copy-paste fix.

8. **Apply or open a PR**. Most agents can edit the relevant config
   (`nginx.conf`, `.htaccess`, `Caddyfile`, `web.config`, `helmet.js`,
   `application.properties`, …) and commit the change.

## Example prompts

**Claude / generic** —

> Scan `example.com` for security misconfigurations and tell me the top
> three things to fix first. My stack is Nginx behind Cloudflare.

The agent will:

1. Confirm authorization.
2. POST `/api/v1/scans` with `wait_seconds: 60`.
3. Poll until completed.
4. List `summary.quick_wins[:3]`.
5. For each, render `remediation.snippets.nginx` and
   `remediation.snippets.cloudflare_dashboard`.

**Cursor agent mode** —

> @websec0 audit my staging deployment, then patch `nginx.conf` to fix
> any HSTS, CSP, and redirect issues you find.

**ChatGPT (custom GPT with the OpenAPI action)** —

> Scan `example.com` and produce a remediation playbook for an Nginx +
> Spring Boot stack.

## Why findings are LLM-ready

A single finding object (excerpted; see [SPEC §6.2](../SPECIFICATIONS.md#62-schéma-dun-finding)
for the full schema):

```json
{
  "id": "TLS-PROTOCOL-LEGACY-TLS10",
  "severity": "high",
  "is_quick_win": true,
  "description": {
    "short": "Server accepts TLS 1.0, deprecated by RFC 8996.",
    "long": "TLS 1.0 (1999) contains structural cryptographic weaknesses (BEAST). Formally deprecated by IETF RFC 8996 in March 2021. Non-compliant with PCI-DSS, NIST SP 800-52 Rev. 2. Modern browsers removed TLS 1.0/1.1 support in 2020-2021. …"
  },
  "evidence": {
    "observed":  { "protocols_enabled": ["TLSv1.0","TLSv1.2","TLSv1.3"] },
    "expected":  { "protocols_enabled": ["TLSv1.2","TLSv1.3"] },
    "raw_excerpt": "ServerHello version: 0x0301 (TLSv1.0)"
  },
  "remediation": {
    "summary": "Disable TLS 1.0 and TLS 1.1; require TLS 1.2 minimum.",
    "snippets": {
      "nginx":      "ssl_protocols TLSv1.2 TLSv1.3;",
      "apache":     "SSLProtocol -all +TLSv1.2 +TLSv1.3",
      "caddy":      "tls { protocols tls1.2 tls1.3 }",
      "cloudflare_dashboard": "SSL/TLS → Edge Certificates → Minimum TLS Version → TLS 1.2"
    },
    "verification": "curl -sI --tls-max 1.0 https://example.com  # expect failure"
  }
}
```

An agent answering "how do I fix this on Nginx?" needs **only this object**.
No external fetch. No hallucination risk.

## Safety rules for agents

The skill at `skills/websec0/SKILL.md` enforces these rules; for direct
API integrations, encode them in your system prompt:

1. Only scan properties the user **owns** or is **authorized** to test.
2. Refuse `.gov`, `.mil`, banking, hospital, and critical-infrastructure
   domains. The server enforces this at the policy layer (`451
   domain_blocklist`); your agent should refuse before posting.
3. WebSec0 is a **passive** scanner. Do not chain it with active
   exploitation tools (sqlmap, nuclei, ffuf, …).
4. Never extract or display secrets if a check happens to surface one
   (e.g. `EXPOSURE-DOTENV` content). Recommend rotation, do not echo.
5. Respect the rate limits (429 = back off; do not retry tighter).

## Output formats per use case

| Agent task | Best format |
|---|---|
| Summarize for the user | Markdown (`GET …/markdown`) |
| File CI ticket / GitHub issue | Markdown |
| Feed GitHub Code Scanning | SARIF (`GET …/sarif`) |
| Function-calling tool result | JSON (`GET …`) |
| Edit a config file | JSON → `findings[i].remediation.snippets[stack]` |

## See also

- [Anthropic Agent Skills](https://www.anthropic.com/engineering/equipping-agents-for-the-real-world-with-agent-skills)
- [`skills/websec0/SKILL.md`](../skills/websec0/SKILL.md) — the shipped skill (Phase 19, WIP)
- [API documentation](./api/) — endpoints and schemas
- [Checks catalog](./checks/) — full list of supported checks
- [SPECIFICATIONS §10 — SKILL.md pour agents IA](../SPECIFICATIONS.md#10-skillmd-pour-agents-ia)
