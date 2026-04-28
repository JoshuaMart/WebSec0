# WebSec0 — TODO

What's left on the road to **0.1.0**. Phases 0 – 21 are largely closed
and live in `git log`; this file tracks only the remaining work.

## Phase 12 — Report engine (last item)

- [ ] Validate the SARIF export against the official OASIS schema in CI
      (deferred — needs a JSON-Schema validator wired into the workflow)

## Phase 14 — Frontend (deferred items)

- [ ] Per-check deep-link page `/checks/{id}` (MVP uses inline expand)
- [ ] Accessibility audit (WCAG 2.1 AA: contrast, keyboard nav)

## Phase 15 — CLI (deferred item)

- [ ] Progress bar (deferred — synchronous mode via `wait_seconds` is
      enough for CI use)

## Phase 18 — Documentation (last item)

- [ ] Screenshots / GIFs in the README

## Phase 19 — Agent skill (deferred items)

- [ ] Test the skill with Claude Code and Cursor (real session)

## Phase 21 — Quality (last item)

- [ ] License audit: `go-licenses` — refuse GPL/AGPL in deps

## Phase 22 — 0.1.0 pre-release

- [ ] Manual walkthrough of every check vs. its check ID — every
      `passed` finding should be intentionally so
- [ ] Security walkthrough (anti-SSRF, blocklist, rate-limit, IP
      anonymisation)
- [ ] Legal walkthrough (ToS / Privacy / Abuse policy in place)
- [ ] OSSF Scorecard score ≥ 7
- [ ] CHANGELOG.md updated with a `0.1.0` section
- [ ] Public demo instance live on `websec0.example`
- [ ] Tag `v0.1.0`, push → goreleaser produces the release
- [ ] Post-release verification: binaries downloadable, Docker image
      pulls, install.sh works, cosign verifies
- [ ] **🎯 Final milestone: 0.1.0 public release**

## Backlog (post-0.1.0, out of MVP scope)

- [ ] HTTP/3 full handshake via `quic-go`
- [ ] Active probes for DROWN / ROBOT / Ticketbleed / Lucky13 / RACCOON
- [ ] Post-quantum readiness (X25519MLKEM768 detection)
- [ ] MCP server `websec0-mcp`
- [ ] Official GitHub Action, GitLab CI template, Jenkins plugin
- [ ] Helm chart for Kubernetes
- [ ] Third-party plugin framework (custom checks contributed by users)
