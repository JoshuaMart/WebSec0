# Security policy

## Reporting a vulnerability

If you believe you have found a security issue in WebSec0, please report
it privately via GitHub's "Report a vulnerability" workflow:

**https://github.com/JoshuaMart/WebSec0/security/advisories/new**

This opens a private security advisory only visible to the project
maintainers. Do not open a public issue, pull request, or social-media
post for security reports before a fix is available.

When reporting, please include:

- The affected version or commit SHA.
- A minimal reproduction (configuration, command, request) that
  triggers the issue.
- The impact you observed (what an attacker can read, modify or
  bypass).
- Any mitigations or patches you have already identified.

You can expect:

- An acknowledgement within **5 business days** of submission.
- A status update at least every **10 business days** while the report
  is open.
- A fix or a written rationale within **30 days**. If we cannot meet
  this window, we will explain why and propose a revised timeline.

Once a fix lands, we will publish a GitHub Security Advisory with a
CVE if appropriate and credit the reporter (unless they prefer to
remain anonymous).

## Scope

In scope:

- The WebSec0 binary built from this repository (`cmd/websec0`).
- The HTTP API documented in `SPECIFICATIONS.md` and in
  `skills/websec0/SKILL.md`.
- The static frontend embedded in the binary
  (`internal/frontend/`).
- The `safehttp` security gate (SSRF, IP pinning, DNS rebinding) and
  its documented invariants (SPEC §8).

Out of scope:

- Vulnerabilities in third-party hosts you choose to scan with
  WebSec0 — those are issues with those sites, not with this project.
- Findings that require a malicious operator already running the
  scanner with elevated privileges.
- Denial-of-service via unbounded scan frequency: rate limits are
  documented and configurable (`config.history.rate_limit`); please
  tune your deployment, do not file a report.
- Issues in the documentation or examples that have no security
  impact on the running binary.

## Supported versions

WebSec0 is pre-1.0. Only `main` and the most recent tagged release
receive security fixes. Older tags are best-effort.

## Disclosure of issues affecting WebSec0's own hosted instance

When the project hosts a public WebSec0 instance, it will publish a
`/.well-known/security.txt` pointing back to this policy.
