import type { APIRoute } from 'astro';

export const GET: APIRoute = ({ site }) =>
  new Response(
    `# WebSec0

> WebSec0 is an open-source web-security scanner that reports TLS configuration, HTTP security headers and informational custom and email DNS observations.

TLS and HTTP headers receive separate grades. Custom findings, certificate transparency observations and email DNS checks do not affect those grades. Missing or unassessed observations do not establish that a security check passed.

Reports are configuration assessments, not proof of exploitability or a guarantee that a website is safe. Public-history listing is opt-in; unlisted reports remain accessible to anyone with their link while cached.

## Website

- [WebSec0](${new URL('/', site).href}): Scanner homepage.

## Documentation

- [Project overview](https://raw.githubusercontent.com/JoshuaMart/WebSec0/main/README.md): Features, setup and deployment.
- [WebSec0 agent skill](https://raw.githubusercontent.com/JoshuaMart/WebSec0/main/skills/websec0/SKILL.md): Scope, instance selection and report interpretation workflow.
- [API contract](https://raw.githubusercontent.com/JoshuaMart/WebSec0/main/skills/websec0/references/api.md): Request fields, response envelopes and errors.
- [Report interpretation](https://raw.githubusercontent.com/JoshuaMart/WebSec0/main/skills/websec0/references/interpretation.md): Grades, findings and remediation guidance.
- [Email observations](https://raw.githubusercontent.com/JoshuaMart/WebSec0/main/skills/websec0/references/email.md): SPF and DMARC results and limitations.
`,
    { headers: { 'Content-Type': 'text/plain; charset=utf-8' } },
  );
