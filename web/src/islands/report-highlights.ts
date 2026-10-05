import type {
  Severity,
  Status,
  TLSReport,
  HeadersReport,
  CustomFinding,
  ScanResult,
} from './report-types.ts';

export function statusSev(status: Status): Severity {
  if (status === 'pass') return 'good';
  if (status === 'warn') return 'warn';
  if (status === 'fail') return 'bad';
  return 'info';
}

type HighlightSection =
  | 'protocols'
  | 'ciphers'
  | 'certificate'
  | 'vulns'
  | 'headers'
  | 'custom';
type Highlight = {
  title: string;
  body: string;
  level: Severity;
  section?: HighlightSection;
};

function protocolHighlights(tls?: TLSReport): Highlight[] {
  if (!tls) return [];
  const offered = new Set(
    (tls.protocols ?? []).filter((p) => p.offered).map((p) => p.name),
  );
  const out: Highlight[] = [];
  const legacyDisabled = ['SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1'].every(
    (name) =>
      tls.protocols?.some(
        (p) =>
          p.name === name &&
          !p.offered &&
          ['stdlib', 'raw_clienthello'].includes(p.probe),
      ),
  );
  if (
    tls.scan_status !== 'partial_blocked' &&
    offered.has('TLS 1.3') &&
    legacyDisabled
  ) {
    out.push({
      title: 'TLS 1.3 with no legacy fallback',
      body: 'TLS 1.3 is offered; SSLv2, SSLv3, TLS 1.0 and TLS 1.1 were tested and are disabled.',
      level: 'good',
    });
  }
  if (offered.has('SSL 2.0') || offered.has('SSL 3.0')) {
    out.push({
      title: 'Obsolete SSL versions enabled',
      body: 'SSLv2 or SSLv3 is offered. These obsolete protocols cap the TLS grade at F; this observation does not establish exploitability.',
      level: 'bad',
    });
  }
  if (offered.has('TLS 1.0') || offered.has('TLS 1.1')) {
    out.push({
      title: 'Deprecated TLS versions enabled',
      body: 'TLS 1.0 or 1.1 is offered. Disable them to remove the C cap.',
      level: 'warn',
    });
  }
  return out;
}

function cipherHighlights(tls?: TLSReport): Highlight[] {
  if (!tls || !tls.ciphers?.length) return [];
  const out: Highlight[] = [];
  const ciphers = tls.ciphers;

  if (ciphers.every((c) => c.pfs)) {
    out.push({
      title: 'All offered ciphers provide forward secrecy',
      body: 'Every enumerated cipher is marked as providing forward secrecy.',
      level: 'good',
    });
  } else if (ciphers.some((c) => c.name.includes('_RSA_WITH_'))) {
    out.push({
      title: 'RSA key-exchange ciphers offered',
      body: 'Some TLS 1.2 suites use static RSA — no forward secrecy. Drop the TLS_RSA_WITH_* suites.',
      level: 'warn',
    });
  }

  const cbc12 = ciphers.filter(
    (c) => c.protocol === 'TLS 1.2' && c.name.includes('_CBC_'),
  );
  if (cbc12.length) {
    out.push({
      title: 'Legacy CBC modes on TLS 1.2',
      body: `${cbc12.length} CBC-mode cipher${cbc12.length > 1 ? 's are' : ' is'} offered. Prefer AEAD (GCM/ChaCha20-Poly1305) and drop the rest.`,
      level: 'warn',
    });
  }

  const weak = ciphers.filter((c) => c.level === 'bad');
  if (weak.length) {
    const sample = weak
      .slice(0, 3)
      .map((c) => c.name)
      .join(', ');
    const suffix = weak.length > 3 ? ` (+${weak.length - 3} more)` : '';
    out.push({
      title: `${weak.length} weak cipher${weak.length > 1 ? 's' : ''} offered`,
      body: `${sample}${suffix} — RC4/3DES/anon/export-grade suites should be disabled.`,
      level: 'bad',
    });
  }

  if (tls.cipher_preference === 'server') {
    out.push({
      title: 'Server enforces cipher preference',
      body: 'The server selects from the offered cipher suites according to its own preference.',
      level: 'good',
    });
  }
  return out;
}

function certificateHighlights(tls?: TLSReport): Highlight[] {
  if (!tls) return [];
  const chain = tls.certificate_chain ?? [];
  const leaf = chain.find((c) => c.step === 0) ?? chain[0];
  if (!leaf) return [];
  const out: Highlight[] = [];

  if (leaf.days_left < 0) {
    out.push({
      title: 'Leaf certificate has expired',
      body: 'The observed certificate is past its expiry date. Review its replacement and deployment.',
      level: 'bad',
    });
  } else if (leaf.days_left < 7) {
    out.push({
      title: 'Leaf certificate expires within a week',
      body: `Renew immediately — only ${leaf.days_left} day${leaf.days_left === 1 ? '' : 's'} left.`,
      level: 'bad',
    });
  } else if (leaf.days_left < 30) {
    out.push({
      title: 'Leaf certificate expires within 30 days',
      body: `${leaf.days_left} days left — schedule renewal.`,
      level: 'warn',
    });
  }

  if (/ECDSA|Ed25519/i.test(leaf.key_alg)) {
    out.push({
      title: 'Modern key algorithm',
      body: `Leaf certificate uses ${leaf.key_alg} — smaller, faster handshakes than RSA.`,
      level: 'good',
    });
  }
  return out;
}

function trustAndOcspHighlights(tls?: TLSReport): Highlight[] {
  if (!tls) return [];
  const out: Highlight[] = [];

  if (
    ['expired', 'self_signed', 'hostname_mismatch', 'untrusted'].includes(
      tls.chain_trust,
    )
  ) {
    out.push({
      title: 'Certificate chain does not validate',
      body: `Chain trust: ${tls.chain_trust.replace(/_/g, ' ')}. The grade is capped at T.`,
      level: 'bad',
    });
  }

  if (tls.chain_trust === 'no_chain') {
    out.push({
      title: 'Certificate trust not assessed',
      body: 'No certificate chain was captured. Trust could not be established.',
      level: 'info',
    });
  }

  if (tls.ocsp_stapling && tls.ocsp_status === 'good') {
    out.push({
      title: 'OCSP stapling enabled with good status',
      body: 'The server staples a fresh OCSP response — clients do not need to query the CA.',
      level: 'good',
    });
  } else if (tls.ocsp_stapling && tls.ocsp_status === 'revoked') {
    out.push({
      title: 'Stapled OCSP reports the certificate as revoked',
      body: 'Browsers will reject this certificate. Reissue and redeploy immediately.',
      level: 'bad',
    });
  } else if (tls.ocsp_stapling === false) {
    out.push({
      title: 'OCSP stapling not enabled',
      body: 'Clients fall back to querying the CA themselves — adds a privacy and latency cost.',
      level: 'info',
    });
  }

  if (tls.session_resumption === 'supported') {
    out.push({
      title: 'Session resumption supported',
      body: 'Repeat clients skip a full handshake — fewer round-trips and CPU.',
      level: 'good',
    });
  }
  return out;
}

function vulnHighlights(tls?: TLSReport): Highlight[] {
  if (!tls) return [];
  const out: Highlight[] = [];
  const vulns = tls.vulnerabilities ?? [];
  const bad = vulns.filter((v) => v.level === 'bad');
  const warn = vulns.filter((v) => v.level === 'warn');
  if (bad.length) {
    out.push({
      title: `${bad.length} configuration weakness ${bad.length > 1 ? 'findings' : 'finding'}`,
      body: bad.map((v) => v.title || v.id).join(', '),
      level: 'bad',
    });
  }
  if (warn.length) {
    out.push({
      title: `${warn.length} vulnerability caveat${warn.length > 1 ? 's' : ''}`,
      body: warn.map((v) => v.title || v.id).join(', '),
      level: 'warn',
    });
  }
  return out;
}

const coreDescriptions: Record<string, { label: string; fix: string }> = {
  'strict-transport-security': {
    label: 'HSTS',
    fix: 'Use max-age of at least one year and includeSubDomains.',
  },
  'content-security-policy': {
    label: 'Content-Security-Policy',
    fix: 'Review script-src and its default-src fallback to restrict inline scripts.',
  },
  'x-frame-options': {
    label: 'Clickjacking protection',
    fix: 'Configure X-Frame-Options or a restrictive CSP frame-ancestors directive.',
  },
  'x-content-type-options': {
    label: 'X-Content-Type-Options',
    fix: 'Set X-Content-Type-Options to nosniff.',
  },
  'referrer-policy': {
    label: 'Referrer-Policy',
    fix: 'Use a restrictive Referrer-Policy.',
  },
  'permissions-policy': {
    label: 'Permissions-Policy',
    fix: 'Restrict browser APIs with Permissions-Policy.',
  },
};

function headerHighlights(headers?: HeadersReport): Highlight[] {
  if (!headers) return [];
  const out: Highlight[] = [];
  for (const [name, { label, fix }] of Object.entries(coreDescriptions)) {
    const result = headers.core[name];
    if (!result) continue;
    if (result.status === 'pass') {
      out.push({
        title: label,
        body: result.present
          ? 'The configured header passed the scanner’s checks.'
          : 'Protection is provided by the configured policy.',
        level: 'good',
      });
    } else if (result.status === 'warn' || result.status === 'fail') {
      out.push({
        title: label,
        body: fix,
        level: statusSev(result.status),
      });
    }
  }
  const additional = headers.additional;
  for (const name of [
    'cross-origin-opener-policy',
    'cross-origin-embedder-policy',
    'cross-origin-resource-policy',
  ] as const) {
    const result = additional[name];
    if (!result || result.status === 'info') continue;
    out.push({
      title: name,
      body: result.value || 'Review this policy.',
      level: statusSev(result.status),
    });
  }
  if (additional.server?.status === 'warn') {
    out.push({
      title: 'Server header discloses version',
      body: `Server: ${additional.server.value}. Remove the disclosed version.`,
      level: 'warn',
    });
  }
  if (additional['access-control-allow-origin']?.status === 'warn') {
    out.push({
      title: 'Permissive cross-origin policy',
      body: 'Review whether wildcard access is appropriate for this resource.',
      level: 'warn',
    });
  }
  return out;
}

function cookieHighlights(headers?: HeadersReport): Highlight[] {
  const weak = (headers?.additional['set-cookie'] ?? []).filter(
    (c) => c.status === 'warn' || c.status === 'fail',
  );
  if (!weak.length) return [];
  const names = weak
    .slice(0, 2)
    .map((c) => c.name)
    .join(', ');
  const suffix = weak.length > 2 ? ` (+${weak.length - 2} more)` : '';
  return [
    {
      title: `${weak.length} cookie${weak.length > 1 ? 's need' : ' needs'} attention`,
      body: `${names}${suffix} — review Secure, SameSite and HttpOnly where applicable.`,
      level: weak.some((c) => c.status === 'fail') ? 'bad' : 'warn',
    },
  ];
}

function customHighlights(custom?: CustomFinding[]): Highlight[] {
  if (!custom?.length) return [];
  const out: Highlight[] = [];
  for (const f of custom) {
    if (f.status === 'info' && typeof f.details?.note === 'string') {
      out.push({
        title: `${f.title}: not assessed`,
        body: f.details.note,
        level: 'info',
      });
      continue;
    }
    if (f.id === 'custom.security_txt') {
      if (f.status === 'fail') {
        out.push({
          title: 'security.txt missing or unreachable',
          body: 'No usable /.well-known/security.txt — publish one per RFC 9116 so researchers can reach you.',
          level: 'warn',
        });
      } else if (f.status === 'warn') {
        out.push({
          title: 'security.txt is not fully RFC 9116-compliant',
          body: 'The file is reachable but missing required fields (Expires, Contact) or has expired.',
          level: 'info',
        });
      }
    } else if (f.id === 'custom.robots_txt') {
      const susp = Array.isArray(f.details?.suspicious_disallow)
        ? (f.details!.suspicious_disallow as string[])
        : [];
      if (susp.length) {
        const sample = susp.slice(0, 2).join(', ');
        const suffix = susp.length > 2 ? ` (+${susp.length - 2} more)` : '';
        out.push({
          title: `robots.txt discloses ${susp.length} suspicious path${susp.length > 1 ? 's' : ''}`,
          body: `${sample}${suffix} — Disallow entries reveal admin/internal paths to anyone reading robots.txt.`,
          level: 'warn',
        });
      }
    }
  }
  return out;
}

export function deriveHighlights(data: ScanResult): Highlight[] {
  const all: Highlight[] = [
    ...protocolHighlights(data.tls).map((h) => ({
      ...h,
      section: 'protocols' as const,
    })),
    ...cipherHighlights(data.tls).map((h) => ({
      ...h,
      section: 'ciphers' as const,
    })),
    ...certificateHighlights(data.tls).map((h) => ({
      ...h,
      section: 'certificate' as const,
    })),
    ...trustAndOcspHighlights(data.tls).map((h) => ({
      ...h,
      section: 'certificate' as const,
    })),
    ...vulnHighlights(data.tls).map((h) => ({
      ...h,
      section: 'vulns' as const,
    })),
    ...headerHighlights(data.headers).map((h) => ({
      ...h,
      section: 'headers' as const,
    })),
    ...cookieHighlights(data.headers).map((h) => ({
      ...h,
      section: 'headers' as const,
    })),
    ...customHighlights(data.custom).map((h) => ({
      ...h,
      section: 'custom' as const,
    })),
  ];
  const order: Record<Severity, number> = { bad: 0, warn: 1, info: 2, good: 3 };
  all.sort((a, b) => order[a.level] - order[b.level]);
  const top = all.slice(0, 6);
  if (top.length === 0) {
    top.push({
      title:
        !data.tls && !data.headers
          ? 'Assessment unavailable'
          : 'No highlights to display',
      body: 'Review the available observations in each section. Missing data does not establish a passing result.',
      level: 'info',
    });
  }
  return top;
}
