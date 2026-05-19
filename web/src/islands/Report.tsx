/**
 * Report island — Preact component mounted at /r/{id}. Reads the scan ID
 * from window.location.pathname, fetches /api/v1/scan/{id} and renders
 * the result with seven tabs.
 *
 * Types mirror internal/scan/types.go. We keep them inline (rather than
 * pulling a shared module) to keep the bundle compact.
 */

import { useEffect, useMemo, useRef, useState } from 'preact/hooks';

// ────────────────────────────────────────────────────────────────────────────
// Types

type Grade = 'A+' | 'A' | 'B' | 'C' | 'D' | 'E' | 'F' | 'T' | '';
type Status = 'pass' | 'fail' | 'warn' | 'info' | '';
type Severity = 'good' | 'warn' | 'bad' | 'info';

type ProtocolSupport = { name: string; offered: boolean; probe: string };
type Cipher = {
  protocol: string;
  name: string;
  code: string;
  strength: number;
  aead: boolean;
  pfs: boolean;
  level: Severity;
};
type Certificate = {
  step: number;
  kind: string;
  cn: string;
  issuer: string;
  not_before: string;
  not_after: string;
  days_left: number;
  key_alg: string;
  sig_alg: string;
  serial: string;
  sha256: string;
  san: string[];
  revocation: string;
};
type Vuln = {
  id: string;
  title: string;
  cve?: string;
  state: string;
  level: Severity;
  body: string;
};
type HeaderResult = { present: boolean; value?: string; status: Status };
type CookieResult = {
  name: string;
  secure: boolean;
  httponly: boolean;
  samesite: string | null;
  status: Status;
};
type TLSReport = {
  grade: Grade;
  scores: {
    certificate: number;
    protocol_support: number;
    key_exchange: number;
    cipher_strength: number;
    final: number;
  };
  protocols: ProtocolSupport[];
  ciphers: Cipher[];
  cipher_preference?: 'server' | 'client' | '';
  certificate_chain: Certificate[];
  chain_trust: string;
  ocsp_stapling: boolean;
  ocsp_status?: string;
  session_resumption?: string;
  vulnerabilities: Vuln[];
};
type HeadersReport = {
  grade: Grade;
  score: number;
  core: Record<string, HeaderResult>;
  additional: {
    server?: HeaderResult;
    'set-cookie'?: CookieResult[];
    'access-control-allow-origin'?: HeaderResult;
    'cross-origin-opener-policy'?: HeaderResult;
    'cross-origin-embedder-policy'?: HeaderResult;
    'cross-origin-resource-policy'?: HeaderResult;
  };
  probed_host?: string;
};
type CustomFinding = {
  id: string;
  title: string;
  status: Status;
  details?: Record<string, unknown>;
};
type ScanResult = {
  id: string;
  host: string;
  port: number;
  resolved_ip: string;
  scanned_at: string;
  duration_ms: number;
  tls?: TLSReport;
  headers?: HeadersReport;
  custom?: CustomFinding[];
};

// ────────────────────────────────────────────────────────────────────────────
// Tiny utilities

function statusSev(status: Status): Severity {
  if (status === 'pass') return 'good';
  if (status === 'warn') return 'warn';
  if (status === 'fail') return 'bad';
  return 'info';
}

function sevLabel(level: Severity): string {
  if (level === 'good') return 'Pass';
  if (level === 'warn') return 'Warn';
  if (level === 'bad') return 'Fail';
  return 'Info';
}

function SevPill({ level }: { level: Severity }) {
  return (
    <span class={`pill ${level}`}>
      <span class="dot" />
      {sevLabel(level)}
    </span>
  );
}

function fmtDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return iso;
  }
}

function fmtDuration(ms: number): string {
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(1)} s`;
}

function scanIDFromPath(): string {
  const m = location.pathname.match(/^\/r\/([^/?#]+)/);
  return m ? decodeURIComponent(m[1]) : '';
}

// ────────────────────────────────────────────────────────────────────────────
// Top-level component

export default function Report() {
  const [data, setData] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<TabId>('overview');

  useEffect(() => {
    const id = scanIDFromPath();
    if (!id) {
      setError('No scan ID in URL');
      return;
    }
    fetch(`/api/v1/scan/${encodeURIComponent(id)}`)
      .then(async (r) => {
        if (r.ok) return r.json();
        const body = await r.json().catch(() => ({}));
        throw new Error(body?.error?.message ?? `HTTP ${r.status}`);
      })
      .then((r) => setData(r as ScanResult))
      .catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)));
  }, []);

  if (error) return <ErrorState message={error} />;
  if (!data) return <LoadingState />;

  return (
    <div>
      <Crumbs host={data.host} />
      <Header data={data} />
      <GradePanel data={data} />
      <Tabs active={tab} onChange={setTab} data={data} />
      <TabPanel id={tab} data={data} />
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────────────
// Header + grade panel

function Crumbs({ host }: { host: string }) {
  return (
    <div class="crumbs">
      <a href="/" style={{ color: 'inherit', textDecoration: 'none' }}>
        scans
      </a>
      <span class="sep">/</span>
      <span class="ink2">{host}</span>
    </div>
  );
}

function Header({ data }: { data: ScanResult }) {
  return (
    <div class="header">
      <div>
        <h1 class="h-title">
          <span class="scheme">https://</span>
          {data.host}
          <TrustPill trust={data.tls?.chain_trust} />
        </h1>
        <div class="h-meta">
          <div>
            <span class="k">IP</span>
            <span class="v">{data.resolved_ip || '—'}</span>
          </div>
          <div>
            <span class="k">Port</span>
            <span class="v">{data.port}</span>
          </div>
          <div>
            <span class="k">Tested</span>
            <span class="v">{fmtDate(data.scanned_at)}</span>
          </div>
          <div>
            <span class="k">Duration</span>
            <span class="v">{fmtDuration(data.duration_ms)}</span>
          </div>
        </div>
      </div>
    </div>
  );
}

function TrustPill({ trust }: { trust?: string }) {
  if (!trust || trust === '') return null;
  if (trust === 'trusted')
    return (
      <span class="pill good">
        <span class="dot" />
        Trusted
      </span>
    );
  if (trust === 'expired')
    return (
      <span class="pill bad">
        <span class="dot" />
        Expired
      </span>
    );
  if (trust === 'self_signed')
    return (
      <span class="pill bad">
        <span class="dot" />
        Self-signed
      </span>
    );
  if (trust === 'hostname_mismatch')
    return (
      <span class="pill bad">
        <span class="dot" />
        Hostname mismatch
      </span>
    );
  return (
    <span class="pill bad">
      <span class="dot" />
      Untrusted
    </span>
  );
}

function GradePanel({ data }: { data: ScanResult }) {
  const tlsGrade = data.tls?.grade ?? '';
  const tlsScore = data.tls?.scores.final ?? 0;
  const headersGrade = data.headers?.grade ?? '';
  const headersScore = data.headers?.score ?? 0;
  return (
    <div class="grade-panel grade-panel-two">
      <div class="grade-cell">
        <GradeCard
          label="TLS grade"
          grade={tlsGrade}
          score={tlsScore}
          sub={prettyTrust(data.tls?.chain_trust)}
        />
        {data.tls && (
          <div class="score-list" style={{ marginTop: 24 }}>
            <ScoreBar name="Certificate" value={data.tls.scores.certificate} />
            <ScoreBar name="Protocol support" value={data.tls.scores.protocol_support} />
            <ScoreBar name="Key exchange" value={data.tls.scores.key_exchange} />
            <ScoreBar name="Cipher strength" value={data.tls.scores.cipher_strength} />
          </div>
        )}
      </div>
      <div class="grade-cell">
        <GradeCard
          label="Headers grade"
          grade={headersGrade}
          score={headersScore}
          sub={
            data.headers?.probed_host
              ? `${headersScore}/100 · via ${data.headers.probed_host}`
              : `${headersScore}/100`
          }
        />
        {data.headers && (
          <div class="score-list" style={{ marginTop: 24 }}>
            {Object.entries(data.headers.core).map(([name, r]) => (
              <ScoreBar
                key={name}
                name={prettyHeader(name)}
                value={r.status === 'pass' ? 100 : r.status === 'warn' ? 50 : 0}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function GradeCard({
  label,
  grade,
  score,
  sub,
}: {
  label: string;
  grade: string;
  score: number;
  sub: string;
}) {
  return (
    <div style={{ display: 'grid', placeItems: 'center', padding: '8px 0 4px' }}>
      <GradeRing grade={grade} score={score} />
      <div class="grade-label">{label}</div>
      <div class="grade-sub">{sub || ''}</div>
    </div>
  );
}

// GradeRing renders the maquette's SVG ring: a dark inner disc, a faint
// background circle, an arc whose length scales with the score, and the
// grade letter centred. The ring colour comes from the grade letter
// (good for A/A+, warn for B/C, bad below) — independent of the score
// so a chain-trust-capped scan stays visually consistent.
function GradeRing({ grade, score }: { grade: string; score: number }) {
  const r = 70;
  const c = 2 * Math.PI * r;
  const pct = Math.max(0.02, Math.min(1, (score || 0) / 100));
  const visible = c * pct;
  const color = gradeColorVar(grade);
  const showGrade = grade || '—';
  return (
    <svg viewBox="0 0 168 168" width="132" height="132" aria-label={`Grade ${showGrade}`}>
      <circle cx="84" cy="84" r={r} fill="var(--ink)" />
      <circle cx="84" cy="84" r={r} fill="none" stroke="var(--line)" stroke-width="6" />
      <circle
        cx="84"
        cy="84"
        r={r}
        fill="none"
        stroke={color}
        stroke-width="6"
        stroke-linecap="round"
        stroke-dasharray={`${visible} ${c}`}
        transform="rotate(-90 84 84)"
      />
      <text
        x="84"
        y="98"
        text-anchor="middle"
        fill="white"
        font-family="var(--font-mono)"
        font-weight="600"
        font-size="44"
        letter-spacing="-0.02em"
      >
        {showGrade}
      </text>
    </svg>
  );
}

function gradeColorVar(grade: string): string {
  if (grade === 'A+' || grade === 'A') return 'var(--good)';
  if (grade === 'B' || grade === 'C') return 'var(--warn)';
  return 'var(--bad)';
}

function prettyTrust(trust?: string): string {
  if (!trust) return '';
  if (trust === 'trusted') return 'Browser-trusted';
  return trust.replace(/_/g, ' ');
}

function ScoreBar({ name, value }: { name: string; value: number }) {
  const level = value >= 80 ? 'good' : value >= 50 ? 'warn' : 'bad';
  return (
    <div class="score-row">
      <div class="name">{name}</div>
      <div class={`bar ${level}`}>
        <span style={{ width: `${Math.max(0, Math.min(100, value))}%` }} />
      </div>
      <div class="val">{value}/100</div>
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────────────
// Tabs

type TabId =
  | 'overview'
  | 'certificate'
  | 'protocols'
  | 'ciphers'
  | 'headers'
  | 'vulns'
  | 'custom';

function Tabs({
  active,
  onChange,
  data,
}: {
  active: TabId;
  onChange: (t: TabId) => void;
  data: ScanResult;
}) {
  const tabs: { id: TabId; label: string; count?: number }[] = [
    { id: 'overview', label: 'Overview' },
    {
      id: 'certificate',
      label: 'Certificate',
      count: data.tls?.certificate_chain?.length,
    },
    {
      id: 'protocols',
      label: 'Protocols',
      count: data.tls?.protocols?.filter((p) => p.offered).length,
    },
    {
      id: 'ciphers',
      label: 'Ciphers',
      count: data.tls?.ciphers?.length,
    },
    { id: 'headers', label: 'Headers' },
    {
      id: 'vulns',
      label: 'Vulnerabilities',
      count: data.tls?.vulnerabilities?.length,
    },
    { id: 'custom', label: 'Custom', count: data.custom?.length },
  ];
  return (
    <div class="tabs" role="tablist">
      {tabs.map((t) => (
        <button
          key={t.id}
          class={'tab' + (active === t.id ? ' active' : '')}
          onClick={() => onChange(t.id)}
        >
          {t.label}
          {t.count != null && <span class="count">{t.count}</span>}
        </button>
      ))}
    </div>
  );
}

function TabPanel({ id, data }: { id: TabId; data: ScanResult }) {
  switch (id) {
    case 'overview':
      return <Overview data={data} />;
    case 'certificate':
      return <CertificateTab chain={data.tls?.certificate_chain ?? []} />;
    case 'protocols':
      return <ProtocolsTab protocols={data.tls?.protocols ?? []} />;
    case 'ciphers':
      return <CiphersTab ciphers={data.tls?.ciphers ?? []} pref={data.tls?.cipher_preference} />;
    case 'headers':
      return <HeadersTab headers={data.headers} />;
    case 'vulns':
      return <VulnsTab vulns={data.tls?.vulnerabilities ?? []} />;
    case 'custom':
      return <CustomTab findings={data.custom ?? []} />;
  }
}

// ────────────────────────────────────────────────────────────────────────────
// Overview

function Overview({ data }: { data: ScanResult }) {
  const tls = data.tls;
  const headers = data.headers;
  const offeredProtos = (tls?.protocols ?? []).filter((p) => p.offered).map((p) => p.name);
  const leaf = tls?.certificate_chain?.[0];
  const highlights = deriveHighlights(data);
  return (
    <div class="section">
      <div class="grid-2">
        <div class="card">
          <div class="card-head">
            <h3>Highlights</h3>
            <span class="sub">{highlights.length} findings</span>
          </div>
          <div class="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {highlights.map((h, i) => (
              <div
                key={i}
                style={{
                  display: 'grid',
                  gridTemplateColumns: '14px 1fr',
                  gap: 12,
                  alignItems: 'flex-start',
                  paddingTop: i ? 12 : 0,
                  borderTop: i ? '1px dashed var(--line)' : 'none',
                }}
              >
                <span class={`sev ${h.level}`} style={{ marginTop: 6 }} />
                <div>
                  <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 2 }}>{h.title}</div>
                  <div style={{ fontSize: 12.5, color: 'var(--muted)' }}>{h.body}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
        <div class="card">
          <div class="card-head">
            <h3>At a glance</h3>
          </div>
          <div class="card-body" style={{ padding: 0 }}>
            <div class="kv-grid" style={{ padding: '0 18px 16px' }}>
              <div class="k">Host</div>
              <div class="v">{data.host}</div>
              <div class="k">Resolved IP</div>
              <div class="v">{data.resolved_ip}</div>
              <div class="k">Port</div>
              <div class="v">{data.port}</div>
              <div class="k">TLS versions</div>
              <div class="v">{offeredProtos.join(', ') || '—'}</div>
              <div class="k">Cipher count</div>
              <div class="v">{tls?.ciphers?.length ?? 0} offered</div>
              <div class="k">Cipher preference</div>
              <div class="v">{tls?.cipher_preference || '—'}</div>
              <div class="k">OCSP stapling</div>
              <div class="v">
                {tls?.ocsp_stapling ? `yes (${tls.ocsp_status || 'unknown'})` : 'no'}
              </div>
              <div class="k">Session resumption</div>
              <div class="v">{tls?.session_resumption || '—'}</div>
              {leaf && (
                <>
                  <div class="k">Certificate</div>
                  <div class="v">
                    {leaf.key_alg} · {leaf.sig_alg}
                  </div>
                  <div class="k">Expires in</div>
                  <div class="v">
                    {leaf.days_left} days · {leaf.not_after.slice(0, 10)}
                  </div>
                </>
              )}
              {headers && (
                <>
                  <div class="k">Headers score</div>
                  <div class="v">
                    {headers.score}/100 ({headers.grade})
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

type Highlight = { title: string; body: string; level: Severity };

function parseMaxAge(value: string): number | null {
  const m = value.match(/max-age\s*=\s*"?(\d+)"?/i);
  return m ? Number(m[1]) : null;
}

function protocolHighlights(tls?: TLSReport): Highlight[] {
  if (!tls) return [];
  const offered = new Set((tls.protocols ?? []).filter((p) => p.offered).map((p) => p.name));
  const out: Highlight[] = [];
  if (offered.has('TLS 1.3') && !offered.has('TLS 1.0') && !offered.has('TLS 1.1')) {
    out.push({
      title: 'TLS 1.3 with no legacy fallback',
      body: 'Only TLS 1.2 and 1.3 are offered. Legacy protocols (1.0/1.1) are disabled.',
      level: 'good',
    });
  }
  if (offered.has('SSL 2.0') || offered.has('SSL 3.0')) {
    out.push({
      title: 'Obsolete SSL versions enabled',
      body: 'SSLv2 or SSLv3 is enabled — POODLE/DROWN are exploitable.',
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
      body: 'Every cipher uses ECDHE/DHE — past sessions stay safe even if the private key is compromised.',
      level: 'good',
    });
  } else if (ciphers.some((c) => c.name.includes('_RSA_WITH_'))) {
    out.push({
      title: 'Caveat: RSA key-exchange ciphers offered',
      body: 'Some TLS 1.2 suites use static RSA — no forward secrecy. Drop the TLS_RSA_WITH_* suites.',
      level: 'warn',
    });
  }

  const cbc12 = ciphers.filter((c) => c.protocol === 'TLS 1.2' && !c.aead);
  if (cbc12.length) {
    out.push({
      title: 'Caveat: legacy CBC modes on TLS 1.2',
      body: `${cbc12.length} CBC-mode cipher${cbc12.length > 1 ? 's are' : ' is'} offered. Prefer AEAD (GCM/ChaCha20-Poly1305) and drop the rest.`,
      level: 'warn',
    });
  }

  const weak = ciphers.filter((c) => c.level === 'bad');
  if (weak.length) {
    const sample = weak.slice(0, 3).map((c) => c.name).join(', ');
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
      body: 'The server picks the cipher instead of trusting the client list — prevents downgrade games.',
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

  if (leaf.days_left < 7) {
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

  if (tls.chain_trust && tls.chain_trust !== 'trusted') {
    out.push({
      title: 'Certificate chain does not validate',
      body: `Chain trust: ${tls.chain_trust.replace(/_/g, ' ')}. The grade is capped at T.`,
      level: 'bad',
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
      title: `${bad.length} active vulnerability ${bad.length > 1 ? 'findings' : 'finding'}`,
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

function headerHighlights(headers?: HeadersReport): Highlight[] {
  if (!headers) return [];
  const core = headers.core;
  const out: Highlight[] = [];

  const hsts = core['strict-transport-security'];
  if (!hsts?.present) {
    out.push({
      title: 'HSTS not set',
      body: 'No Strict-Transport-Security header — first visit can still be downgraded to HTTP.',
      level: 'bad',
    });
  } else {
    const value = hsts.value ?? '';
    const age = parseMaxAge(value);
    const subs = /includeSubDomains/i.test(value);
    const preload = /preload/i.test(value);
    const sixMonths = 60 * 60 * 24 * 180;
    const oneYear = 60 * 60 * 24 * 365;
    if (age === null || age < sixMonths) {
      out.push({
        title: 'HSTS max-age too short',
        body: `max-age=${age ?? '0'} — set at least 6 months (15768000) for any real protection.`,
        level: 'warn',
      });
    } else if (age >= oneYear && subs && preload) {
      const years = Math.round((age / (60 * 60 * 24 * 365)) * 10) / 10;
      out.push({
        title: `HSTS preloaded with ${years}-year max-age`,
        body: 'Strict-Transport-Security includes includeSubDomains and preload; eligible for the HSTS Preload List.',
        level: 'good',
      });
    } else if (!subs) {
      out.push({
        title: 'HSTS missing includeSubDomains',
        body: 'Subdomains can still negotiate plain HTTP. Add includeSubDomains, then preload.',
        level: 'info',
      });
    }
  }

  const csp = core['content-security-policy'];
  if (!csp?.present) {
    out.push({
      title: 'No Content-Security-Policy',
      body: 'CSP is missing — clients have no inline-script or origin restrictions.',
      level: 'warn',
    });
  } else {
    const v = csp.value ?? '';
    if (/'unsafe-inline'|'unsafe-eval'/i.test(v) || /(script-src|default-src)[^;]*\*\b/i.test(v)) {
      out.push({
        title: "CSP allows 'unsafe-inline' or wildcard sources",
        body: 'A permissive CSP barely raises the bar against XSS. Tighten script-src to nonces or hashes.',
        level: 'warn',
      });
    } else {
      out.push({
        title: 'Content-Security-Policy in place',
        body: 'CSP is set without unsafe-inline or wildcard script sources.',
        level: 'good',
      });
    }
  }

  const xfo = core['x-frame-options'];
  const cspV = csp?.value ?? '';
  if (!xfo?.present && !/frame-ancestors/i.test(cspV)) {
    out.push({
      title: 'Clickjacking defence missing',
      body: 'No X-Frame-Options and no CSP frame-ancestors — the page can be framed.',
      level: 'warn',
    });
  }

  const xcto = core['x-content-type-options'];
  if (!xcto?.present || !/nosniff/i.test(xcto.value ?? '')) {
    out.push({
      title: 'X-Content-Type-Options missing nosniff',
      body: 'Browsers may MIME-sniff responses, enabling some XSS vectors.',
      level: 'warn',
    });
  }

  if (!core['referrer-policy']?.present) {
    out.push({
      title: 'No Referrer-Policy',
      body: 'Referrer leakage falls back to the browser default — set no-referrer or strict-origin.',
      level: 'info',
    });
  }

  if (!core['permissions-policy']?.present) {
    out.push({
      title: 'No Permissions-Policy',
      body: 'Powerful APIs (camera, geolocation, etc.) are not scoped — at least opt out of what you do not use.',
      level: 'info',
    });
  }

  if (headers.additional['cross-origin-opener-policy']?.present) {
    out.push({
      title: 'Cross-Origin-Opener-Policy set',
      body: 'COOP isolates browsing contexts — blocks Spectre-style cross-origin leaks.',
      level: 'good',
    });
  }

  const server = headers.additional.server;
  if (server?.present && /\d/.test(server.value ?? '')) {
    out.push({
      title: 'Server header discloses version',
      body: `Server: ${server.value}. Strip the version to avoid handing attackers a fingerprint.`,
      level: 'warn',
    });
  }

  return out;
}

function cookieHighlights(headers?: HeadersReport): Highlight[] {
  if (!headers) return [];
  const cookies = headers.additional['set-cookie'] ?? [];
  const weak = cookies.filter((c) => !c.secure || !c.httponly);
  if (!weak.length) return [];
  const names = weak.slice(0, 2).map((c) => c.name).join(', ');
  const suffix = weak.length > 2 ? ` (+${weak.length - 2} more)` : '';
  return [
    {
      title: `${weak.length} cookie${weak.length > 1 ? 's' : ''} missing Secure/HttpOnly`,
      body: `${names}${suffix} — add the Secure and HttpOnly flags on every session cookie.`,
      level: 'warn',
    },
  ];
}

function customHighlights(custom?: CustomFinding[]): Highlight[] {
  if (!custom?.length) return [];
  const out: Highlight[] = [];
  for (const f of custom) {
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

function deriveHighlights(data: ScanResult): Highlight[] {
  const all = [
    ...protocolHighlights(data.tls),
    ...cipherHighlights(data.tls),
    ...certificateHighlights(data.tls),
    ...trustAndOcspHighlights(data.tls),
    ...vulnHighlights(data.tls),
    ...headerHighlights(data.headers),
    ...cookieHighlights(data.headers),
    ...customHighlights(data.custom),
  ];
  const order: Record<Severity, number> = { bad: 0, warn: 1, info: 2, good: 3 };
  all.sort((a, b) => order[a.level] - order[b.level]);
  const top = all.slice(0, 6);
  if (top.length === 0) {
    top.push({
      title: 'No notable findings yet',
      body: 'The scan completed without highlights to surface.',
      level: 'info',
    });
  }
  return top;
}

// ────────────────────────────────────────────────────────────────────────────
// Certificate tab

function CertificateTab({ chain }: { chain: Certificate[] }) {
  const [open, setOpen] = useState<Record<number, boolean>>({ 0: true });
  if (!chain.length) return <EmptyCard message="No certificate chain captured." />;
  return (
    <div class="card">
      <div class="card-head">
        <h3>
          Certification path <span class="sub">· {chain.length} certificates</span>
        </h3>
      </div>
      <div class="card-body flush chain">
        {chain.map((c, i) => {
          const isOpen = !!open[i];
          return (
            <div key={i} class={'cert-node' + (isOpen ? ' open' : '')}>
              <div
                class="cert-head"
                onClick={() => setOpen({ ...open, [i]: !isOpen })}
              >
                <span class="cert-step">{c.step}</span>
                <div class="cert-info">
                  <div class="cert-cn">{c.cn || '(no CN)'}</div>
                  <div class="cert-sub">
                    {c.kind} · issued by {c.issuer || '—'}
                  </div>
                </div>
                <div class="cert-meta">
                  <span class="pill">
                    <span class="dot" style={{ background: 'var(--muted-2)' }} />
                    {c.key_alg.split(' ')[0] || c.key_alg}
                  </span>
                  {c.days_left < 0 ? (
                    <span class="pill bad">
                      <span class="dot" />
                      Expired
                    </span>
                  ) : c.days_left < 30 ? (
                    <span class="pill warn">
                      <span class="dot" />
                      Expires in {c.days_left}d
                    </span>
                  ) : (
                    <span class="pill good">
                      <span class="dot" />
                      Valid {c.days_left}d
                    </span>
                  )}
                  <svg
                    class="caret"
                    viewBox="0 0 16 16"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="1.5"
                  >
                    <path d="M6 4l4 4-4 4" />
                  </svg>
                </div>
              </div>
              {isOpen && (
                <div class="cert-body">
                  <div class="k">Subject CN</div>
                  <div class="v">{c.cn || '—'}</div>
                  <div class="k">Issuer</div>
                  <div class="v">{c.issuer || '—'}</div>
                  <div class="k">Valid from</div>
                  <div class="v">{c.not_before.slice(0, 10)}</div>
                  <div class="k">Valid until</div>
                  <div class="v">{c.not_after.slice(0, 10)}</div>
                  <div class="k">Key algorithm</div>
                  <div class="v">{c.key_alg}</div>
                  <div class="k">Signature algorithm</div>
                  <div class="v">{c.sig_alg}</div>
                  <div class="k">Serial</div>
                  <div class="v">{c.serial}</div>
                  <div class="k">SHA-256 fingerprint</div>
                  <div class="v" style={{ fontSize: 11.5 }}>
                    {c.sha256}
                  </div>
                  <div class="k">SAN</div>
                  <div class="v">{c.san.join(', ')}</div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────────────
// Protocols, Ciphers, Headers, Vulns, Custom tabs

function ProtocolsTab({ protocols }: { protocols: ProtocolSupport[] }) {
  if (!protocols.length) return <EmptyCard message="No protocols enumerated." />;
  const offered = protocols.filter((p) => p.offered).length;
  return (
    <div class="card">
      <div class="card-head">
        <h3>Protocol support</h3>
        <span class="sub">
          {offered} offered · {protocols.length - offered} disabled
        </span>
      </div>
      <div class="card-body flush">
        <div class="proto-list">
          {protocols.map((p) => (
            <div key={p.name} class="proto-row">
              <div class="proto-name">
                <b>{p.name}</b>
                <span>via {p.probe}</span>
              </div>
              {p.offered ? (
                <span class="pill good">
                  <span class="dot" />
                  Offered
                </span>
              ) : (
                <span class="pill">
                  <span class="dot" style={{ background: 'var(--muted-2)' }} />
                  Disabled
                </span>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function CiphersTab({
  ciphers,
  pref,
}: {
  ciphers: Cipher[];
  pref?: 'server' | 'client' | '';
}) {
  const [tooltip, setTooltip] = useState<
    | {
        x: number;
        y: number;
        c: Cipher;
        parsed: ReturnType<typeof parseCipherName>;
      }
    | null
  >(null);
  const wrapRef = useRef<HTMLDivElement>(null);

  if (!ciphers.length) return <EmptyCard message="No ciphers enumerated." />;
  const grouped = useMemo(() => {
    const g: Record<string, Cipher[]> = {};
    for (const c of ciphers) (g[c.protocol] ??= []).push(c);
    return g;
  }, [ciphers]);

  function onMove(e: MouseEvent, c: Cipher) {
    const rect = wrapRef.current?.getBoundingClientRect();
    if (!rect) return;
    setTooltip({
      x: e.clientX - rect.left + 14,
      y: e.clientY - rect.top + 14,
      c,
      parsed: parseCipherName(c.name),
    });
  }

  return (
    <div class="card" ref={wrapRef} style={{ position: 'relative' }}>
      <div class="card-head">
        <h3>
          Cipher suites{' '}
          <span class="sub">
            · {pref ? `${pref} preference` : 'preference unknown'} · forward secrecy required
          </span>
        </h3>
        <span class="muted" style={{ fontSize: 12 }}>Hover for details</span>
      </div>
      <div class="card-body flush">
        {Object.entries(grouped).map(([proto, list]) => (
          <div key={proto}>
            <div
              style={{
                padding: '10px 18px',
                fontFamily: 'var(--font-mono)',
                fontSize: 11,
                letterSpacing: '0.06em',
                textTransform: 'uppercase',
                color: 'var(--muted)',
                background: 'var(--bg-sub)',
                borderTop: '1px solid var(--line)',
                borderBottom: '1px solid var(--line)',
              }}
            >
              {proto} · {list.length} suites
            </div>
            <table class="tbl">
              <tbody>
                {list.map((c) => (
                  <tr
                    key={c.code}
                    class="hoverable cipher-row"
                    onMouseMove={(e) => onMove(e, c)}
                    onMouseLeave={() => setTooltip(null)}
                  >
                    <td>
                      <span class={`sev ${c.level}`} />
                    </td>
                    <td class="cipher-name">
                      {c.name}
                      <span class="small">{c.code}</span>
                    </td>
                    <td class="mono" style={{ textAlign: 'right', width: 80 }}>
                      {c.strength} bit
                    </td>
                    <td style={{ width: 100 }}>
                      {c.aead ? (
                        <span class="pill good">
                          <span class="dot" />
                          AEAD
                        </span>
                      ) : (
                        <span class="pill warn">
                          <span class="dot" />
                          CBC
                        </span>
                      )}
                    </td>
                    <td style={{ width: 96 }}>
                      {c.pfs ? (
                        <span class="pill good">
                          <span class="dot" />
                          PFS
                        </span>
                      ) : (
                        <span class="pill bad">
                          <span class="dot" />
                          No PFS
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ))}
      </div>
      {tooltip && (
        <div class="tt" style={{ left: tooltip.x, top: tooltip.y }}>
          <h5>
            {tooltip.c.code} · {tooltip.c.protocol}
          </h5>
          <p style={{ marginBottom: 8 }}>{tooltip.c.name}</p>
          <div class="row">
            <span class="k">Key exchange</span>
            <span class="v">{tooltip.parsed.kx}</span>
          </div>
          <div class="row">
            <span class="k">Authentication</span>
            <span class="v">{tooltip.parsed.auth}</span>
          </div>
          <div class="row">
            <span class="k">Cipher</span>
            <span class="v">{tooltip.parsed.cipher}</span>
          </div>
          <div class="row">
            <span class="k">MAC</span>
            <span class="v">{tooltip.parsed.mac}</span>
          </div>
          <div class="row">
            <span class="k">Strength</span>
            <span class="v">{tooltip.c.strength} bits</span>
          </div>
        </div>
      )}
    </div>
  );
}

// parseCipherName derives the canonical components (key exchange,
// authentication, bulk cipher, MAC) from an IANA-style suite name.
// TLS 1.3 names omit KX/auth (always (EC)DHE/AEAD), so we fill the gap.
function parseCipherName(name: string): { kx: string; auth: string; cipher: string; mac: string } {
  // TLS 1.3 names like TLS_AES_256_GCM_SHA384 lack the _WITH_ pivot.
  if (!name.includes('_WITH_')) {
    let cipher = '—';
    if (name.includes('CHACHA20')) cipher = 'ChaCha20-Poly1305';
    else if (name.includes('AES_256_GCM')) cipher = 'AES-256-GCM';
    else if (name.includes('AES_128_GCM')) cipher = 'AES-128-GCM';
    else if (name.includes('AES_128_CCM')) cipher = 'AES-128-CCM';
    return { kx: '(EC)DHE', auth: 'signed via cert', cipher, mac: 'AEAD' };
  }
  const [pre, post] = name.replace(/^TLS_/, '').split('_WITH_');
  if (!post) return { kx: '?', auth: '?', cipher: '?', mac: '?' };
  let kx = pre;
  let auth = pre;
  if (pre.includes('_')) {
    const parts = pre.split('_');
    kx = parts.slice(0, -1).join('-');
    auth = parts[parts.length - 1];
  }
  const aead = post.includes('GCM') || post.includes('CHACHA20') || post.includes('POLY1305');
  let cipher = '—';
  if (post.startsWith('AES_256_GCM')) cipher = 'AES-256-GCM';
  else if (post.startsWith('AES_128_GCM')) cipher = 'AES-128-GCM';
  else if (post.startsWith('CHACHA20')) cipher = 'ChaCha20-Poly1305';
  else if (post.includes('AES_256_CBC')) cipher = 'AES-256-CBC';
  else if (post.includes('AES_128_CBC')) cipher = 'AES-128-CBC';
  else if (post.includes('3DES')) cipher = '3DES-EDE-CBC';
  else if (post.includes('RC4')) cipher = 'RC4-128';
  let mac = aead ? 'AEAD' : 'HMAC';
  if (!aead) {
    if (post.endsWith('SHA384')) mac = 'HMAC-SHA384';
    else if (post.endsWith('SHA256')) mac = 'HMAC-SHA256';
    else if (post.endsWith('SHA')) mac = 'HMAC-SHA1';
    else if (post.endsWith('MD5')) mac = 'HMAC-MD5';
  }
  return { kx, auth, cipher, mac };
}

function HeadersTab({ headers }: { headers?: HeadersReport }) {
  if (!headers) return <EmptyCard message="Headers probe did not complete." />;
  return (
    <div class="section">
      <div class="card">
        <div class="card-head">
          <h3>Core headers</h3>
          <span class="sub">
            Score {headers.score}/100 · Grade {headers.grade}
          </span>
        </div>
        <div class="card-body" style={{ padding: 0 }}>
          <table class="tbl">
            <tbody>
              {Object.entries(headers.core).map(([name, r]) => (
                <tr key={name}>
                  <td style={{ width: 24, paddingRight: 0 }}>
                    <span class={`sev ${statusSev(r.status)}`} />
                  </td>
                  <td class="mono" style={{ whiteSpace: 'nowrap' }}>
                    {prettyHeader(name)}
                  </td>
                  <td class="mono muted" style={{ wordBreak: 'break-all' }}>
                    {r.present ? r.value || '(present)' : <em>missing</em>}
                  </td>
                  <td style={{ textAlign: 'right', width: 80 }}>
                    <SevPill level={statusSev(r.status)} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div class="card" style={{ marginTop: 14 }}>
        <div class="card-head">
          <h3>Additional headers</h3>
        </div>
        <div class="card-body" style={{ padding: 0 }}>
          <table class="tbl">
            <tbody>
              <AdditionalRow name="Server" hr={headers.additional.server} />
              <AdditionalRow
                name="Cross-Origin-Opener-Policy"
                hr={headers.additional['cross-origin-opener-policy']}
              />
              <AdditionalRow
                name="Cross-Origin-Embedder-Policy"
                hr={headers.additional['cross-origin-embedder-policy']}
              />
              <AdditionalRow
                name="Cross-Origin-Resource-Policy"
                hr={headers.additional['cross-origin-resource-policy']}
              />
              <AdditionalRow
                name="Access-Control-Allow-Origin"
                hr={headers.additional['access-control-allow-origin']}
              />
            </tbody>
          </table>
          {headers.additional['set-cookie']?.length ? (
            <div style={{ borderTop: '1px solid var(--line)', padding: '12px 18px' }}>
              <div
                style={{
                  fontSize: 11,
                  textTransform: 'uppercase',
                  letterSpacing: '0.06em',
                  color: 'var(--muted)',
                  fontFamily: 'var(--font-mono)',
                  marginBottom: 8,
                }}
              >
                Set-Cookie · {headers.additional['set-cookie']?.length}
              </div>
              {headers.additional['set-cookie']?.map((c, i) => (
                <div
                  key={i}
                  style={{
                    fontSize: 12.5,
                    fontFamily: 'var(--font-mono)',
                    padding: '4px 0',
                    display: 'flex',
                    gap: 10,
                    alignItems: 'center',
                  }}
                >
                  <span class={`sev ${statusSev(c.status)}`} />
                  <code>{c.name}</code>
                  <span class="muted">
                    {c.secure ? 'Secure' : 'no Secure'} · {c.httponly ? 'HttpOnly' : 'no HttpOnly'} ·{' '}
                    {c.samesite ? `SameSite=${c.samesite}` : 'no SameSite'}
                  </span>
                </div>
              ))}
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}

function AdditionalRow({ name, hr }: { name: string; hr?: HeaderResult }) {
  return (
    <tr>
      <td style={{ width: 24, paddingRight: 0 }}>
        {hr ? <span class={`sev ${statusSev(hr.status)}`} /> : <span class="muted">—</span>}
      </td>
      <td class="mono" style={{ whiteSpace: 'nowrap' }}>
        {name}
      </td>
      <td class="mono muted" style={{ wordBreak: 'break-all' }}>
        {hr ? hr.value || '(present)' : <em>absent</em>}
      </td>
      <td style={{ textAlign: 'right', width: 80 }}>
        {hr ? <SevPill level={statusSev(hr.status)} /> : <span class="muted">—</span>}
      </td>
    </tr>
  );
}

function VulnsTab({ vulns }: { vulns: Vuln[] }) {
  const [filter, setFilter] = useState<'all' | Severity>('all');
  if (!vulns.length) return <EmptyCard message="No vulnerability checks performed." />;
  const counts: Record<string, number> = { all: vulns.length };
  for (const v of vulns) counts[v.level] = (counts[v.level] || 0) + 1;
  const visible = vulns.filter((v) => filter === 'all' || v.level === filter);

  const sev = [
    { id: 'all', label: 'All' },
    { id: 'bad', label: 'Critical' },
    { id: 'warn', label: 'Warning' },
    { id: 'good', label: 'Passed' },
    { id: 'info', label: 'Info' },
  ] as const;

  return (
    <div class="card">
      <div class="card-head">
        <h3>Known vulnerabilities</h3>
        <div class="filters">
          {sev.map((s) => (
            <button
              key={s.id}
              class={'chip' + (filter === s.id ? ' on' : '')}
              onClick={() => setFilter(s.id as typeof filter)}
            >
              {s.label}
              <span class="ct">{counts[s.id] || 0}</span>
            </button>
          ))}
        </div>
      </div>
      <div class="card-body flush">
        {visible.map((v) => (
          <div class="vuln-row" key={v.id}>
            <div>
              <span class={`sev ${v.level}`} />
            </div>
            <div>
              <h4>{v.title || v.id}</h4>
              <p>{v.body}</p>
              {v.cve && <div class="cve">{v.cve}</div>}
            </div>
            <div>
              <SevPill level={v.level} />
            </div>
          </div>
        ))}
        {!visible.length && (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--muted)', fontSize: 13 }}>
            No findings at this severity.
          </div>
        )}
      </div>
    </div>
  );
}

function CustomTab({ findings }: { findings: CustomFinding[] }) {
  if (!findings.length) return <EmptyCard message="No custom checks ran." />;
  return (
    <div class="card">
      <div class="card-head">
        <h3>Custom findings</h3>
        <span class="sub">{findings.length}</span>
      </div>
      <div class="card-body flush">
        {findings.map((f) => (
          <div class="vuln-row" key={f.id}>
            <div>
              <span class={`sev ${statusSev(f.status)}`} />
            </div>
            <div>
              <h4>{f.title}</h4>
              <CustomFactStrip finding={f} />
            </div>
            <div>
              <SevPill level={statusSev(f.status)} />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

type FactLevel = Severity | 'neutral';
type Fact = { label: string; level: FactLevel };

const ZERO_TIME = '0001-01-01T00:00:00Z';

function prettyKey(k: string): string {
  const s = k.replace(/_/g, ' ');
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function fmtExpires(iso: string): Fact | null {
  if (!iso || iso === ZERO_TIME) return null;
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return null;
  const date = iso.slice(0, 10);
  return { label: `Expires ${date}`, level: t > Date.now() ? 'good' : 'warn' };
}

function factsForFinding(f: CustomFinding): Fact[] {
  const d = f.details ?? {};
  const facts: Fact[] = [];

  if (f.id === 'custom.security_txt') {
    if (typeof d.rfc9116_compliant === 'boolean') {
      facts.push(
        d.rfc9116_compliant
          ? { label: '✓ RFC 9116', level: 'good' }
          : { label: '✗ RFC 9116', level: 'bad' },
      );
    }
    if (typeof d.signed === 'boolean') {
      facts.push(
        d.signed ? { label: '✓ Signed', level: 'good' } : { label: '✗ Signed', level: 'bad' },
      );
    }
    if (typeof d.contact_count === 'number') {
      const n = d.contact_count;
      facts.push({
        label: `${n} contact${n === 1 ? '' : 's'}`,
        level: n > 0 ? 'good' : 'bad',
      });
    }
    const exp = typeof d.expires === 'string' ? fmtExpires(d.expires) : null;
    if (exp) facts.push(exp);
    if (typeof d.note === 'string' && d.note) {
      facts.push({ label: `⚠ ${d.note}`, level: 'warn' });
    }
    return facts;
  }

  if (f.id === 'custom.robots_txt') {
    if (typeof d.parseable === 'boolean') {
      facts.push(
        d.parseable
          ? { label: '✓ Parseable', level: 'good' }
          : { label: '✗ Parseable', level: 'bad' },
      );
    }
    if (typeof d.size_bytes === 'number') {
      facts.push({ label: `${d.size_bytes} bytes`, level: 'neutral' });
    }
    if (Array.isArray(d.suspicious_disallow) && d.suspicious_disallow.length > 0) {
      const items = d.suspicious_disallow as string[];
      const head = items.slice(0, 3).join(', ');
      const suffix = items.length > 3 ? ` +${items.length - 3} more` : '';
      facts.push({ label: `⚠ Suspicious: ${head}${suffix}`, level: 'warn' });
    }
    if (typeof d.note === 'string' && d.note) {
      facts.push({ label: `⚠ ${d.note}`, level: 'warn' });
    }
    return facts;
  }

  // Unknown check — generic key/value chips, filtering noise.
  for (const [k, v] of Object.entries(d)) {
    if (k === 'url' || k === 'note') continue;
    if (v === null || v === undefined || v === '') continue;
    if (typeof v === 'string' && v === ZERO_TIME) continue;
    if (Array.isArray(v) && v.length === 0) continue;
    const value =
      typeof v === 'object' ? JSON.stringify(v) : typeof v === 'boolean' ? (v ? 'yes' : 'no') : String(v);
    facts.push({ label: `${prettyKey(k)}: ${value}`, level: 'neutral' });
  }
  if (typeof d.note === 'string' && d.note) {
    facts.push({ label: `⚠ ${d.note}`, level: 'warn' });
  }
  return facts;
}

function CustomFactStrip({ finding }: { finding: CustomFinding }) {
  const url = typeof finding.details?.url === 'string' ? (finding.details.url as string) : null;
  const facts = factsForFinding(finding);
  if (!url && !facts.length) return null;
  return (
    <>
      {url && (
        <a class="fact-url" href={url} target="_blank" rel="noreferrer">
          → {url}
        </a>
      )}
      {facts.length > 0 && (
        <div class="fact-strip">
          {facts.map((f, i) => (
            <span key={i} class={f.level === 'neutral' ? 'pill' : `pill ${f.level}`}>
              {f.label}
            </span>
          ))}
        </div>
      )}
    </>
  );
}

// ────────────────────────────────────────────────────────────────────────────
// Misc

function EmptyCard({ message }: { message: string }) {
  return (
    <div class="card">
      <div class="card-body" style={{ padding: 40, textAlign: 'center', color: 'var(--muted)' }}>
        {message}
      </div>
    </div>
  );
}

function LoadingState() {
  return (
    <div style={{ padding: 80, textAlign: 'center', color: 'var(--muted)' }}>
      <div class="scan-title" style={{ justifyContent: 'center', marginBottom: 12 }}>
        <span class="spinner" />
        Loading scan…
      </div>
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{scanIDFromPath()}</div>
    </div>
  );
}

function ErrorState({ message }: { message: string }) {
  return (
    <div class="card" style={{ maxWidth: 640, margin: '60px auto' }}>
      <div class="card-head">
        <h3>Couldn't load scan</h3>
      </div>
      <div class="card-body">
        <p style={{ margin: 0, color: 'var(--muted)' }}>{message}</p>
        <p style={{ marginTop: 14 }}>
          <a href="/" class="btn">
            ← Back to scanner
          </a>
        </p>
      </div>
    </div>
  );
}

function prettyHeader(name: string): string {
  return name
    .split('-')
    .map((s) => s.charAt(0).toUpperCase() + s.slice(1))
    .join('-');
}
