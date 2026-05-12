/**
 * Report island — Preact component mounted at /r/{id}. Reads the scan ID
 * from window.location.pathname, fetches /api/v1/scan/{id} and renders
 * the result with seven tabs.
 *
 * Types mirror internal/scan/types.go. We keep them inline (rather than
 * pulling a shared module) to keep the bundle compact.
 */

import { useEffect, useMemo, useState } from 'preact/hooks';

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

function gradeRingClass(grade: string): string {
  if (grade === 'A+' || grade === 'A') return '';
  if (grade === 'B' || grade === 'C') return ' warn';
  return ' bad';
}

function statusSev(status: Status): Severity {
  if (status === 'pass') return 'good';
  if (status === 'warn') return 'warn';
  if (status === 'fail') return 'bad';
  return 'info';
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

async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
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
  const headersGrade = data.headers?.grade ?? '';
  return (
    <div class="grade-panel" style={{ gridTemplateColumns: '1fr 1fr' }}>
      <div class="grade-cell">
        <GradeCard label="TLS grade" grade={tlsGrade} sub={data.tls?.chain_trust ?? ''} />
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
        <GradeCard label="Headers grade" grade={headersGrade} sub={`Score ${data.headers?.score ?? 0}/100`} />
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

function GradeCard({ label, grade, sub }: { label: string; grade: string; sub: string }) {
  const ringClass = gradeRingClass(grade || 'F');
  return (
    <div style={{ display: 'grid', placeItems: 'center', padding: '8px 0 4px' }}>
      <div style={{ position: 'relative', width: 132, height: 132 }}>
        <span
          class={'grade-chip' + ringClass}
          style={{
            width: '100%',
            height: '100%',
            fontSize: 44,
            position: 'absolute',
            inset: 0,
          }}
        >
          {grade || '—'}
        </span>
      </div>
      <div class="grade-label">{label}</div>
      <div class="grade-sub">{sub || ''}</div>
    </div>
  );
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
      count: data.tls?.certificate_chain.length,
    },
    {
      id: 'protocols',
      label: 'Protocols',
      count: data.tls?.protocols.filter((p) => p.offered).length,
    },
    {
      id: 'ciphers',
      label: 'Ciphers',
      count: data.tls?.ciphers.length,
    },
    { id: 'headers', label: 'Headers' },
    {
      id: 'vulns',
      label: 'Vulnerabilities',
      count: data.tls?.vulnerabilities.length,
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
  const leaf = tls?.certificate_chain[0];
  return (
    <div class="section">
      <div class="grid-2">
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
              <div class="v">{tls?.ciphers.length ?? 0} offered</div>
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
        <div class="card">
          <div class="card-head">
            <h3>Highlights</h3>
            <span class="sub">{deriveHighlights(data).length} findings</span>
          </div>
          <div class="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {deriveHighlights(data).map((h, i) => (
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
      </div>
    </div>
  );
}

function deriveHighlights(data: ScanResult): { title: string; body: string; level: Severity }[] {
  const out: { title: string; body: string; level: Severity }[] = [];
  const tls = data.tls;
  const protocols = new Set(tls?.protocols.filter((p) => p.offered).map((p) => p.name));

  if (protocols.has('TLS 1.3') && !protocols.has('TLS 1.0') && !protocols.has('TLS 1.1')) {
    out.push({
      title: 'TLS 1.3 with no legacy fallback',
      body: 'Only TLS 1.2 and 1.3 are offered. Legacy protocols (1.0/1.1) are disabled.',
      level: 'good',
    });
  }
  if (protocols.has('SSL 2.0') || protocols.has('SSL 3.0')) {
    out.push({
      title: 'Obsolete SSL versions enabled',
      body: 'SSLv2 or SSLv3 is enabled — POODLE/DROWN are exploitable.',
      level: 'bad',
    });
  }
  if (protocols.has('TLS 1.0') || protocols.has('TLS 1.1')) {
    out.push({
      title: 'Deprecated TLS versions enabled',
      body: 'TLS 1.0 or 1.1 is offered. Disable them to remove the C cap.',
      level: 'warn',
    });
  }
  if (tls && tls.ciphers.length && tls.ciphers.every((c) => c.pfs)) {
    out.push({
      title: 'All offered ciphers provide forward secrecy',
      body: 'Every cipher uses ECDHE/DHE — past sessions stay safe even if the private key is compromised.',
      level: 'good',
    });
  }
  if (tls?.ocsp_stapling && tls.ocsp_status === 'good') {
    out.push({
      title: 'OCSP stapling enabled with good status',
      body: 'The server staples a fresh OCSP response — clients do not need to query the CA.',
      level: 'good',
    });
  }
  if (tls?.chain_trust && tls.chain_trust !== 'trusted') {
    out.push({
      title: 'Certificate chain does not validate',
      body: `Chain trust: ${tls.chain_trust.replace(/_/g, ' ')}. The grade is capped at T.`,
      level: 'bad',
    });
  }
  const vulnsBad = (tls?.vulnerabilities ?? []).filter((v) => v.level === 'bad');
  if (vulnsBad.length) {
    out.push({
      title: `${vulnsBad.length} active vulnerability ${vulnsBad.length > 1 ? 'findings' : 'finding'}`,
      body: vulnsBad.map((v) => v.id).join(', '),
      level: 'bad',
    });
  }
  if (out.length === 0) {
    out.push({
      title: 'No notable findings yet',
      body: 'The scan completed without highlights to surface.',
      level: 'info',
    });
  }
  return out;
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
  if (!ciphers.length) return <EmptyCard message="No ciphers enumerated." />;
  const grouped = useMemo(() => {
    const g: Record<string, Cipher[]> = {};
    for (const c of ciphers) (g[c.protocol] ??= []).push(c);
    return g;
  }, [ciphers]);
  return (
    <div class="card">
      <div class="card-head">
        <h3>
          Cipher suites <span class="sub">· {pref ? `${pref} preference` : 'preference unknown'} · forward secrecy required</span>
        </h3>
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
                  <tr key={c.code} class="hoverable cipher-row">
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
                    <td style={{ width: 90 }}>
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
    </div>
  );
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
                  <td class="mono" style={{ whiteSpace: 'nowrap' }}>
                    {prettyHeader(name)}
                  </td>
                  <td class="mono muted" style={{ wordBreak: 'break-all' }}>
                    {r.present ? r.value || '(present)' : <em>missing</em>}
                  </td>
                  <td style={{ textAlign: 'right', width: 72 }}>
                    <span class={`sev ${statusSev(r.status)}`} />
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
      <td class="mono" style={{ whiteSpace: 'nowrap' }}>
        {name}
      </td>
      <td class="mono muted" style={{ wordBreak: 'break-all' }}>
        {hr ? hr.value || '(present)' : <em>absent</em>}
      </td>
      <td style={{ textAlign: 'right', width: 72 }}>
        {hr ? <span class={`sev ${statusSev(hr.status)}`} /> : <span class="muted">—</span>}
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
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span class={`sev ${v.level}`} />
                <span class="mono" style={{ fontSize: 11, color: 'var(--muted)' }}>
                  {v.state}
                </span>
              </div>
            </div>
            <div>
              <h4>{v.id}</h4>
              <p>{v.body}</p>
              {v.cve && <div class="cve">{v.cve}</div>}
            </div>
            <div>
              {v.level === 'good' ? (
                <span class="pill good">
                  <span class="dot" />
                  Pass
                </span>
              ) : v.level === 'bad' ? (
                <span class="pill bad">
                  <span class="dot" />
                  Fail
                </span>
              ) : v.level === 'warn' ? (
                <span class="pill warn">
                  <span class="dot" />
                  Warn
                </span>
              ) : (
                <span class="pill info">
                  <span class="dot" />
                  Info
                </span>
              )}
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
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span class={`sev ${statusSev(f.status)}`} />
                <span class="mono" style={{ fontSize: 11, color: 'var(--muted)' }}>
                  {f.status}
                </span>
              </div>
            </div>
            <div>
              <h4>{f.title}</h4>
              <DetailsBlock details={f.details} />
            </div>
            <div>
              <span class={`pill ${statusSev(f.status)}`}>
                <span class="dot" />
                {f.status}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function DetailsBlock({ details }: { details?: Record<string, unknown> }) {
  if (!details) return null;
  return (
    <p style={{ fontFamily: 'var(--font-mono)', fontSize: 11.5, color: 'var(--muted)' }}>
      {Object.entries(details)
        .filter(([, v]) => v !== null && v !== undefined && v !== '')
        .map(([k, v]) => `${k}: ${typeof v === 'object' ? JSON.stringify(v) : String(v)}`)
        .join(' · ')}
    </p>
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
