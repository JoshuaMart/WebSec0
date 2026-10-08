// Report island mounted at /r/{id}.

import { splitWeaknesses } from './report-weaknesses.ts';
import { EmailTab } from './EmailTab.tsx';
import type { ComponentChildren } from 'preact';
import { useEffect, useState } from 'preact/hooks';
import {
  deriveHighlights,
  statusSev,
  type Highlight,
} from './report-highlights.ts';
import { tlsGradeCap } from './report-grade.ts';
import { certificateSCTSummary, sctSummary } from './report-scts.ts';
import type {
  Severity,
  ProtocolSupport,
  Cipher,
  Certificate,
  Vuln,
  HeaderResult,
  TLSReport,
  HeadersReport,
  CustomFinding,
  ScanResult,
  SCTSummary,
  CertificateSCTs,
} from './report-types.ts';

// ────────────────────────────────────────────────────────────────────────────
// Tiny utilities

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
  try {
    return m ? decodeURIComponent(m[1]) : '';
  } catch {
    return '';
  }
}

// ────────────────────────────────────────────────────────────────────────────
// Top-level component

export default function Report() {
  const [data, setData] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<TabId>('overview');
  const [obsFilter, setObsFilter] = useState<ObservationFilter>('all');

  useEffect(() => {
    const syncTab = () => {
      const section = location.hash.slice(1) as TabId;
      setTab(
        Object.hasOwn(sectionDetails, section) &&
          (section !== 'email' || data?.email)
          ? section
          : 'overview',
      );
    };
    syncTab();
    window.addEventListener('hashchange', syncTab);
    return () => window.removeEventListener('hashchange', syncTab);
  }, [data]);

  function selectTab(next: TabId, focus = false) {
    setTab(next);
    history.replaceState(null, '', `#${next}`);
    if (focus) document.getElementById(`tab-${next}`)?.focus();
  }

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
      .catch((e: unknown) =>
        setError(e instanceof Error ? e.message : String(e)),
      );
  }, []);

  if (error) return <ErrorState message={error} />;
  if (!data) return <LoadingState />;

  return (
    <div class="report-layout">
      <Crumbs />
      <Header data={data} />
      <PartialScanNotice tls={data.tls} />
      <div class="report-intro">
        <h2>Your configuration, at a glance.</h2>
        <p>Two independent grades. Open a section for the evidence.</p>
      </div>
      <GradePanel data={data} />
      <TriageStrip
        data={data}
        onSelect={(next, filter) => {
          if (filter) setObsFilter(filter);
          selectTab(next);
          document
            .getElementById('report-sections')
            ?.scrollIntoView({ block: 'start' });
        }}
      />
      <Tabs active={tab} onChange={(next) => selectTab(next)} data={data} />
      <div
        class="report-panel"
        role="tabpanel"
        id={`panel-${tab}`}
        aria-labelledby={`tab-${tab}`}
        tabIndex={0}
      >
        <div class="section-heading">
          <div>
            <span class="report-eyebrow">The evidence</span>
            <h2>{sectionDetails[tab].title}</h2>
          </div>
          <p>{sectionDetails[tab].description}</p>
        </div>
        <TabPanel
          id={tab}
          data={data}
          onNavigate={(next) => selectTab(next, true)}
          obsFilter={obsFilter}
          onObsFilter={setObsFilter}
        />
      </div>
    </div>
  );
}

function PartialScanNotice({ tls }: { tls?: TLSReport }) {
  if (
    tls?.scan_status !== 'partial_blocked' &&
    !tls?.vulnerabilities?.some(
      (finding) =>
        finding.id === 'vuln.scan_blocked' && finding.state === 'Partial',
    )
  )
    return null;
  return (
    <aside class="partial-notice" aria-label="Scan completeness">
      <span class="pill info">Partial scan</span>
      <p>
        The target stopped responding during TLS checks. <b>Indeterminate</b>{' '}
        protocols were not assessed; grades reflect the observations collected.
      </p>
    </aside>
  );
}

// ────────────────────────────────────────────────────────────────────────────
// Header + grade panel

function Crumbs() {
  return (
    <nav class="crumbs" aria-label="Breadcrumb">
      <a href="/" style={{ color: 'inherit', textDecoration: 'none' }}>
        ← New scan
      </a>
      <span class="sep">/</span>
      <span class="ink2">Report</span>
    </nav>
  );
}

function Header({ data }: { data: ScanResult }) {
  const [copyState, setCopyState] = useState('');
  async function copyLink() {
    try {
      await navigator.clipboard.writeText(location.href);
      setCopyState('Report link copied.');
    } catch {
      setCopyState('Copy the address from your browser to share this report.');
    }
  }
  return (
    <div class="header">
      <div>
        <p class="report-eyebrow">Website security report</p>
        <h1 class="h-title">
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
      <div class="report-actions">
        <div class="report-action-buttons">
          <a
            class="btn"
            href={`/api/v1/scan/${encodeURIComponent(data.id)}`}
            target="_blank"
            rel="noopener"
            aria-label="View JSON (opens in a new tab)"
          >
            View JSON <span aria-hidden="true">↗</span>
          </a>
          <button class="btn btn-primary" type="button" onClick={copyLink}>
            Copy report link <span aria-hidden="true">↗</span>
          </button>
        </div>
        <span class="action-feedback" role="status">
          {copyState}
        </span>
      </div>
    </div>
  );
}

function TrustPill({ trust }: { trust?: string }) {
  if (!trust || trust === '') return null;
  if (trust === 'no_chain')
    return <span class="pill info">Trust not assessed</span>;
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

export function GradePanel({ data }: { data: ScanResult }) {
  const tlsGrade = data.tls?.grade ?? '';
  const tlsScore = data.tls?.scores.final ?? 0;
  const headersGrade = data.headers?.grade ?? '';
  const headersScore = data.headers?.score ?? 0;
  const tlsCap = tlsGradeCap(data.tls);
  const core = Object.entries(data.headers?.core ?? {});
  const failed = core.filter(([, r]) => r.status === 'fail').length;
  const reviewed = core.filter(([, r]) => r.status === 'warn').length;
  return (
    <div class="grade-panel grade-panel-two">
      <div class="grade-cell">
        <GradeCard
          label="TLS grade"
          grade={tlsGrade}
          score={tlsScore}
          sub={
            data.tls
              ? `${tlsScore}/100 · ${prettyTrust(data.tls.chain_trust) || 'Trust not assessed'}`
              : 'TLS assessment unavailable'
          }
          note={tlsCap && <span class="pill warn">{tlsCap}</span>}
        />
        {data.tls && (
          <div class="grade-breakdown">
            <div class="score-list">
              <ScoreBar
                name="Certificate"
                value={data.tls.scores.certificate}
              />
              <ScoreBar
                name="Protocol support"
                value={data.tls.scores.protocol_support}
              />
              <ScoreBar
                name="Key exchange"
                value={data.tls.scores.key_exchange}
              />
              <ScoreBar
                name="Cipher strength"
                value={data.tls.scores.cipher_strength}
              />
            </div>
          </div>
        )}
      </div>
      <div class="grade-cell">
        <GradeCard
          label="Headers grade"
          grade={headersGrade}
          score={headersScore}
          sub={
            !data.headers
              ? 'HTTP headers assessment unavailable'
              : data.headers.probed_host
                ? `${headersScore}/100 · via ${data.headers.probed_host}`
                : `${headersScore}/100`
          }
          note={
            failed ? (
              <span class="pill bad">
                {failed} core {failed > 1 ? 'checks fail' : 'check fails'}
              </span>
            ) : reviewed ? (
              <span class="pill warn">
                {reviewed} core {reviewed > 1 ? 'checks' : 'check'} to review
              </span>
            ) : null
          }
        />
        {!!core.length && (
          <ul class="grade-breakdown header-status-list">
            {core.map(([name, r]) => {
              const level = statusSev(r.status);
              return (
                <li key={name}>
                  <span class="mono">{prettyHeader(name)}</span>
                  <span class={`status-label ${level}`}>
                    <span class={`sev ${level}`} />
                    {sevLabel(level)}
                  </span>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </div>
  );
}

type ObservationFilter = 'all' | Severity;

const observationGroups: { level: Severity; label: string }[] = [
  { level: 'bad', label: 'Needs attention' },
  { level: 'warn', label: 'Review' },
  { level: 'info', label: 'For context' },
  { level: 'good', label: 'Working well' },
];

function hasAssessment(highlights: Highlight[]): boolean {
  return highlights.some((h) => h.level !== 'info' || h.section);
}

function TriageStrip({
  data,
  onSelect,
}: {
  data: ScanResult;
  onSelect: (tab: TabId, filter?: ObservationFilter) => void;
}) {
  const highlights = deriveHighlights(data);
  if (!hasAssessment(highlights)) return null;
  const count = (level: Severity) =>
    highlights.filter((h) => h.level === level).length;
  const outside = data.tls?.vulnerabilities
    ? splitWeaknesses(data.tls.vulnerabilities).unassessed.length
    : 0;
  const cells: {
    level: Severity | 'outside';
    label: string;
    count: number;
    tab: TabId;
  }[] = [
    { level: 'bad', label: 'Need attention', count: count('bad'), tab: 'overview' },
    { level: 'warn', label: 'To review', count: count('warn'), tab: 'overview' },
    { level: 'good', label: 'Working well', count: count('good'), tab: 'overview' },
  ];
  if (outside)
    cells.push({
      level: 'outside',
      label: 'Outside this scan',
      count: outside,
      tab: 'vulns',
    });
  return (
    <div class="triage-strip" role="group" aria-label="Observations by priority">
      {cells.map((cell) => (
        <button
          key={cell.level}
          type="button"
          class={`triage-cell ${cell.level}`}
          onClick={() =>
            onSelect(
              cell.tab,
              cell.level === 'outside' ? undefined : cell.level,
            )
          }
        >
          <b>{cell.count}</b>
          <span>
            <span class={`sev ${cell.level}`} />
            {cell.label}
          </span>
        </button>
      ))}
    </div>
  );
}

function GradeCard({
  label,
  grade,
  score,
  sub,
  note,
}: {
  label: string;
  grade: string;
  score: number;
  sub: string;
  note?: ComponentChildren;
}) {
  return (
    <div class="grade-summary">
      <GradeRing grade={grade} score={score} />
      <div>
        <h3 class="grade-label">{label}</h3>
        <div class="grade-sub">{sub || ''}</div>
        {note && <div class="grade-note">{note}</div>}
      </div>
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
    <svg
      role="img"
      viewBox="0 0 168 168"
      width="132"
      height="132"
      aria-label={`Grade ${showGrade}`}
    >
      <circle cx="84" cy="84" r={r} fill="var(--ink)" />
      <circle
        cx="84"
        cy="84"
        r={r}
        fill="none"
        stroke="var(--line)"
        stroke-width="6"
      />
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
  if (['D', 'E', 'F', 'T'].includes(grade)) return 'var(--bad)';
  return 'var(--muted-2)';
}

function prettyTrust(trust?: string): string {
  if (!trust || trust === 'no_chain') return 'Trust not assessed';
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
  | 'custom'
  | 'email';

const sectionDetails: Record<TabId, { title: string; description: string }> = {
  overview: {
    title: 'Report summary.',
    description:
      'Start with the highest-priority observations. Open a section to inspect the evidence.',
  },
  certificate: {
    title: 'Identity & trust.',
    description:
      'Inspect the certificate chain, validity and certificate transparency observations.',
  },
  protocols: {
    title: 'The connections your server accepts.',
    description:
      'Offered, disabled and indeterminate protocols are shown separately.',
  },
  ciphers: {
    title: 'Inside the encrypted connection.',
    description:
      'Explore each offered cipher suite, its strength and forward secrecy.',
  },
  headers: {
    title: 'The browser’s first line of defence.',
    description:
      'Inspect the returned policies and the status of each header check.',
  },
  vulns: {
    title: 'Configuration weaknesses.',
    description:
      'These are configuration and version indicators. They do not establish exploitability.',
  },
  custom: {
    title: 'The surrounding signals.',
    description:
      'Additional observations provide context without changing the TLS or Headers grades.',
  },
  email: {
    title: 'Email configuration.',
    description:
      'Policy validity, requested protection and verification status, at a glance.',
  },
};

export function Tabs({
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
      label: 'Weaknesses',
      count: data.tls?.vulnerabilities
        ? splitWeaknesses(data.tls.vulnerabilities).assessed.length
        : undefined,
    },
    { id: 'custom', label: 'Other checks', count: data.custom?.length },
  ];
  if (data.email) tabs.push({ id: 'email', label: 'Email security' });
  return (
    <div
      class="tabs"
      id="report-sections"
      role="tablist"
      aria-label="Report sections"
    >
      {tabs.map((t) => (
        <button
          key={t.id}
          class={'tab' + (active === t.id ? ' active' : '')}
          type="button"
          role="tab"
          id={`tab-${t.id}`}
          aria-selected={active === t.id}
          aria-controls={active === t.id ? `panel-${t.id}` : undefined}
          tabIndex={active === t.id ? 0 : -1}
          onClick={() => onChange(t.id)}
          onKeyDown={(event) => {
            const index = tabs.findIndex((item) => item.id === t.id);
            let next: number;
            if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
            else if (event.key === 'ArrowLeft')
              next = (index - 1 + tabs.length) % tabs.length;
            else if (event.key === 'Home') next = 0;
            else if (event.key === 'End') next = tabs.length - 1;
            else return;
            event.preventDefault();
            onChange(tabs[next].id);
            document.getElementById(`tab-${tabs[next].id}`)?.focus();
          }}
        >
          {t.label}
          {t.count != null && <span class="count">{t.count}</span>}
        </button>
      ))}
    </div>
  );
}

export function TabPanel({
  id,
  data,
  onNavigate,
  obsFilter,
  onObsFilter,
}: {
  id: TabId;
  data: ScanResult;
  onNavigate?: (id: TabId) => void;
  obsFilter?: ObservationFilter;
  onObsFilter?: (filter: ObservationFilter) => void;
}) {
  switch (id) {
    case 'overview':
      return (
        <Overview
          data={data}
          onNavigate={onNavigate}
          filter={obsFilter}
          onFilter={onObsFilter}
        />
      );
    case 'certificate':
      return (
        <div class="section">
          {data.tls && (
            <div class="card">
              <div class="card-head">
                <h3>Trust & connection</h3>
              </div>
              <dl class="connection-facts">
                <div>
                  <dt>Certificate trust</dt>
                  <dd>{prettyTrust(data.tls.chain_trust)}</dd>
                </div>
                <div>
                  <dt>OCSP stapling</dt>
                  <dd>
                    {data.tls.ocsp_stapling
                      ? `Stapled · ${data.tls.ocsp_status || 'Status unknown'}`
                      : 'Not observed'}
                  </dd>
                </div>
                <div>
                  <dt>Session resumption</dt>
                  <dd>
                    {data.tls.session_resumption?.replace(/_/g, ' ') ||
                      'Not assessed'}
                  </dd>
                </div>
              </dl>
            </div>
          )}
          <CertificateTab chain={data.tls?.certificate_chain ?? []} />
          <CertificateTransparencyCard
            handshake={data.tls?.handshake_scts}
            certificate={data.tls?.certificate_scts}
          />
        </div>
      );
    case 'protocols':
      return <ProtocolsTab protocols={data.tls?.protocols ?? []} />;
    case 'ciphers':
      return (
        <CiphersTab
          ciphers={data.tls?.ciphers ?? []}
          pref={data.tls?.cipher_preference}
        />
      );
    case 'headers':
      return <HeadersTab headers={data.headers} />;
    case 'vulns':
      return <VulnsTab vulns={data.tls?.vulnerabilities ?? []} />;
    case 'custom':
      return <CustomTab findings={data.custom ?? []} />;
    case 'email':
      return <EmailTab email={data.email} />;
  }
}

// ────────────────────────────────────────────────────────────────────────────
// Overview

function Overview({
  data,
  onNavigate,
  filter: controlledFilter,
  onFilter,
}: {
  data: ScanResult;
  onNavigate?: (id: TabId) => void;
  filter?: ObservationFilter;
  onFilter?: (filter: ObservationFilter) => void;
}) {
  const [localFilter, setLocalFilter] = useState<ObservationFilter>('all');
  const filter = controlledFilter ?? localFilter;
  const setFilter = onFilter ?? setLocalFilter;
  const tls = data.tls;
  const offeredProtos = (tls?.protocols ?? [])
    .filter((p) => p.offered)
    .map((p) => p.name);
  const leaf = tls?.certificate_chain?.[0];
  const highlights = deriveHighlights(data).map((h, i) => ({
    ...h,
    number: String(i + 1).padStart(2, '0'),
  }));
  const groups = observationGroups
    .map((group) => ({
      ...group,
      items: highlights.filter((h) => h.level === group.level),
    }))
    .filter((group) => group.items.length);
  const visibleGroups = groups.filter(
    (group) => filter === 'all' || group.level === filter,
  );
  const shownGroups = visibleGroups.length ? visibleGroups : groups;
  const activeFilter = visibleGroups.length ? filter : 'all';
  return (
    <div class="section">
      <div class="overview-grid">
        <div class="card findings-card">
          <div class="card-head">
            <h3>Key observations</h3>
            {groups.length > 1 && (
              <div
                class="filters"
                role="group"
                aria-label="Filter observations"
              >
                {[{ level: 'all' as const, label: 'All' }, ...groups].map(
                  (item) => (
                    <button
                      key={item.level}
                      type="button"
                      class={'chip' + (activeFilter === item.level ? ' on' : '')}
                      aria-pressed={activeFilter === item.level}
                      onClick={() => setFilter(item.level)}
                    >
                      {item.label}
                      <span class="ct">
                        {item.level === 'all'
                          ? highlights.length
                          : highlights.filter((h) => h.level === item.level)
                              .length}
                      </span>
                    </button>
                  ),
                )}
              </div>
            )}
          </div>
          {shownGroups.map((group) => (
            <section
              key={group.level}
              class="finding-group"
              aria-label={group.label}
            >
              <div class="finding-group-label">
                <span>
                  <span class={`sev ${group.level}`} />
                  {group.label}
                </span>
                <span>{group.items.length}</span>
              </div>
              <ol class="finding-list">
                {group.items.map((h) => (
                  <li key={h.number} class={`finding-item ${h.level}`}>
                    <span class="finding-number" aria-hidden="true">
                      {h.number}
                    </span>
                    <div>
                      {h.section === 'custom' && (
                        <span class="finding-label info">Informational</span>
                      )}
                      <h3>{h.title}</h3>
                      <p>{h.body}</p>
                      {h.section && (
                        <a
                          class="evidence-link"
                          href={`#${h.section}`}
                          onClick={(event) => {
                            if (
                              onNavigate &&
                              !event.metaKey &&
                              !event.ctrlKey &&
                              !event.shiftKey &&
                              !event.altKey
                            ) {
                              event.preventDefault();
                              onNavigate(h.section!);
                            }
                          }}
                        >
                          View{' '}
                          {h.section === 'vulns'
                            ? 'weaknesses'
                            : h.section === 'custom'
                              ? 'other checks'
                              : h.section}{' '}
                          <span aria-hidden="true">↗</span>
                        </a>
                      )}
                    </div>
                  </li>
                ))}
              </ol>
            </section>
          ))}
        </div>
        <div class="overview-aside">
          {leaf && <CertificateValidityCard cert={leaf} />}
          <div class="card">
            <div class="card-head">
              <h3>Connection snapshot</h3>
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
                <div class="v">
                  {tls ? `${tls.ciphers?.length ?? 0} offered` : 'Not assessed'}
                </div>
                <div class="k">Cipher preference</div>
                <div class="v">{tls?.cipher_preference || '—'}</div>
                <div class="k">OCSP stapling</div>
                <div class="v">
                  {!tls
                    ? 'Not assessed'
                    : tls.ocsp_stapling
                      ? `yes (${tls.ocsp_status || 'unknown'})`
                      : 'no'}
                </div>
                <div class="k">Session resumption</div>
                <div class="v">{tls?.session_resumption || '—'}</div>
              </div>
            </div>
          </div>
          <div class="report-scope">
            <span class="report-eyebrow">Reading this report</span>
            <h3>Two grades. One point in time.</h3>
            <p>
              TLS and Headers measure different parts of your configuration.
              Missing or incomplete checks are not passing results.
            </p>
            <a href="/api/v1/checks" class="evidence-link">
              Explore the check catalog <span aria-hidden="true">↗</span>
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}

function CertificateValidityCard({ cert }: { cert: Certificate }) {
  const start = Date.parse(cert.not_before);
  const end = Date.parse(cert.not_after);
  const totalDays = (end - start) / 86_400_000;
  const remaining =
    totalDays > 0
      ? Math.max(0, Math.min(1, cert.days_left / totalDays))
      : 0;
  const level =
    cert.days_left < 0 ? 'bad' : cert.days_left < 30 ? 'warn' : 'good';
  return (
    <div class="card validity-card">
      <div class="card-head">
        <h3>Certificate</h3>
        <span class={`pill ${level}`}>
          <span class="dot" />
          {cert.days_left < 0 ? 'Expired' : `${cert.days_left} days left`}
        </span>
      </div>
      <div class="card-body">
        <div class="validity-identity">
          <span class="mono">{cert.cn || '(no CN)'}</span>
          <span class="mono muted">{cert.key_alg}</span>
        </div>
        <div
          class={`bar ${level}`}
          role="img"
          aria-label={`${Math.round(remaining * 100)}% of the validity period remaining`}
        >
          <span style={{ width: `${remaining * 100}%` }} />
        </div>
        <div class="validity-dates mono">
          <span>{cert.not_before.slice(0, 10)}</span>
          <span>expires {cert.not_after.slice(0, 10)}</span>
        </div>
      </div>
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────────────
// Certificate tab

function CertificateTab({ chain }: { chain: Certificate[] }) {
  const [open, setOpen] = useState<Record<number, boolean>>({ 0: true });
  if (!chain.length)
    return <EmptyCard message="No certificate chain captured." />;
  return (
    <div class="card">
      <div class="card-head">
        <h3>
          Certification path{' '}
          <span class="sub">· {chain.length} certificates</span>
        </h3>
      </div>
      <div class="card-body flush chain">
        {chain.map((c, i) => {
          const isOpen = !!open[i];
          return (
            <div key={i} class={'cert-node' + (isOpen ? ' open' : '')}>
              <button
                type="button"
                aria-expanded={isOpen}
                aria-controls={isOpen ? `certificate-${i}` : undefined}
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
                    <span
                      class="dot"
                      style={{ background: 'var(--muted-2)' }}
                    />
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
              </button>
              {isOpen && (
                <div class="cert-body" id={`certificate-${i}`}>
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

function CertificateTransparencyCard({
  handshake,
  certificate,
}: {
  handshake?: SCTSummary;
  certificate?: CertificateSCTs;
}) {
  return (
    <div class="card">
      <div class="card-head">
        <h3>Certificate Transparency</h3>
        <SevPill level="info" />
      </div>
      <div class="card-body sct-body">
        <SCTSource
          title="Leaf certificate"
          summary={certificateSCTSummary(certificate)}
          logIDs={
            certificate?.present && !certificate.parse_error
              ? certificate.log_ids
              : undefined
          }
        />
        <SCTSource
          title="TLS handshake"
          summary={sctSummary(handshake)}
          logIDs={handshake?.log_ids}
        />
        <p class="muted">
          Informational only; no effect on the grade. SCT signatures and log
          inclusion are not verified. SCTs in OCSP responses are not assessed.
        </p>
      </div>
    </div>
  );
}

function SCTSource({
  title,
  summary,
  logIDs,
}: {
  title: string;
  summary: string;
  logIDs?: string[];
}) {
  return (
    <section class="sct-source" aria-label={title}>
      <h4>{title}</h4>
      <p>{summary}</p>
      {!!logIDs?.length && (
        <>
          <p class="muted">Log IDs (SHA-256, unique per source)</p>
          <ul class="sct-log-ids mono">
            {logIDs.map((id) => (
              <li key={id}>{id}</li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}

// ────────────────────────────────────────────────────────────────────────────
// Protocols, Ciphers, Headers, Vulns, Custom tabs

function ProtocolsTab({ protocols }: { protocols: ProtocolSupport[] }) {
  if (!protocols.length)
    return <EmptyCard message="No protocols enumerated." />;
  const offered = protocols.filter((p) => p.offered);
  const indeterminate = protocols.filter((p) => p.probe === 'aborted').length;
  const disabled = protocols.length - offered.length - indeterminate;
  const ordered = [...protocols].sort(
    (a, b) => protocolOrder(a.name) - protocolOrder(b.name),
  );
  const names = new Set(offered.map((p) => p.name));
  const notice =
    names.has('SSL 2.0') || names.has('SSL 3.0')
      ? {
          level: 'bad',
          text: 'SSL is offered. Disable SSL 2.0 and SSL 3.0 to remove the F cap on the TLS grade.',
        }
      : names.has('TLS 1.0') || names.has('TLS 1.1')
        ? {
            level: 'warn',
            text: 'TLS 1.0 or 1.1 is offered. Disable both to remove the C cap on the TLS grade.',
          }
        : null;
  return (
    <div class="card">
      <div class="card-head">
        <h3>Protocol support</h3>
        <span class="sub">
          {offered.length} offered
          {indeterminate > 0 ? ` · ${indeterminate} indeterminate` : ''}
          {' · '}
          {disabled} disabled
        </span>
      </div>
      <ul class="proto-grid">
        {ordered.map((p) => (
          <li key={p.name} class="proto-cell">
            <b>{p.name}</b>
            <span>
              {p.name.startsWith('SSL')
                ? 'Obsolete'
                : ['TLS 1.0', 'TLS 1.1'].includes(p.name)
                  ? 'Deprecated'
                  : 'Modern TLS'}
            </span>
            {p.probe === 'aborted' ? (
              <span class="pill info" style={{ borderStyle: 'dashed' }}>
                <span class="dot" />
                Indeterminate
              </span>
            ) : p.offered ? (
              <span
                class={`pill ${p.name.startsWith('SSL') ? 'bad' : ['TLS 1.0', 'TLS 1.1'].includes(p.name) ? 'warn' : 'good'}`}
              >
                <span class="dot" />
                Offered
              </span>
            ) : (
              <span class="pill">
                <span class="dot" style={{ background: 'var(--muted-2)' }} />
                Disabled
              </span>
            )}
          </li>
        ))}
      </ul>
      {notice && <p class={`proto-notice ${notice.level}`}>{notice.text}</p>}
    </div>
  );
}

// protocolOrder lists protocols from oldest to newest; unknown names go last.
function protocolOrder(name: string): number {
  const index = ['SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3'].indexOf(name);
  return index === -1 ? 99 : index;
}

function CiphersTab({
  ciphers,
  pref,
}: {
  ciphers: Cipher[];
  pref?: 'server' | 'client' | '';
}) {
  if (!ciphers.length) return <EmptyCard message="No ciphers enumerated." />;
  const grouped: Record<string, Cipher[]> = {};
  for (const cipher of ciphers) (grouped[cipher.protocol] ??= []).push(cipher);
  return (
    <div class="card">
      <div class="card-head">
        <h3>Cipher suites</h3>
        <span class="sub">
          {pref ? `${pref} preference` : 'Preference not assessed'}
        </span>
      </div>
      {Object.entries(grouped).map(([protocol, list]) => (
        <div key={protocol}>
          <div class="cipher-group-label">
            {protocol}
            <span>{list.length} suites</span>
          </div>
          {list.map((cipher) => {
            const parts = parseCipherName(cipher.name);
            return (
              <details class="cipher-detail" key={cipher.code}>
                <summary>
                  <span class="cipher-identity">
                    <span class={`sev ${cipher.level}`} />
                    <span>
                      {cipher.name}
                      <small>
                        {cipher.code} · {cipher.strength} bit
                      </small>
                    </span>
                  </span>
                  <span class="cipher-badges">
                    <span class={`pill ${cipher.aead ? 'good' : 'warn'}`}>
                      {cipher.aead ? 'AEAD' : 'Non-AEAD'}
                    </span>
                    <span class={`pill ${cipher.pfs ? 'good' : 'warn'}`}>
                      {cipher.pfs ? 'PFS' : 'No PFS'}
                    </span>
                    <span class="disclosure-plus" aria-hidden="true">
                      +
                    </span>
                  </span>
                </summary>
                <dl class="cipher-facts">
                  <div>
                    <dt>Key exchange</dt>
                    <dd>{parts.kx}</dd>
                  </div>
                  <div>
                    <dt>Authentication</dt>
                    <dd>{parts.auth}</dd>
                  </div>
                  <div>
                    <dt>Cipher</dt>
                    <dd>{parts.cipher}</dd>
                  </div>
                  <div>
                    <dt>MAC / integrity</dt>
                    <dd>{parts.mac}</dd>
                  </div>
                </dl>
              </details>
            );
          })}
        </div>
      ))}
    </div>
  );
}

// parseCipherName derives the canonical components (key exchange,
// authentication, bulk cipher, MAC) from an IANA-style suite name.
// TLS 1.3 negotiates key exchange and authentication separately from the suite.
function parseCipherName(name: string): {
  kx: string;
  auth: string;
  cipher: string;
  mac: string;
} {
  // TLS 1.3 names like TLS_AES_256_GCM_SHA384 lack the _WITH_ pivot.
  if (!name.includes('_WITH_')) {
    let cipher = '—';
    if (name.includes('CHACHA20')) cipher = 'ChaCha20-Poly1305';
    else if (name.includes('AES_256_GCM')) cipher = 'AES-256-GCM';
    else if (name.includes('AES_128_GCM')) cipher = 'AES-128-GCM';
    else if (name.includes('AES_128_CCM')) cipher = 'AES-128-CCM';
    return {
      kx: 'Negotiated separately',
      auth: 'Negotiated separately',
      cipher,
      mac: 'AEAD',
    };
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
  const aead =
    post.includes('GCM') ||
    post.includes('CHACHA20') ||
    post.includes('POLY1305');
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
          <div class="header-observations">
            {Object.entries(headers.core).map(([name, result]) => (
              <HeaderObservation
                key={name}
                name={prettyHeader(name)}
                result={result}
                guideSlug={name}
              />
            ))}
          </div>
        </div>
      </div>

      <div class="card" style={{ marginTop: 14 }}>
        <div class="card-head">
          <h3>Additional headers</h3>
        </div>
        <div class="card-body" style={{ padding: 0 }}>
          <div class="header-observations">
            {(
              [
                'server',
                'cross-origin-opener-policy',
                'cross-origin-embedder-policy',
                'cross-origin-resource-policy',
                'access-control-allow-origin',
              ] as const
            ).map((name) => (
              <HeaderObservation
                key={name}
                name={prettyHeader(name)}
                result={headers.additional[name]}
              />
            ))}
          </div>
          {headers.additional['set-cookie']?.length ? (
            <div
              style={{
                borderTop: '1px solid var(--line)',
                padding: '12px 18px',
              }}
            >
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
                    {c.secure ? 'Secure' : 'no Secure'} ·{' '}
                    {c.httponly ? 'HttpOnly' : 'no HttpOnly'} ·{' '}
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

// Optional remediation guides, hosted outside this repository. The base URL
// comes from <meta name="websec0-guides-url"> (added via the head_inject config
// option), so the published image carries no external links by default.
function guidesUrl(): string {
  if (typeof document === 'undefined') return '';
  const meta = document.querySelector('meta[name="websec0-guides-url"]');
  return (meta?.getAttribute('content') || '').replace(/\/+$/, '');
}

function HeaderObservation({
  name,
  result,
  guideSlug,
}: {
  name: string;
  result?: HeaderResult;
  guideSlug?: string;
}) {
  const guides = guidesUrl();
  const showGuide =
    guides && guideSlug && result && statusSev(result.status) !== 'good';
  return (
    <div class="header-observation">
      <div>
        <h4>{name}</h4>
        {result ? (
          <SevPill level={statusSev(result.status)} />
        ) : (
          <span class="pill">Not reported</span>
        )}
      </div>
      <p>
        {result ? (
          result.present ? (
            <code>{result.value || '(present)'}</code>
          ) : (
            'Header not present'
          )
        ) : (
          'No observation available.'
        )}
      </p>
      {showGuide && (
        <p>
          <a href={`${guides}/${guideSlug}`}>How to fix {name}</a>
        </p>
      )}
    </div>
  );
}

function VulnsTab({ vulns }: { vulns: Vuln[] }) {
  const [filter, setFilter] = useState<'all' | Severity>('all');
  const { assessed, unassessed } = splitWeaknesses(vulns);
  const counts: Record<string, number> = { all: assessed.length };
  for (const finding of assessed)
    counts[finding.level] = (counts[finding.level] || 0) + 1;
  const visible = assessed.filter(
    (finding) => filter === 'all' || finding.level === filter,
  );
  const filters = [
    { id: 'all', label: 'All results' },
    { id: 'bad', label: 'Failed' },
    { id: 'warn', label: 'Review' },
    { id: 'good', label: 'Passed' },
    { id: 'info', label: 'Info' },
  ] as const;
  return (
    <div class="section">
      <div class="card">
        <div class="card-head">
          <h3>Checks with results</h3>
          {!!assessed.length && (
            <div class="filters">
              {filters
                .filter((item) => item.id === 'all' || counts[item.id])
                .map((item) => (
                  <button
                    key={item.id}
                    class={'chip' + (filter === item.id ? ' on' : '')}
                    type="button"
                    aria-pressed={filter === item.id}
                    onClick={() => setFilter(item.id)}
                  >
                    {item.label}
                    <span class="ct">{counts[item.id] || 0}</span>
                  </button>
                ))}
            </div>
          )}
        </div>
        <div class="card-body flush">
          {visible.map((finding) => (
            <div class="vuln-row" key={finding.id}>
              <div>
                <span class={`sev ${finding.level}`} />
              </div>
              <div>
                <h4>{finding.title || finding.id}</h4>
                <p>{finding.body}</p>
                <div class="cve">
                  {finding.state}
                  {finding.cve ? ` · ${finding.cve}` : ''}
                </div>
              </div>
              <div>
                <SevPill level={finding.level} />
              </div>
            </div>
          ))}
          {!visible.length && (
            <p class="weakness-empty">
              {assessed.length
                ? 'No results match this filter.'
                : 'No assessed weakness checks are available in this report.'}
            </p>
          )}
        </div>
      </div>
      {!!unassessed.length && (
        <details class="coverage-details">
          <summary>
            Checks outside this scan <span>{unassessed.length}</span>
          </summary>
          <div class="coverage-body">
            <p>These checks have no result and are not counted as passes.</p>
            <ul>
              {unassessed.map((finding) => (
                <li key={finding.id}>
                  <div>
                    <strong>{finding.title || finding.id}</strong>
                    {finding.cve && <span class="mono">{finding.cve}</span>}
                  </div>
                  <p>{finding.body}</p>
                </li>
              ))}
            </ul>
          </div>
        </details>
      )}
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
  if (f.status === 'info' && typeof d.note === 'string' && d.note) {
    return [{ label: d.note, level: 'info' }];
  }

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
        d.signed
          ? { label: '✓ Signed', level: 'good' }
          : { label: '✗ Signed', level: 'bad' },
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
    if (
      Array.isArray(d.suspicious_disallow) &&
      d.suspicious_disallow.length > 0
    ) {
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
      typeof v === 'object'
        ? JSON.stringify(v)
        : typeof v === 'boolean'
          ? v
            ? 'yes'
            : 'no'
          : String(v);
    facts.push({ label: `${prettyKey(k)}: ${value}`, level: 'neutral' });
  }
  if (typeof d.note === 'string' && d.note) {
    facts.push({ label: `⚠ ${d.note}`, level: 'warn' });
  }
  return facts;
}

function CustomFactStrip({ finding }: { finding: CustomFinding }) {
  const url =
    typeof finding.details?.url === 'string'
      ? (finding.details.url as string)
      : null;
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
            <span
              key={i}
              class={f.level === 'neutral' ? 'pill' : `pill ${f.level}`}
            >
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
      <div
        class="card-body"
        style={{ padding: 40, textAlign: 'center', color: 'var(--muted)' }}
      >
        {message}
      </div>
    </div>
  );
}

function LoadingState() {
  return (
    <div
      role="status"
      style={{
        padding: '60px 16px',
        textAlign: 'center',
        color: 'var(--muted)',
      }}
    >
      <div
        class="scan-title"
        style={{ justifyContent: 'center', marginBottom: 12 }}
      >
        <span class="spinner" />
        Loading scan…
      </div>
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>
        {scanIDFromPath()}
      </div>
    </div>
  );
}

function ErrorState({ message }: { message: string }) {
  return (
    <div
      class="card"
      role="alert"
      style={{ maxWidth: 640, margin: '60px auto' }}
    >
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
