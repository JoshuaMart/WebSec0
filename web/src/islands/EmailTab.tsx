import type { ComponentChildren } from 'preact';
import type { DNSRecord, EmailReport } from './report-types.ts';

const states: Record<DNSRecord['state'], string> = {
  observed: 'Assessment unavailable',
  absent: 'No record found',
  invalid: 'Invalid configuration',
  unavailable: 'DNS unavailable',
};
const badge = {
  pass: ['good', 'Checked'],
  warn: ['warn', 'Review'],
  fail: ['bad', 'Error'],
  info: ['info', 'Info'],
  '': ['info', 'Info'],
};

function PolicyCard({ title, record, children, details }: {
  title: string;
  record: DNSRecord;
  children?: ComponentChildren;
  details?: ComponentChildren;
}) {
  const verdict = record.assessment;
  const [color, label] = verdict ? badge[verdict.status] : ['info', states[record.state]];
  return (
    <section class="card" aria-label={title}>
      <div class="card-head">
        <h3>{title}</h3>
        <span class={`pill ${color}`}>{label}</span>
      </div>
      <div class="card-body" style={{ display: 'grid', gap: 16, overflowWrap: 'anywhere' }}>
        {verdict ? <div>
          <h4 style={{ margin: '0 0 6px' }}>{verdict.title}</h4>
          <p style={{ margin: 0 }}>{verdict.summary}</p>
        </div> : <p style={{ margin: 0 }}>{states[record.state]}. Run a fresh scan for an assessment.</p>}
        {children}
        {verdict && verdict.recommendations.length > 0 && <div>
          <strong>Recommended next steps</strong>
          <ul style={{ margin: '6px 0 0', paddingLeft: 20 }}>
            {verdict.recommendations.map((item, i) => <li key={i}>{item}</li>)}
          </ul>
        </div>}
        <details>
          <summary>Technical details</summary>
          <div style={{ display: 'grid', gap: 12, marginTop: 12 }}>
            {record.records.map((raw, i) => (
              <pre key={i} class="mono" style={{ margin: 0, whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}><code>{raw}</code></pre>
            ))}
            {record.warnings.length > 0 && <ul style={{ margin: 0, paddingLeft: 20 }}>
              {record.warnings.map((warning, i) => <li key={i}>{warning}</li>)}
            </ul>}
            {details}
          </div>
        </details>
      </div>
    </section>
  );
}

export function EmailTab({ email }: { email?: EmailReport }) {
  if (!email) return <div class="empty">Email security was not assessed in this report.</div>;
  const { spf, dmarc } = email;
  const audit = spf.audit;
  return (
    <div class="section">
      <div class="card">
        <div class="card-head"><h3>Email security</h3><span class="pill info">Informational</span></div>
        <div class="card-body" style={{ display: 'grid', gap: 8 }}>
          <p style={{ margin: 0 }}>Email domain: <strong class="mono" style={{ overflowWrap: 'anywhere' }}>{email.domain}</strong></p>
          <p class="muted" style={{ margin: 0 }}>SPF and DMARC configuration checks, with no effect on TLS or HTTP grades.</p>
        </div>
      </div>
      <div class="grid-2" style={{ alignItems: 'start' }}>
        <PolicyCard title="SPF" record={spf} details={<>
          {spf.state === 'observed' && <p style={{ margin: 0 }}>
            {spf.all && <>First catch-all mechanism: <code>{spf.all}</code>.</>}
            {spf.redirect && <> Declared redirect: <code>{spf.redirect}</code>.</>}
          </p>}
          {audit && <>
            <p style={{ margin: 0 }}>DNS-causing terms counted: <strong>{audit.lookup_terms}</strong> / 10.
              {' '}Actual evaluation depends on the sender.</p>
            <div>SPF DNS names checked:
              <ul class="mono" style={{ margin: '6px 0 0', paddingLeft: 20 }}>
                {audit.queries.map((name) => <li key={name}>{name}</li>)}
              </ul>
            </div>
            {audit.limitations.length > 0 && <ul style={{ margin: 0, paddingLeft: 20 }}>
              {audit.limitations.map((item, i) => <li key={i}>{item}</li>)}
            </ul>}
          </>}
          <p class="muted" style={{ margin: 0 }}>Static include/redirect dependencies are inspected. Macros, address mechanisms and void-lookup limits are not evaluated.</p>
        </>}>
          {spf.state === 'observed' && <p class="muted" style={{ margin: 0 }}>
            {audit
              ? audit.complete
                ? 'Policy syntax and static SPF dependencies checked; no dependency errors detected.'
                : audit.issues.length > 0
                  ? 'Dependency errors were detected; see below.'
                  : 'Partial verification: some dependencies or sender-specific checks remain unverified.'
              : 'Dependency validation is unavailable in this report; run a fresh scan.'}
          </p>}
          {audit && audit.issues.length > 0 && <ul style={{ margin: 0, paddingLeft: 20 }}>
            {audit.issues.map((item, i) => <li key={i}>{item}</li>)}
          </ul>}
        </PolicyCard>
        <PolicyCard title="DMARC" record={dmarc} details={<>
          {dmarc.state === 'observed' && <>
            <p style={{ margin: 0 }}>
              {dmarc.inherited ? 'Inherited from' : 'Published at'} <code>_dmarc.{dmarc.policy_domain}</code>
              {' '}using <code>{dmarc.policy_tag}</code>.
            </p>
            {(dmarc.reporting_uris?.length ?? 0) > 0 && <div>Reporting destinations:
              <ul class="mono" style={{ margin: '6px 0 0', paddingLeft: 20 }}>
                {dmarc.reporting_uris!.map((uri, i) => <li key={i}>{uri}</li>)}
              </ul>
            </div>}
          </>}
          {dmarc.queries.length > 0 && <div>DMARC DNS names checked:
            <ul class="mono" style={{ margin: '6px 0 0', paddingLeft: 20 }}>
              {dmarc.queries.map((name) => <li key={name}>{name}</li>)}
            </ul>
          </div>}
          <p class="muted" style={{ margin: 0 }}>Policy discovery follows RFC 9989. External reporting authorization and report delivery are not verified.</p>
        </>}>
          {dmarc.state === 'observed' && <>
            <p style={{ margin: 0 }}>
              Requested policy: <strong>{dmarc.policy}</strong>.
              {dmarc.testing && ' Testing mode is reflected in this policy.'}
            </p>
            <p style={{ margin: 0 }}>Aggregate reports: <strong>
              {dmarc.reporting_state === 'configured' ? 'Requested'
                : dmarc.reporting_state === 'absent' ? 'Not requested (no rua)'
                : dmarc.reporting_state === 'invalid' ? 'No valid reporting destination'
                : 'Unassessed in this report'}
            </strong>.</p>
          </>}
        </PolicyCard>
      </div>
      <p class="muted" style={{ margin: 0 }}>
        These DNS checks do not authenticate a message or establish whether the domain sends email.
        {' '}SPF/DKIM alignment is not verified. DKIM is not assessed: a selector from the sending system is required.
      </p>
    </div>
  );
}
