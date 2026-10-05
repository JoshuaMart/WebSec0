import type { ComponentChildren } from 'preact';
import type { DNSRecord, EmailReport } from './report-types.ts';
import { spfView, dmarcView, emailSummary } from './email-presentation.ts';
import type { EmailPolicyView } from './email-presentation.ts';

const states: Record<DNSRecord['state'], string> = {
  observed: 'Assessment unavailable',
  absent: 'No record found',
  invalid: 'Invalid configuration',
  unavailable: 'DNS unavailable',
};

function PolicyCard({
  protocol,
  record,
  presentation,
  details,
}: {
  protocol: 'SPF' | 'DMARC';
  record: DNSRecord;
  presentation: EmailPolicyView;
  details?: ComponentChildren;
}) {
  const verdict = record.assessment;
  return (
    <section class="card email-policy" aria-label={protocol}>
      <div class="card-head">
        <div>
          <h3>{protocol}</h3>
          <p class="email-purpose">
            {protocol === 'SPF'
              ? 'Who is allowed to send?'
              : 'What happens if authentication fails?'}
          </p>
        </div>
        <span class={`pill ${presentation.level}`}>{presentation.label}</span>
      </div>
      <div class="card-body email-policy-body">
        <dl class="email-checks">
          {presentation.checks.map((check) => (
            <div class="email-check" key={check.label}>
              <dt>{check.label}</dt>
              <dd>
                <span class={`email-check-value ${check.level}`}>
                  <span aria-hidden="true">
                    {check.level === 'good'
                      ? '✓'
                      : check.level === 'bad'
                        ? '×'
                        : check.level === 'warn'
                          ? '!'
                          : 'i'}
                  </span>
                  {check.value}
                </span>
                {check.note && <p>{check.note}</p>}
              </dd>
            </div>
          ))}
        </dl>
        {presentation.next && (
          <div class="email-next">
            <span class="report-eyebrow">Next step</span>
            <p>{presentation.next}</p>
          </div>
        )}
      </div>
      <details class="email-evidence">
        <summary>
          View DNS records & check details <span aria-hidden="true">+</span>
        </summary>
        <div class="email-evidence-body">
          {record.records.length > 0 && (
            <div>
              <h4>Published records</h4>
              {record.records.map((raw, i) => (
                <pre key={i}>
                  <code>{raw}</code>
                </pre>
              ))}
            </div>
          )}
          <div>
            <h4>Scanner assessment</h4>
            {verdict ? (
              <>
                <strong>{verdict.title}</strong>
                <p>{verdict.summary}</p>
              </>
            ) : (
              <p>{states[record.state]}.</p>
            )}
          </div>
          {record.warnings.length > 0 && (
            <div>
              <h4>Warnings</h4>
              <ul>
                {record.warnings.map((warning, i) => (
                  <li key={i}>{warning}</li>
                ))}
              </ul>
            </div>
          )}
          {details}
          {verdict && verdict.recommendations.length > 0 && (
            <div>
              <h4>Recommended next steps</h4>
              <ul>
                {verdict.recommendations.map((item, i) => (
                  <li key={i}>{item}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </details>
    </section>
  );
}

export function EmailTab({ email }: { email?: EmailReport }) {
  if (!email)
    return (
      <div class="empty">Email security was not assessed in this report.</div>
    );
  const { spf, dmarc } = email;
  const audit = spf.audit;
  const spfPresentation = spfView(spf);
  const dmarcPresentation = dmarcView(dmarc);
  const summary = emailSummary(spfPresentation, dmarcPresentation);
  return (
    <div class="section email-section">
      <p class="email-domain">
        Email domain: <strong class="mono">{email.domain}</strong>
      </p>
      <div class={`email-summary ${summary.level}`}>
        <span class="email-summary-icon" aria-hidden="true">
          {summary.level === 'good'
            ? '✓'
            : summary.level === 'bad'
              ? '×'
              : summary.level === 'warn'
                ? '!'
                : 'i'}
        </span>
        <div>
          <h3>{summary.title}</h3>
          <p>{summary.summary}</p>
        </div>
      </div>
      <div class="email-grid">
        <PolicyCard
          protocol="SPF"
          record={spf}
          presentation={spfPresentation}
          details={
            <>
              {spf.state === 'observed' && (
                <p>
                  {spf.all && (
                    <>
                      First catch-all mechanism: <code>{spf.all}</code>.
                    </>
                  )}
                  {spf.redirect && (
                    <>
                      {' '}
                      Declared redirect: <code>{spf.redirect}</code>.
                    </>
                  )}
                </p>
              )}
              {audit && (
                <>
                  {audit.complete && (
                    <p>
                      Policy syntax and static SPF dependencies checked; no
                      dependency errors detected.
                    </p>
                  )}
                  <p>
                    DNS-causing terms counted:{' '}
                    <strong>{audit.lookup_terms}</strong> / 10. Actual
                    evaluation depends on the sender.
                  </p>
                  {audit.issues.length > 0 && (
                    <div>
                      <h4>Dependency errors</h4>
                      <ul>
                        {audit.issues.map((issue, i) => (
                          <li key={i}>{issue}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                  <div>
                    <h4>SPF DNS names checked</h4>
                    <ul class="mono">
                      {audit.queries.map((name) => (
                        <li key={name}>{name}</li>
                      ))}
                    </ul>
                  </div>
                  {audit.limitations.length > 0 && (
                    <div>
                      <h4>Checks that remain incomplete</h4>
                      <ul>
                        {audit.limitations.map((item, i) => (
                          <li key={i}>{item}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </>
              )}
              <p class="muted">
                Static include/redirect dependencies are inspected. Macros,
                address mechanisms and void-lookup limits are not evaluated.
              </p>
            </>
          }
        ></PolicyCard>
        <PolicyCard
          protocol="DMARC"
          record={dmarc}
          presentation={dmarcPresentation}
          details={
            <>
              {dmarc.state === 'observed' && (
                <>
                  <p>
                    Requested policy:{' '}
                    <strong>{dmarc.policy || 'Undetermined'}</strong>.
                    {dmarc.testing &&
                      ' Testing mode is reflected in this policy.'}
                  </p>
                  {dmarc.policy_domain && (
                    <p>
                      {dmarc.inherited ? 'Inherited from' : 'Published at'}{' '}
                      <code>_dmarc.{dmarc.policy_domain}</code>
                      {dmarc.policy_tag && (
                        <>
                          {' '}
                          using <code>{dmarc.policy_tag}</code>
                        </>
                      )}
                      .
                    </p>
                  )}
                  <p>
                    Aggregate reports:{' '}
                    <strong>
                      {dmarc.reporting_state === 'configured'
                        ? 'Requested'
                        : dmarc.reporting_state === 'absent'
                          ? 'Not requested (no rua)'
                          : dmarc.reporting_state === 'invalid'
                            ? 'No valid reporting destination'
                            : 'Unassessed in this report'}
                    </strong>
                    .
                  </p>
                  {!!dmarc.reporting_uris?.length && (
                    <div>
                      <h4>Reporting destinations</h4>
                      <ul class="mono">
                        {dmarc.reporting_uris.map((uri, i) => (
                          <li key={i}>{uri}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </>
              )}
              {dmarc.queries.length > 0 && (
                <div>
                  <h4>DMARC DNS names checked</h4>
                  <ul class="mono">
                    {dmarc.queries.map((name) => (
                      <li key={name}>{name}</li>
                    ))}
                  </ul>
                </div>
              )}
              <p class="muted">
                Policy discovery follows RFC 9989. External reporting
                authorization and report delivery are not verified.
              </p>
            </>
          }
        ></PolicyCard>
      </div>
      <details class="coverage-details email-scope">
        <summary>What these checks cover</summary>
        <div class="coverage-body">
          <p>
            SPF and DMARC configuration checks have no effect on TLS or HTTP
            grades.
          </p>
          <p>
            These DNS checks do not authenticate a message or establish whether
            the domain sends email. SPF/DKIM alignment is not verified. DKIM is
            not assessed: a selector from the sending system is required.
          </p>
        </div>
      </details>
    </div>
  );
}
