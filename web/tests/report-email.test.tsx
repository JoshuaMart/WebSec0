import assert from 'node:assert/strict';
import test from 'node:test';
import render from 'preact-render-to-string';
import { TabPanel, Tabs } from '../src/islands/Report.tsx';
import { deriveHighlights } from '../src/islands/report-highlights.ts';
import type { DNSRecord, EmailReport, ScanResult } from '../src/islands/report-types.ts';

const metadata: ScanResult = {
  id: 'fixture', host: 'www.example.com', port: 443, resolved_ip: '',
  scanned_at: '2026-01-01T00:00:00Z', duration_ms: 0,
};

function report(state: DNSRecord['state'] = 'observed'): EmailReport {
  return {
    domain: 'example.com',
    spf: { id: 'email.spf', state, records: [], warnings: [], includes: [] },
    dmarc: {
      id: 'email.dmarc', state, records: [], warnings: [],
      inherited: false, testing: false, queries: ['_dmarc.example.com'],
    },
  };
}

function panel(email?: EmailReport) {
  return render(<TabPanel id="email" data={{ ...metadata, email }} />);
}

test('email tab identifies the selected domain and stays informational', () => {
  const email = report();
  email.spf.all = '-all';
  email.spf.records = ['v=spf1 -all'];
  email.dmarc.policy = 'reject';
  email.dmarc.policy_domain = 'example.com';
  email.dmarc.policy_tag = 'p';
  email.dmarc.records = ['v=DMARC1; p=reject'];
  const html = panel(email);
  assert.match(html, /Email domain:.*example.com/);
  assert.doesNotMatch(html, /www.example.com/);
  assert.match(html, /no effect on TLS or HTTP grades/);
  assert.match(html, /Assessment unavailable/);
  assert.match(html, /First catch-all mechanism: <code>-all/);
  assert.match(html, /Requested policy: <strong>reject/);
  assert.match(html, /Published at.*_dmarc.example.com/);
  assert.match(html, /Static include\/redirect dependencies are inspected/);
  assert.match(html, /DKIM is not assessed/);
  assert.deepEqual(deriveHighlights({ ...metadata, email }), deriveHighlights(metadata));
});

test('old reports and skipped subdomains have no email tab or implied absence', () => {
  const tabs = (email?: EmailReport) => render(<Tabs active="overview" onChange={() => {}} data={{ ...metadata, email }} />);
  assert.doesNotMatch(tabs(), /Email security/);
  assert.match(tabs(report()), /Email security/);
  assert.match(panel(), /not assessed/);
  assert.doesNotMatch(panel(), /No record|DNS unavailable/);
});

test('DNS absence, invalid records and lookup failures stay distinct', () => {
  for (const [state, expected] of [
    ['absent', 'No record found'],
    ['invalid', 'Invalid configuration'],
    ['unavailable', 'DNS unavailable'],
  ] as const) {
    const html = panel(report(state));
    assert.match(html, new RegExp(expected));
    assert.doesNotMatch(html, /Requested policy|First catch-all|Record observed/);
    if (state !== 'absent') assert.doesNotMatch(html, /No record found|No SPF TXT record was found/);
  }
});

test('parent policy and testing mode are displayed without attributing the TXT to the child', () => {
  const email = report();
  email.domain = 'tenant.github.io';
  email.dmarc = {
    ...email.dmarc, policy: 'quarantine', policy_domain: 'github.io',
    policy_tag: 'sp', inherited: true, testing: true,
    queries: ['_dmarc.tenant.github.io', '_dmarc.github.io'],
  };
  const html = panel(email);
  assert.match(html, /Inherited from <code>_dmarc.github.io/);
  assert.match(html, /using <code>sp/);
  assert.match(html, /Testing mode is reflected/);
  assert.match(html, /DNS names checked/);
});

test('TXT records and DNS diagnostics render as escaped text', () => {
  const email = report('invalid');
  email.spf.records = ['v=spf1 <script>alert("record")</script>'];
  email.spf.warnings = ['<img src=x onerror=alert(1)>'];
  const html = panel(email);
  assert.doesNotMatch(html, /<script>|<img /);
  assert.match(html, /&lt;script>/);
  assert.match(html, /&lt;img /);
});

test('softfail and DMARC without rua provide actionable verdicts without claiming monitoring', () => {
  const email = report();
  email.spf.all = '~all';
  email.spf.assessment = {
    status: 'info', title: 'SPF softfail policy',
    summary: 'This is a valid policy, not a configuration error.',
    recommendations: ['Confirm that every legitimate sender is covered.'],
  };
  email.spf.audit = {
    complete: true, lookup_terms: 1, lookup_limit_exceeded: false,
    queries: ['example.com', 'mx.provider.example.com'], issues: [], limitations: [],
  };
  email.dmarc.policy = 'none';
  email.dmarc.reporting_state = 'absent';
  email.dmarc.reporting_uris = [];
  email.dmarc.assessment = {
    status: 'warn', title: 'No enforcement or reports',
    summary: 'No rejection, quarantine or usable aggregate reporting destination.',
    recommendations: ['Add a valid rua reporting address.'],
  };
  const html = panel(email);
  assert.match(html, /SPF softfail policy/);
  assert.match(html, /no dependency errors detected/);
  assert.match(html, /No enforcement or reports/);
  assert.match(html, /Not requested \(no rua\)/);
  assert.match(html, /Recommended next steps/);
  assert.match(html, /Add a valid rua/);
  assert.match(html, /class="pill warn">Review/);
  assert.doesNotMatch(html, /monitoring|Record observed|Invalid SPF configuration/);
  assert.match(html, /<details><summary>Technical details/);
});

test('broken dependencies surface their diagnostics and a correction', () => {
  const email = report();
  email.spf.assessment = {
    status: 'fail', title: 'Broken SPF dependencies',
    summary: 'A referenced policy is missing.',
    recommendations: ['Correct the include at missing.example.com.'],
  };
  email.spf.audit = {
    complete: false, lookup_terms: 1, lookup_limit_exceeded: false,
    queries: ['example.com', 'missing.example.com'],
    issues: ['No SPF policy at missing.example.com.'], limitations: [],
  };
  const html = panel(email);
  assert.match(html, /class="pill bad">Error/);
  assert.match(html, /Broken SPF dependencies/);
  assert.match(html, /No SPF policy at missing.example.com/);
  assert.doesNotMatch(html, /no dependency errors detected/);
});

test('partial SPF audit never claims all dependencies passed', () => {
  const email = report();
  email.spf.audit = {
    complete: false, lookup_terms: 1, lookup_limit_exceeded: false,
    queries: ['example.com'], issues: [],
    limitations: ['Macro-based dependencies need sender context.'],
  };
  const html = panel(email);
  assert.match(html, /Partial verification/);
  assert.match(html, /Macro-based dependencies need sender context/);
  assert.doesNotMatch(html, /no dependency errors detected/);
});

test('reporting is not inferred for old reports and invalid destinations are explicit', () => {
  const email = report();
  let html = panel(email);
  assert.match(html, /Unassessed in this report/);
  assert.doesNotMatch(html, /Not requested \(no rua\)|monitoring/);
  email.dmarc.reporting_state = 'invalid';
  html = panel(email);
  assert.match(html, /No valid reporting destination/);
  email.dmarc.reporting_state = 'configured';
  email.dmarc.reporting_uris = ['mailto:reports@example.com'];
  html = panel(email);
  assert.match(html, /Aggregate reports: <strong>Requested/);
  assert.match(html, /mailto:reports@example.com/);
  assert.doesNotMatch(html, /href="mailto:/);
});
