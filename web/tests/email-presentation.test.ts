import test from 'node:test';
import assert from 'node:assert/strict';
import {
  spfView,
  dmarcView,
  emailSummary,
} from '../src/islands/email-presentation.ts';
import type { EmailReport } from '../src/islands/report-types.ts';

function spf(overrides: Partial<EmailReport['spf']> = {}): EmailReport['spf'] {
  return {
    id: 'email.spf',
    state: 'observed',
    records: ['v=spf1 include:mail.example.com ~all'],
    warnings: [],
    includes: ['mail.example.com'],
    all: '~all',
    assessment: {
      status: 'info',
      title: 'SPF softfail policy',
      summary: 'Softfail is a valid choice.',
      recommendations: [],
    },
    audit: {
      complete: false,
      lookup_terms: 1,
      lookup_limit_exceeded: false,
      queries: [],
      issues: [],
      limitations: ['Sender context required.'],
    },
    ...overrides,
  };
}
function dmarc(
  overrides: Partial<EmailReport['dmarc']> = {},
): EmailReport['dmarc'] {
  return {
    id: 'email.dmarc',
    state: 'observed',
    records: ['v=DMARC1; p=none'],
    warnings: [],
    policy: 'none',
    inherited: false,
    testing: false,
    queries: [],
    reporting_state: 'absent',
    assessment: {
      status: 'warn',
      title: 'No enforcement or reports',
      summary: 'No enforcement or usable reporting.',
      recommendations: [],
    },
    ...overrides,
  };
}

test('valid softfail with incomplete dependencies is neither invalid nor fully verified', () => {
  const view = spfView(spf());
  assert.equal(view.label, 'Partially verified');
  assert.equal(view.level, 'info');
  assert.equal(view.checks[0].value, 'Valid');
  assert.match(view.checks[1].note!, /valid policy choice/);
  assert.equal(view.checks[2].value, 'Verification incomplete');
});

test('valid p=none without rua needs improvement despite a syntactically valid record', () => {
  const view = dmarcView(dmarc());
  assert.equal(view.label, 'Needs improvement');
  assert.equal(view.checks[0].value, 'Valid');
  assert.equal(view.checks[1].value, 'No action requested (p=none)');
  assert.equal(view.checks[2].value, 'Not configured');
  assert.equal(emailSummary(spfView(spf()), view).level, 'warn');
});

test('DMARC with reporting but no enforcement remains a review item', () => {
  const view = dmarcView(dmarc({ reporting_state: 'configured' }));
  assert.equal(view.level, 'warn');
  assert.equal(view.checks[2].value, 'Configured');
  assert.match(view.summary, /Reports are requested, but blocking is not/);
});

test('missing reporting information is never rendered as reports not configured', () => {
  const view = dmarcView(
    dmarc({
      policy: 'reject',
      reporting_state: undefined,
      assessment: undefined,
    }),
  );
  assert.equal(view.level, 'info');
  assert.equal(view.checks[2].value, 'Not available in this report');
  assert.doesNotMatch(JSON.stringify(view.checks), /Not configured/);
});

test('a complete configured policy has a scoped positive verdict', () => {
  const view = dmarcView(
    dmarc({
      policy: 'reject',
      reporting_state: 'configured',
      assessment: {
        status: 'pass',
        title: 'DMARC rejection requested',
        summary: 'Rejection requested.',
        recommendations: [],
      },
    }),
  );
  assert.equal(view.level, 'good');
  assert.equal(view.label, 'Checks passed');
  assert.equal(
    dmarcView(
      dmarc({ policy: 'reject', reporting_state: 'configured', testing: true }),
    ).level,
    'warn',
  );
});

test('DNS failures remain distinct from missing or invalid policies', () => {
  for (const state of ['absent', 'invalid', 'unavailable'] as const) {
    const view = spfView(spf({ state }));
    assert.doesNotMatch(JSON.stringify(view.checks), /"Valid"/);
    assert.equal(
      view.label,
      state === 'absent'
        ? 'Missing policy'
        : state === 'invalid'
          ? 'Invalid record'
          : 'Check incomplete',
    );
  }
});

test('dependency errors outrank a valid SPF root record', () => {
  const policy = spf();
  policy.audit!.issues = ['Missing referenced policy.'];
  const view = spfView(policy);
  assert.equal(view.level, 'bad');
  assert.equal(view.label, 'Needs fixing');
  assert.equal(view.checks[2].value, 'Errors detected');
});

test('parsed policies with warnings are not declared unconditionally valid', () => {
  const view = dmarcView(
    dmarc({ warnings: ['Invalid policy value; reporting fallback used.'] }),
  );
  assert.equal(view.level, 'warn');
  assert.equal(view.checks[0].value, 'Review warnings');
  assert.doesNotMatch(view.summary, /record is valid/);
});

test('unfamiliar informational assessments never become a passing verdict', () => {
  const policy = spf();
  policy.audit!.complete = true;
  policy.assessment!.title = 'New assessment';
  assert.equal(spfView(policy).level, 'info');
  assert.equal(
    dmarcView(
      dmarc({
        policy: 'reject',
        reporting_state: 'configured',
        assessment: { ...policy.assessment! },
      }),
    ).level,
    'info',
  );
});
