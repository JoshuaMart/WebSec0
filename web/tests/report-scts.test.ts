import assert from 'node:assert/strict';
import test from 'node:test';
import { sctSummary } from '../src/islands/report-scts.ts';

test('unavailable and observed absence have different messages', () => {
  assert.match(sctSummary(), /unavailable/);
  assert.equal(sctSummary({ count: 0, log_ids: [], unparsed_count: 0 }),
    'No SCTs observed via the TLS extension.');
});

test('SCT count includes multiple entries from the same log', () => {
  const ids = ['ab'.repeat(32)];
  assert.equal(sctSummary({ count: 1, log_ids: ids, unparsed_count: 0 }),
    '1 SCT received via the TLS extension.');
  assert.equal(sctSummary({ count: 2, log_ids: ids, unparsed_count: 0 }),
    '2 SCTs received via the TLS extension.');
});

test('unparsed SCTs remain visible even when no log ID can be extracted', () => {
  const summary = sctSummary({ count: 2, log_ids: [], unparsed_count: 2 });
  assert.match(summary, /^2 SCTs received/);
  assert.match(summary, /2 could not be decoded/);
  assert.doesNotMatch(summary, /No SCTs|unavailable/);
});

test('partially decoded SCTs retain the total and unparsed count', () => {
  assert.equal(sctSummary({ count: 3, log_ids: ['ab'.repeat(32)], unparsed_count: 1 }),
    '3 SCTs received via the TLS extension. 1 could not be decoded (malformed or unsupported version).');
});
