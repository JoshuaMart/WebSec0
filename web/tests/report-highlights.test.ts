import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deriveHighlights } from '../src/islands/report-highlights.ts';
import type { ScanResult, TLSReport, HeadersReport, ProtocolSupport } from '../src/islands/report-types.ts';

function report(parts: Partial<ScanResult>): ScanResult {
  return { id: 'fixture', host: 'example.test', port: 443, resolved_ip: '', scanned_at: '', duration_ms: 0, ...parts };
}
function tls(protocols: ProtocolSupport[], scan_status: TLSReport['scan_status'] = 'complete'): TLSReport {
  return { grade: '', scores: { certificate: 0, protocol_support: 0, key_exchange: 0, cipher_strength: 0, final: 0 }, protocols, scan_status, ciphers: [], certificate_chain: [], chain_trust: '', ocsp_stapling: false, vulnerabilities: [] };
}
function headers(parts: Partial<HeadersReport>): HeadersReport {
  return { grade: '', score: 0, core: {}, additional: {}, ...parts };
}
const complete = ['TLS 1.3', 'TLS 1.2', 'TLS 1.1', 'TLS 1.0', 'SSL 3.0', 'SSL 2.0'].map((name) => ({ name, offered: ['TLS 1.3', 'TLS 1.2'].includes(name), probe: name.startsWith('SSL') ? 'raw_clienthello' : 'stdlib' }));
const legacyPraise = (data: ScanResult) => deriveHighlights(data).some((h) => h.title === 'TLS 1.3 with no legacy fallback');

test('only a complete negative legacy check earns the positive highlight', () => {
  assert.equal(legacyPraise(report({ tls: tls(complete) })), true);
  assert.equal(legacyPraise(report({ tls: tls(complete, 'partial_blocked') })), false);
  for (const name of ['TLS 1.0', 'TLS 1.1', 'SSL 3.0', 'SSL 2.0']) {
    assert.equal(legacyPraise(report({ tls: tls(complete.map((p) => p.name === name ? { ...p, probe: 'aborted' } : p)) })), false);
    assert.equal(legacyPraise(report({ tls: tls(complete.filter((p) => p.name !== name)) })), false);
    assert.equal(legacyPraise(report({ tls: tls(complete.map((p) => p.name === name ? { ...p, offered: true } : p)) })), false);
  }
});

test('header highlights follow backend classifications, including absent XFO covered by CSP', () => {
  const result = deriveHighlights(report({ headers: headers({ core: {
    'strict-transport-security': { present: true, value: 'max-age=20000000; includeSubDomains', status: 'warn' },
    'content-security-policy': { present: true, value: "style-src 'unsafe-inline'; script-src 'self'", status: 'pass' },
    'x-frame-options': { present: false, status: 'pass' },
  }, additional: { 'cross-origin-opener-policy': { present: true, value: 'unsafe-none', status: 'warn' } } }) }));
  assert.equal(result.find((h) => h.title.startsWith('HSTS'))?.level, 'warn');
  assert.equal(result.find((h) => h.title.startsWith('Content-Security'))?.level, 'good');
  assert.equal(result.find((h) => h.title.startsWith('Clickjacking'))?.level, 'good');
  assert.equal(result.find((h) => h.title === 'cross-origin-opener-policy')?.level, 'warn');
});

test('cookie highlights use the backend status for SameSite and non-session cookies', () => {
  const data = report({ headers: headers({ additional: { 'set-cookie': [
    { name: 'theme', secure: true, httponly: false, samesite: 'Lax', status: 'pass' },
    { name: 'session', secure: true, httponly: true, samesite: null, status: 'warn' },
  ] } }) });
  const finding = deriveHighlights(data).find((h) => h.title.includes('cookie'));
  assert.equal(finding?.level, 'warn');
  assert.match(finding?.body ?? '', /session/);
  assert.doesNotMatch(finding?.body ?? '', /theme/);
});

test('HSTS directives do not claim preload-list membership', () => {
  const result = deriveHighlights(report({ headers: headers({ core: {
    'strict-transport-security': { present: true, value: 'max-age=31536000; includeSubDomains; preload', status: 'pass' },
  } }) }));
  assert.equal(result[0].level, 'good');
  assert.doesNotMatch(result[0].title, /preloaded/i);
});

test('incomplete custom responses are shown as not assessed', () => {
  const result = deriveHighlights(report({ custom: [{
    id: 'custom.security_txt', title: 'security.txt', status: 'info',
    details: { note: 'Incomplete response: unexpected EOF', rfc9116_compliant: false },
  }] }));
  assert.equal(result[0].level, 'info');
  assert.match(result[0].title, /not assessed/);
  assert.match(result[0].body, /Incomplete response/);
});
