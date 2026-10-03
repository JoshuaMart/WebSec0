import assert from 'node:assert/strict';
import test from 'node:test';
import render from 'preact-render-to-string';
import { TabPanel } from '../src/islands/Report.tsx';
import type { TLSReport } from '../src/islands/report-types.ts';

const leafID = 'ab'.repeat(32);
const handshakeID = 'cd'.repeat(32);
const empty = { count: 0, log_ids: [], unparsed_count: 0 };

function tlsReport(scts: Pick<TLSReport, 'handshake_scts' | 'certificate_scts'> = {}): TLSReport {
  return {
    grade: '',
    scores: { certificate: 0, protocol_support: 0, key_exchange: 0, cipher_strength: 0, final: 0 },
    protocols: [], ciphers: [], certificate_chain: [], vulnerabilities: [],
    chain_trust: '', ocsp_stapling: false,
    ...scts,
  };
}

function renderCertificateTab(tls?: TLSReport): string {
  return render(<TabPanel id="certificate" data={{
    id: 'fixture', host: 'example.test', port: 443, resolved_ip: '',
    scanned_at: '2026-01-01T00:00:00Z', duration_ms: 0, tls,
  }} />);
}

function source(html: string, title: 'Leaf certificate' | 'TLS handshake'): string {
  const matches = [...html.matchAll(new RegExp(`<section\\b[^>]*aria-label="${title}"[^>]*>([\\s\\S]*?)</section>`, 'g'))];
  assert.equal(matches.length, 1, `expected one ${title} section`);
  return matches[0][1];
}

function logIDs(html: string): string[] {
  return [...html.matchAll(/<li>([^<]*)<\/li>/g)].map((match) => match[1]);
}

test('certificate tab keeps SCT counts and log IDs attached to their sources', () => {
  const html = renderCertificateTab(tlsReport({
    certificate_scts: {
      present: true, parse_error: false,
      count: 3, log_ids: [leafID], unparsed_count: 1,
    },
    handshake_scts: { count: 2, log_ids: [leafID, handshakeID], unparsed_count: 0 },
  }));
  const leaf = source(html, 'Leaf certificate');
  const handshake = source(html, 'TLS handshake');
  assert.match(html, /<h3>Certificate Transparency<\/h3>/);
  assert.match(html, /class="pill info"/);
  assert.match(leaf, /3 SCTs embedded in the leaf certificate/);
  assert.match(leaf, /1 could not be decoded/);
  assert.deepEqual(logIDs(leaf), [leafID]);
  assert.match(handshake, /2 SCTs received via the TLS extension/);
  assert.doesNotMatch(handshake, /could not be decoded/);
  assert.deepEqual(logIDs(handshake), [leafID, handshakeID]);
  assert.match(html, /no effect on the grade/);
  assert.match(html, /SCT signatures and log inclusion are not verified/);
  assert.match(html, /SCTs in OCSP responses are not assessed/);
});

for (const [name, tls] of [['old report', tlsReport()], ['missing TLS report', undefined]] as const) {
  test(`certificate tab renders unavailable SCTs for ${name}`, () => {
    const html = renderCertificateTab(tls);
    assert.match(source(html, 'Leaf certificate'), /Certificate SCT data unavailable/);
    assert.match(source(html, 'TLS handshake'), /TLS handshake SCT data unavailable/);
    assert.doesNotMatch(html, /No SCT|0 SCT|Log IDs|<li>/);
  });
}

test('certificate tab distinguishes observed absence from unavailable SCT data', () => {
  const html = renderCertificateTab(tlsReport({
    certificate_scts: { ...empty, present: false, parse_error: false },
    handshake_scts: empty,
  }));
  assert.match(source(html, 'Leaf certificate'), /No SCT extension observed in the leaf certificate/);
  assert.match(source(html, 'TLS handshake'), /No SCTs observed via the TLS extension/);
  assert.doesNotMatch(html, /unavailable|malformed|Log IDs|<li>/);
});

test('malformed certificate SCTs leave the handshake observations visible', () => {
  const html = renderCertificateTab(tlsReport({
    certificate_scts: { ...empty, present: true, parse_error: true },
    handshake_scts: { count: 1, log_ids: [handshakeID], unparsed_count: 0 },
  }));
  const leaf = source(html, 'Leaf certificate');
  assert.match(leaf, /extension is malformed/);
  assert.match(leaf, /count is unavailable/);
  assert.doesNotMatch(leaf, /No SCT|0 SCT|Log IDs|<li>/);
  const handshake = source(html, 'TLS handshake');
  assert.match(handshake, /1 SCT received via the TLS extension/);
  assert.deepEqual(logIDs(handshake), [handshakeID]);
});

test('undecodable SCTs retain their counts without displaying an empty log list', () => {
  const undecodable = { count: 1, log_ids: [], unparsed_count: 1 };
  const html = renderCertificateTab(tlsReport({
    certificate_scts: { ...undecodable, present: true, parse_error: false },
    handshake_scts: undecodable,
  }));
  assert.match(source(html, 'Leaf certificate'), /1 SCT embedded/);
  assert.match(source(html, 'TLS handshake'), /1 SCT received/);
  for (const title of ['Leaf certificate', 'TLS handshake'] as const) {
    assert.match(source(html, title), /1 could not be decoded/);
  }
  assert.doesNotMatch(html, /unavailable|No SCT|Log IDs|<ul/);
});

test('each SCT source remains visible when the other observation is unavailable', () => {
  const certificateOnly = renderCertificateTab(tlsReport({
    certificate_scts: { present: true, parse_error: false, count: 1, log_ids: [leafID], unparsed_count: 0 },
  }));
  assert.deepEqual(logIDs(source(certificateOnly, 'Leaf certificate')), [leafID]);
  assert.match(source(certificateOnly, 'TLS handshake'), /unavailable/);
  const handshakeOnly = renderCertificateTab(tlsReport({
    handshake_scts: { count: 1, log_ids: [handshakeID], unparsed_count: 0 },
  }));
  assert.match(source(handshakeOnly, 'Leaf certificate'), /unavailable/);
  assert.deepEqual(logIDs(source(handshakeOnly, 'TLS handshake')), [handshakeID]);
});
