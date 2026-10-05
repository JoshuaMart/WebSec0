import assert from 'node:assert/strict';
import test from 'node:test';
import render from 'preact-render-to-string';
import { deriveHighlights } from '../src/islands/report-highlights.ts';
import { reportFixture } from './fixtures/report.ts';
import { GradePanel, Tabs, TabPanel } from '../src/islands/Report.tsx';
import type { ScanResult } from '../src/islands/report-types.ts';

const metadata: ScanResult = {
  id: 'fixture',
  host: 'example.com',
  port: 443,
  resolved_ip: '',
  scanned_at: '2026-01-01T00:00:00Z',
  duration_ms: 0,
};

test('missing assessments have neutral grades and do not imply a zero headers score', () => {
  const html = render(<GradePanel data={metadata} />);
  assert.match(html, /TLS assessment unavailable/);
  assert.match(html, /HTTP headers assessment unavailable/);
  assert.doesNotMatch(html, /0\/100|var\(--bad\)/);
  assert.match(html, /var\(--muted-2\)/);
});

test('certificate trust failure retains its failure color', () => {
  const html = render(
    <GradePanel
      data={{
        ...metadata,
        tls: {
          grade: 'T',
          chain_trust: 'expired',
          scores: {
            final: 0,
            certificate: 0,
            protocol_support: 100,
            key_exchange: 100,
            cipher_strength: 100,
          },
        } as ScanResult['tls'],
      }}
    />,
  );
  assert.match(html, /Grade T/);
  assert.match(html, /stroke="var\(--bad\)"/);
  assert.match(html, /expired/);
});

test('only the active report tab is in the sequential keyboard order', () => {
  const html = render(
    <Tabs active="headers" onChange={() => {}} data={metadata} />,
  );
  assert.equal((html.match(/tabindex="0"/g) ?? []).length, 1);
  assert.match(
    html,
    /id="tab-headers" aria-selected="true" aria-controls="panel-headers" tabindex="0"/,
  );
  assert.match(html, /aria-label="Report sections"/);
  assert.equal((html.match(/role="tab"/g) ?? []).length, 7);
});

test('a report without assessments does not claim a completed clean scan', () => {
  const highlights = deriveHighlights(metadata);
  assert.equal(highlights[0].title, 'Assessment unavailable');
  assert.match(
    highlights[0].body,
    /Missing data does not establish a passing result/,
  );
});

test('core header statuses are not presented as invented numerical scores', () => {
  const html = render(
    <GradePanel data={{ ...metadata, headers: reportFixture.headers }} />,
  );
  assert.match(html, /75\/100/);
  assert.match(html, />Fail</);
  assert.doesNotMatch(html, /100\/100|50\/100|0\/100/);
});

test('overview links connect observations to their evidence sections', () => {
  const html = render(<TabPanel id="overview" data={reportFixture} />);
  assert.match(html, /href="#headers"/);
  assert.match(html, /href="#protocols"/);
  assert.match(html, /href="#ciphers"/);
});

test('cipher details are native disclosures and non-AEAD is not inferred to mean CBC', () => {
  const data = {
    ...reportFixture,
    tls: {
      ...reportFixture.tls!,
      ciphers: [
        {
          protocol: 'TLS 1.2',
          name: 'TLS_RSA_WITH_RC4_128_SHA',
          code: '0x0005',
          strength: 128,
          aead: false,
          pfs: false,
          level: 'bad' as const,
        },
      ],
    },
  };
  const html = render(<TabPanel id="ciphers" data={data} />);
  assert.match(html, /<details class="cipher-detail"><summary>/);
  assert.match(html, /Non-AEAD/);
  assert.match(html, /RC4-128/);
  assert.doesNotMatch(html, /CBC|Hover for details/);
});

test('headers preserve absence, passing alternative protection, and unreported observations', () => {
  const data = {
    ...metadata,
    headers: {
      grade: 'A' as const,
      score: 90,
      core: { 'x-frame-options': { present: false, status: 'pass' as const } },
      additional: {},
    },
  };
  const html = render(<TabPanel id="headers" data={data} />);
  assert.match(html, /Header not present/);
  assert.match(html, />Pass</);
  assert.match(html, /Not reported/);
});

test('unavailable chain does not claim a trust failure or T cap', () => {
  const data = {
    ...metadata,
    tls: {
      ...reportFixture.tls!,
      chain_trust: 'no_chain',
      certificate_chain: [],
      protocols: [],
      ciphers: [],
      vulnerabilities: [],
    },
  };
  const highlights = deriveHighlights(data);
  assert.match(highlights[0].title, /trust not assessed/);
  assert.equal(highlights[0].level, 'info');
  assert.doesNotMatch(
    JSON.stringify(highlights),
    /capped at T|does not validate/,
  );
});

test('expired certificate and configuration indicators are accurately qualified', () => {
  const data = {
    ...metadata,
    tls: {
      ...reportFixture.tls!,
      protocols: [{ name: 'SSL 3.0', offered: true, probe: 'raw_clienthello' }],
      certificate_chain: [
        { ...reportFixture.tls!.certificate_chain[0], days_left: -2 },
      ],
    },
  };
  const highlights = deriveHighlights(data);
  assert.ok(highlights.some((h) => h.title === 'Leaf certificate has expired'));
  assert.doesNotMatch(
    JSON.stringify(highlights),
    /are exploitable|only -2 days/,
  );
});
