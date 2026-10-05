import assert from 'node:assert/strict';
import test from 'node:test';
import render from 'preact-render-to-string';
import { deriveHighlights } from '../src/islands/report-highlights.ts';
import { GradePanel, Tabs } from '../src/islands/Report.tsx';
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
