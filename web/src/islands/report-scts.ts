import type { HandshakeSCTs } from './report-types.ts';

export function sctSummary(scts?: HandshakeSCTs): string {
  if (!scts) return 'TLS handshake SCT data unavailable in this report.';
  if (scts.count === 0) return 'No SCTs observed via the TLS extension.';
  const received = `${scts.count} SCT${scts.count === 1 ? '' : 's'} received via the TLS extension.`;
  if (scts.unparsed_count === 0) return received;
  return `${received} ${scts.unparsed_count} could not be decoded (malformed or unsupported version).`;
}
