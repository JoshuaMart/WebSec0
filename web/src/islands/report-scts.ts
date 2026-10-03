import type { CertificateSCTs, SCTSummary } from './report-types.ts';

export function sctSummary(scts?: SCTSummary): string {
  if (!scts) return 'TLS handshake SCT data unavailable in this report.';
  if (scts.count === 0) return 'No SCTs observed via the TLS extension.';
  const received = `${scts.count} SCT${scts.count === 1 ? '' : 's'} received via the TLS extension.`;
  return received + unparsedNote(scts);
}

export function certificateSCTSummary(scts?: CertificateSCTs): string {
  if (!scts) return 'Certificate SCT data unavailable in this report.';
  if (scts.parse_error) return 'The leaf certificate SCT extension is malformed; the SCT count is unavailable.';
  if (!scts.present) return 'No SCT extension observed in the leaf certificate.';
  return `${scts.count} SCT${scts.count === 1 ? '' : 's'} embedded in the leaf certificate.` + unparsedNote(scts);
}

function unparsedNote(scts: SCTSummary): string {
  if (scts.unparsed_count === 0) return '';
  return ` ${scts.unparsed_count} could not be decoded (malformed or unsupported version).`;
}
