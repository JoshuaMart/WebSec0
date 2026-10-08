// Explains which floor in internal/scoring/tls.go set a TLS grade below the
// letter its score alone would earn. Keep the rules aligned with TLSFinal.

import type { Grade, TLSReport } from './report-types.ts';

const rank: Record<Grade, number> = {
  'A+': 8,
  A: 7,
  B: 6,
  C: 5,
  D: 4,
  E: 3,
  F: 2,
  T: 1,
  '': 0,
};

function scoreGrade(score: number): Grade {
  if (score >= 95) return 'A+';
  if (score >= 80) return 'A';
  if (score >= 65) return 'B';
  if (score >= 50) return 'C';
  if (score >= 35) return 'D';
  if (score >= 20) return 'E';
  return 'F';
}

export function tlsGradeCap(tls?: TLSReport): string {
  if (!tls?.grade || rank[tls.grade] >= rank[scoreGrade(tls.scores.final)])
    return '';
  const offered = new Set(
    (tls.protocols ?? []).filter((p) => p.offered).map((p) => p.name),
  );
  const names = (tls.ciphers ?? []).map((c) => c.name.toUpperCase());
  const reasons: [Grade, boolean, string][] = [
    [
      'T',
      ['expired', 'self_signed', 'hostname_mismatch', 'untrusted'].includes(
        tls.chain_trust,
      ),
      'certificate chain does not validate',
    ],
    ['F', offered.has('SSL 2.0') || offered.has('SSL 3.0'), 'SSL offered'],
    [
      'F',
      names.some(
        (n) => n.includes('RC4') || n.includes('_ANON') || n.includes('EXPORT'),
      ),
      'weak cipher suites offered',
    ],
    [
      'C',
      offered.has('TLS 1.0') || offered.has('TLS 1.1'),
      offered.has('TLS 1.0') ? 'TLS 1.0 offered' : 'TLS 1.1 offered',
    ],
    ['C', names.some((n) => n.includes('3DES')), '3DES offered'],
    [
      'C',
      names.length > 0 && !(tls.ciphers ?? []).some((c) => c.pfs),
      'no forward secrecy',
    ],
    ['A', true, 'HSTS not preload-eligible'],
  ];
  const match = reasons.find(([grade, applies]) => applies && grade === tls.grade);
  return match ? `Capped at ${tls.grade} · ${match[2]}` : '';
}
