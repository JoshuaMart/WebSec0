import type { Vuln } from './report-types.ts';

export function splitWeaknesses(findings: Vuln[]) {
  const assessed: Vuln[] = [];
  const unassessed: Vuln[] = [];
  for (const finding of findings) {
    // Completion is report metadata, not a weakness. Partial scans have a
    // dedicated notice, including older reports that only carry this finding.
    if (finding.id === 'vuln.scan_blocked') continue;
    const state = finding.state.trim().toLowerCase().replace(/_/g, ' ');
    if (finding.level === 'info' && state === 'not assessed')
      unassessed.push(finding);
    else assessed.push(finding);
  }
  return { assessed, unassessed };
}
