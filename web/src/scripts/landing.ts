const form = document.getElementById('scanForm') as HTMLFormElement;
const input = document.getElementById('hostInput') as HTMLInputElement;
const optPublic = document.getElementById('listInHistory') as HTMLInputElement;
const button = document.getElementById('scanButton') as HTMLButtonElement;
const buttonLabel = document.getElementById(
  'scanButtonLabel',
) as HTMLSpanElement;
const validating = document.getElementById('validating') as HTMLDivElement;
const validatingText = document.getElementById(
  'validatingText',
) as HTMLSpanElement;
const errorBox = document.getElementById('errorBox') as HTMLDivElement;
let pending = false;

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (pending) return;
  const host = input.value
    .trim()
    .replace(/^https?:\/\//i, '')
    .replace(/\/$/, '');
  if (!host) {
    input.focus();
    return;
  }
  pending = true;
  button.disabled = true;
  input.readOnly = true;
  optPublic.disabled = true;
  buttonLabel.textContent = 'Scanning…';
  form.setAttribute('aria-busy', 'true');
  errorBox.hidden = true;
  validatingText.textContent = `Checking ${host}. Please keep this page open.`;
  validating.hidden = false;
  try {
    const response = await fetch('/api/v1/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host, list_in_history: optPublic.checked }),
    });
    const data = await response.json().catch(() => null);
    if (!response.ok) {
      throw new Error(
        data?.error?.message ??
          `The scan could not complete (HTTP ${response.status}). Please try again later.`,
      );
    }
    if (typeof data?.id !== 'string' || !data.id)
      throw new Error(
        'The server returned an incomplete response. Please try again.',
      );
    window.location.assign(`/r/${encodeURIComponent(data.id)}`);
  } catch (error) {
    errorBox.textContent =
      error instanceof TypeError
        ? 'Could not reach the scanner. Check your connection and try again.'
        : error instanceof Error
          ? error.message
          : 'The scan could not complete. Please try again.';
    errorBox.hidden = false;
  } finally {
    pending = false;
    button.disabled = false;
    input.readOnly = false;
    optPublic.disabled = false;
    buttonLabel.textContent = 'Scan website';
    form.removeAttribute('aria-busy');
    validating.hidden = true;
  }
});

type HistoryEntry = {
  id: string;
  host: string;
  scanned_at: string;
  tls_grade: string;
  headers_grade: string;
};
function gradeClass(grade: string): string {
  if (grade === 'A+' || grade === 'A') return '';
  if (grade === 'B' || grade === 'C') return ' warn';
  if (['D', 'E', 'F', 'T'].includes(grade)) return ' bad';
  return ' unknown';
}
function timeAgo(iso: string): string {
  const minutes = Math.floor((Date.now() - new Date(iso).getTime()) / 60000);
  if (!Number.isFinite(minutes)) return 'Scan time unavailable';
  if (minutes < 1) return 'Just now';
  if (minutes < 60) return `${minutes}m ago`;
  if (minutes < 1440) return `${Math.floor(minutes / 60)}h ago`;
  return `${Math.floor(minutes / 1440)}d ago`;
}
function renderRecent(entries: HistoryEntry[]) {
  const grid = document.getElementById('recentGrid')!;
  const section = document.getElementById('recent')!;
  for (const entry of entries.slice(0, 4)) {
    if (typeof entry?.id !== 'string' || typeof entry.host !== 'string')
      continue;
    const card = document.createElement('a');
    card.className = 'recent-card';
    card.href = `/r/${encodeURIComponent(entry.id)}`;
    const host = document.createElement('span');
    host.className = 'dom';
    host.textContent = entry.host;
    host.title = entry.host;
    const grades = document.createElement('span');
    grades.className = 'grades';
    for (const [label, value] of [
      ['TLS', entry.tls_grade],
      ['Headers', entry.headers_grade],
    ]) {
      const grade = typeof value === 'string' && value ? value : '?';
      const row = document.createElement('span');
      row.textContent = label;
      const chip = document.createElement('span');
      chip.className = `grade-chip${gradeClass(grade)}`;
      chip.textContent = grade;
      row.append(chip);
      grades.append(row);
    }
    const time = document.createElement('span');
    time.className = 'ago';
    time.textContent = timeAgo(entry.scanned_at);
    card.append(host, grades, time);
    grid.append(card);
  }
  section.hidden = !grid.childElementCount;
}
fetch('/api/v1/history?limit=4')
  .then((response) => (response.ok ? response.json() : []))
  .then((entries: unknown) => {
    if (Array.isArray(entries)) renderRecent(entries);
  })
  .catch(() => {
    /* Public history is optional; the main interface stays available. */
  });

// Motion starts without hover, and rests off screen or when the tab is hidden.
// Without JavaScript, the same illustration is complete and static.
const motion = window.matchMedia('(prefers-reduced-motion: no-preference)');
const figureHost = document.getElementById('securityFigure')!;
let figureVisible = false;
const steps = [
  ...document.querySelectorAll<HTMLElement>('.workflow-steps > li'),
];
const visibleSteps = new Set<Element>();
function syncMotion() {
  figureHost.toggleAttribute(
    'data-playing',
    motion.matches && figureVisible && !document.hidden,
  );
  for (const step of steps) {
    if (motion.matches && visibleSteps.has(step) && !document.hidden)
      step.setAttribute('data-entered', '');
    step.toggleAttribute(
      'data-paused',
      !motion.matches || !visibleSteps.has(step) || document.hidden,
    );
  }
}
motion.addEventListener('change', syncMotion);
document.addEventListener('visibilitychange', syncMotion);
const figureObserver = new IntersectionObserver(([entry]) => {
  figureVisible = entry.isIntersecting;
  syncMotion();
});
figureObserver.observe(figureHost);
// Each step plays once when it becomes visible, including in the mobile layout.
const stepsObserver = new IntersectionObserver(
  (entries) => {
    for (const entry of entries) {
      if (entry.isIntersecting) visibleSteps.add(entry.target);
      else visibleSteps.delete(entry.target);
    }
    syncMotion();
  },
  { threshold: 0.35 },
);
steps.forEach((step) => stepsObserver.observe(step));
syncMotion();
