import type { DNSRecord, EmailReport, Severity } from './report-types.ts';

type PolicyCopy = { title: string; meaning: string; next?: string };

// The source assessment stays available in the evidence disclosure. These
// summaries translate known verdicts without inventing an email grade.
const verdicts: Record<string, PolicyCopy> = {
  'SPF softfail policy': {
    title: 'Unlisted senders are flagged.',
    meaning:
      'The policy marks senders outside its allowed list as suspicious (softfail). It does not ask for automatic rejection.',
    next: 'Check that every service you use to send email is covered. Keep softfail if this is intentional; review it together with DMARC with your email provider.',
  },
  'SPF fail policy': {
    title: 'Unlisted senders fail the SPF check.',
    meaning:
      'Senders outside the allowed list receive a fail result. Receiving servers decide whether to accept or reject the message.',
    next: 'Keep the allowed sender list up to date when you add or remove email services.',
  },
  'Permissive SPF policy': {
    title: 'The sender list is too broad.',
    meaning:
      'The policy can authorize senders beyond the services you intend to use.',
    next: 'Ask your email provider to review the permissive rule shown in the evidence and limit it to legitimate senders.',
  },
  'Neutral SPF policy': {
    title: 'Unlisted senders get no clear verdict.',
    meaning:
      'The domain does not say whether senders outside its allowed list are authorized.',
    next: 'Confirm your email services with your provider, then choose the intended policy for everyone else.',
  },
  'Implicit neutral SPF policy': {
    title: 'No fallback rule is declared.',
    meaning: 'A sender that matches no rule receives a neutral result.',
    next: 'Confirm your legitimate senders before choosing an explicit fallback with your provider.',
  },
  'Delegated SPF policy': {
    title: 'Another policy handles unmatched senders.',
    meaning:
      'The SPF redirect points to the policy used for senders that match no earlier rule.',
    next: 'Confirm that the referenced policy belongs to the service you intend to use.',
  },
  'Broken SPF dependencies': {
    title: 'A referenced sender policy needs fixing.',
    meaning:
      'A policy used by SPF is missing, invalid or circular. Messages that reach that rule can encounter an SPF error.',
    next: 'Share the dependency errors in the evidence with your email provider and correct the affected reference.',
  },
  'Potential SPF lookup overflow': {
    title: 'The sender policy may require too many lookups.',
    meaning:
      'The static check exceeds SPF’s lookup budget. The actual result depends on which rules a sender reaches.',
    next: 'Ask your email provider to simplify the referenced policies. The evidence lists the terms counted.',
  },
  'DMARC monitoring only': {
    title: 'Reports are requested; blocking is not.',
    meaning:
      'The policy asks for authentication reports but does not request rejection or quarantine for messages that fail DMARC.',
    next: 'Review reports and confirm legitimate senders before moving gradually to quarantine or rejection.',
  },
  'No enforcement or reports': {
    title: 'Neither blocking nor reports are requested.',
    meaning:
      'The policy does not request rejection or quarantine and has no usable aggregate-report destination.',
    next: 'Set up a valid reporting address with your provider. Review legitimate senders before choosing a stricter policy.',
  },
  'DMARC quarantine requested': {
    title: 'Failing messages should be treated as suspicious.',
    meaning:
      'The domain asks receiving servers to quarantine messages that fail DMARC. Each receiver decides how to handle them.',
  },
  'DMARC rejection requested': {
    title: 'Failing messages should be rejected.',
    meaning:
      'The domain asks receiving servers to reject messages that fail DMARC. Each receiver makes the final decision.',
  },
};

export function policyCopy(
  protocol: 'SPF' | 'DMARC',
  record: DNSRecord,
): PolicyCopy {
  if (record.state === 'absent')
    return {
      title: `No ${protocol} policy found.`,
      meaning:
        protocol === 'SPF'
          ? 'No SPF sender policy was found for this domain.'
          : 'No applicable DMARC policy was found to tell receivers how to handle messages that fail authentication.',
      next: `Confirm whether this domain sends email, then configure ${protocol} with your DNS or email provider.`,
    };
  if (record.state === 'invalid')
    return {
      title: `The ${protocol} policy could not be read.`,
      meaning: 'The published DNS records do not form a usable policy.',
      next: 'Ask your DNS or email provider to correct the records listed in the evidence.',
    };
  if (record.state === 'unavailable')
    return {
      title: 'The DNS check could not finish.',
      meaning:
        'A DNS error or scan limit prevented a result. This does not mean the policy is missing.',
      next: 'Try again when DNS is responding. The evidence contains the diagnostic details.',
    };
  const assessment = record.assessment;
  if (!assessment)
    return {
      title: 'A policy was found.',
      meaning:
        'This report contains the DNS record, but no assessment of how the policy is configured.',
      next: 'Run a fresh scan for an assessment, or inspect the record in the evidence.',
    };
  if (Object.hasOwn(verdicts, assessment.title))
    return verdicts[assessment.title];
  // Unknown/new verdicts retain the scanner's explanation and recommendation.
  return {
    title: assessment.title,
    meaning: assessment.summary,
    next: assessment.recommendations[0],
  };
}

export type EmailCheck = {
  label: string;
  value: string;
  level: Severity;
  note?: string;
};
export type EmailPolicyView = {
  label: string;
  level: Severity;
  summary: string;
  checks: EmailCheck[];
  next?: string;
};

function unavailableView(
  protocol: 'SPF' | 'DMARC',
  record: DNSRecord,
): EmailPolicyView | undefined {
  if (record.state === 'observed') return;
  const copy = policyCopy(protocol, record);
  const level =
    record.state === 'invalid'
      ? 'bad'
      : record.state === 'absent'
        ? 'warn'
        : 'info';
  const label =
    record.state === 'invalid'
      ? 'Invalid record'
      : record.state === 'absent'
        ? 'Missing policy'
        : 'Check incomplete';
  return {
    label,
    level,
    summary: copy.meaning,
    next: copy.next,
    checks: [
      {
        label:
          record.state === 'unavailable' ? 'DNS lookup' : 'Published policy',
        value:
          record.state === 'invalid'
            ? 'Invalid'
            : record.state === 'absent'
              ? 'Not found'
              : 'Could not complete',
        level,
      },
    ],
  };
}

export function spfView(spf: EmailReport['spf']): EmailPolicyView {
  const unavailable = unavailableView('SPF', spf);
  if (unavailable) return unavailable;
  const copy = policyCopy('SPF', spf);
  const audit = spf.audit;
  const hasErrors = spf.assessment?.status === 'fail' || !!audit?.issues.length;
  const needsReview =
    spf.assessment?.status === 'warn' ||
    audit?.lookup_limit_exceeded ||
    spf.warnings.length > 0 ||
    ['+all', '?all'].includes(spf.all ?? '');
  const partial =
    !audit?.complete ||
    !spf.assessment ||
    (spf.assessment.status !== 'pass' &&
      !Object.hasOwn(verdicts, spf.assessment.title));
  const level = hasErrors
    ? 'bad'
    : needsReview
      ? 'warn'
      : partial
        ? 'info'
        : 'good';
  const fallback: Record<string, EmailCheck> = {
    '~all': {
      label: 'Unlisted senders',
      value: 'Softfail (~all)',
      level: 'info',
      note: 'A valid policy choice. Senders are flagged; rejection is not required.',
    },
    '-all': {
      label: 'Unlisted senders',
      value: 'Fail (-all)',
      level: 'good',
      note: 'They fail SPF. The receiving server decides whether to reject the message.',
    },
    '+all': {
      label: 'Unlisted senders',
      value: 'Authorized (+all)',
      level: 'warn',
    },
    '?all': {
      label: 'Unlisted senders',
      value: 'No decision (?all)',
      level: 'warn',
    },
  };
  const senderRule =
    spf.all && Object.hasOwn(fallback, spf.all)
      ? fallback[spf.all]
      : {
          label: 'Unlisted senders',
          value: spf.redirect
            ? 'Use redirected policy'
            : 'No fallback reported',
          level: 'info' as const,
        };
  return {
    label: hasErrors
      ? 'Needs fixing'
      : needsReview
        ? 'Needs improvement'
        : partial
          ? 'Partially verified'
          : 'Checks passed',
    level,
    summary:
      hasErrors || needsReview
        ? copy.meaning
        : partial
          ? 'The SPF record is valid, but this scan cannot confirm the complete sender configuration.'
          : 'The published SPF policy and its static dependencies passed the checks performed.',
    checks: [
      {
        label: 'Record format',
        value: spf.warnings.length ? 'Review warnings' : 'Valid',
        level: spf.warnings.length ? 'warn' : 'good',
      },
      senderRule,
      {
        label: 'Referenced policies',
        value: audit?.issues.length
          ? 'Errors detected'
          : audit?.lookup_limit_exceeded
            ? 'Possible lookup limit exceeded'
            : !audit
              ? 'Verification unavailable'
              : audit.complete
                ? 'Checks passed'
                : 'Verification incomplete',
        level: audit?.issues.length
          ? 'bad'
          : audit?.lookup_limit_exceeded
            ? 'warn'
            : audit?.complete
              ? 'good'
              : 'info',
      },
      ...(spf.warnings.length
        ? [
            {
              label: 'Policy warnings',
              value: `${spf.warnings.length} to review`,
              level: 'warn' as const,
            },
          ]
        : []),
    ],
    next:
      !hasErrors && !needsReview && spf.all === '~all'
        ? partial
          ? 'Keep ~all if it matches your intended policy. Confirm your sending services and the incomplete checks with your email provider.'
          : 'Keep ~all if it matches your intended policy. Update the allowed sender list when you change email services.'
        : copy.next,
  };
}

export function dmarcView(dmarc: EmailReport['dmarc']): EmailPolicyView {
  const unavailable = unavailableView('DMARC', dmarc);
  if (unavailable) return unavailable;
  const copy = policyCopy('DMARC', dmarc);
  const hasErrors = dmarc.assessment?.status === 'fail';
  const needsReview =
    dmarc.policy === 'none' ||
    ['absent', 'invalid'].includes(dmarc.reporting_state ?? '') ||
    dmarc.testing ||
    dmarc.warnings.length > 0 ||
    dmarc.assessment?.status === 'warn';
  const partial =
    !dmarc.policy ||
    !dmarc.reporting_state ||
    dmarc.assessment?.status !== 'pass';
  const level = hasErrors
    ? 'bad'
    : needsReview
      ? 'warn'
      : partial
        ? 'info'
        : 'good';
  return {
    label: hasErrors
      ? 'Needs fixing'
      : needsReview
        ? 'Needs improvement'
        : partial
          ? 'Partially verified'
          : 'Checks passed',
    level,
    summary:
      hasErrors || dmarc.warnings.length
        ? copy.meaning
        : dmarc.policy === 'none'
          ? dmarc.reporting_state === 'configured'
            ? 'The DMARC record is valid. Reports are requested, but blocking is not.'
            : dmarc.reporting_state === 'absent' ||
                dmarc.reporting_state === 'invalid'
              ? 'The DMARC record is valid, but it requests neither blocking nor usable aggregate reports.'
              : 'The DMARC record requests no blocking. Reporting settings are unavailable in this report.'
          : copy.meaning,
    checks: [
      {
        label: 'Record format',
        value: dmarc.warnings.length ? 'Review warnings' : 'Valid',
        level: dmarc.warnings.length ? 'warn' : 'good',
      },
      {
        label: 'Failed messages',
        value:
          dmarc.policy === 'none'
            ? 'No action requested (p=none)'
            : dmarc.policy === 'reject'
              ? 'Rejection requested'
              : dmarc.policy === 'quarantine'
                ? 'Quarantine requested'
                : 'Policy undetermined',
        level:
          dmarc.policy === 'none' ? 'warn' : dmarc.policy ? 'good' : 'info',
      },
      {
        label: 'Aggregate reports',
        value:
          dmarc.reporting_state === 'configured'
            ? 'Configured'
            : dmarc.reporting_state === 'absent'
              ? 'Not configured'
              : dmarc.reporting_state === 'invalid'
                ? 'Invalid destination'
                : 'Not available in this report',
        level:
          dmarc.reporting_state === 'configured'
            ? 'good'
            : dmarc.reporting_state
              ? 'warn'
              : 'info',
      },
      ...(dmarc.testing
        ? [
            {
              label: 'Testing mode',
              value: 'Enabled',
              level: 'warn' as const,
              note: 'The requested handling above includes the testing adjustment.',
            },
          ]
        : []),
      ...(dmarc.warnings.length
        ? [
            {
              label: 'Policy warnings',
              value: `${dmarc.warnings.length} to review`,
              level: 'warn' as const,
            },
          ]
        : []),
    ],
    next:
      copy.next ||
      dmarc.assessment?.recommendations[0] ||
      'Review authentication reports and keep legitimate senders aligned with this policy.',
  };
}

export function emailSummary(spf: EmailPolicyView, dmarc: EmailPolicyView) {
  const order: Record<Severity, number> = { bad: 0, warn: 1, info: 2, good: 3 };
  const priority = order[dmarc.level] <= order[spf.level] ? dmarc : spf;
  return {
    level: priority.level,
    title:
      priority.level === 'bad'
        ? 'Configuration needs fixing'
        : priority.level === 'warn'
          ? 'Configuration needs improvement'
          : priority.level === 'info'
            ? 'Configuration not fully verified'
            : 'Published policies pass these checks',
    summary: priority.summary,
  };
}
