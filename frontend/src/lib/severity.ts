import type { Issue } from '../types';

/**
 * Severity helpers shared by the explanation panel and the queue list.
 *
 * These were duplicated across ExplanationPanel and QueuePage — each with its
 * own copy of severityRank — which is how the two views could drift apart on
 * what "worst" means. One ranking, one reducer, one place to test.
 */

type Severity = Issue['severity'];

/** Lower number = more severe, so a plain `<` comparison finds the worst. */
export const severityRank: Record<Severity, number> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
};

/** Issues belonging to a single detector. */
export function getIssuesForDetector(detector: string, issues: Issue[]): Issue[] {
  return issues.filter(i => i.detector === detector);
}

/** The worst severity among the given issues, or null when there are none. */
export function getDetectorGrade(detectorIssues: Issue[]): Severity | null {
  if (detectorIssues.length === 0) return null;
  return detectorIssues.reduce<Severity>(
    (worst, issue) => (severityRank[issue.severity] < severityRank[worst] ? issue.severity : worst),
    detectorIssues[0].severity,
  );
}

/** One entry per detector, carrying that detector's worst severity. */
export function groupIssuesByDetector(
  issues: { detector: string; severity: string }[] | undefined,
): { detector: string; severity: string }[] {
  const grouped: Record<string, string> = {};
  for (const issue of issues ?? []) {
    const current = grouped[issue.detector];
    if (!current || severityRank[issue.severity as Severity] < severityRank[current as Severity]) {
      grouped[issue.detector] = issue.severity;
    }
  }
  return Object.entries(grouped).map(([detector, severity]) => ({ detector, severity }));
}
