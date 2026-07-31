import { describe, it, expect } from 'vitest';
import {
  getIssuesForDetector,
  getDetectorGrade,
  groupIssuesByDetector,
} from '../src/lib/severity';
import type { Issue } from '../src/types';

const issue = (detector: string, severity: Issue['severity'], flag = 'f'): Issue => ({
  detector,
  flag,
  description: `${flag} description`,
  severity,
});

describe('getIssuesForDetector', () => {
  it('returns only the named detector’s issues', () => {
    const issues = [issue('header', 'High'), issue('url', 'Low'), issue('header', 'Medium')];
    expect(getIssuesForDetector('header', issues)).toEqual([issues[0], issues[2]]);
  });

  it('returns an empty array for a detector with no issues', () => {
    expect(getIssuesForDetector('qrcode', [issue('header', 'High')])).toEqual([]);
  });

  it('returns an empty array when there are no issues at all', () => {
    expect(getIssuesForDetector('header', [])).toEqual([]);
  });
});

describe('getDetectorGrade', () => {
  it('returns null for an empty array', () => {
    expect(getDetectorGrade([])).toBeNull();
  });

  it('reduces to the worst severity regardless of order', () => {
    expect(getDetectorGrade([issue('h', 'Low'), issue('h', 'Critical'), issue('h', 'Medium')]))
      .toBe('Critical');
    expect(getDetectorGrade([issue('h', 'Critical'), issue('h', 'Low')])).toBe('Critical');
  });

  it('ranks every severity level correctly', () => {
    expect(getDetectorGrade([issue('h', 'Low'), issue('h', 'High')])).toBe('High');
    expect(getDetectorGrade([issue('h', 'Medium'), issue('h', 'Low')])).toBe('Medium');
    expect(getDetectorGrade([issue('h', 'Low')])).toBe('Low');
  });

  it('keeps the severity when all issues are equal', () => {
    expect(getDetectorGrade([issue('h', 'Medium'), issue('h', 'Medium')])).toBe('Medium');
  });
});

describe('groupIssuesByDetector', () => {
  it('returns one entry per detector carrying its worst severity', () => {
    const grouped = groupIssuesByDetector([
      { detector: 'header', severity: 'Medium' },
      { detector: 'url', severity: 'Low' },
      { detector: 'header', severity: 'Critical' },
    ]);
    expect(grouped).toHaveLength(2);
    expect(grouped).toContainEqual({ detector: 'header', severity: 'Critical' });
    expect(grouped).toContainEqual({ detector: 'url', severity: 'Low' });
  });

  it('keeps the first on equal severities rather than flapping', () => {
    expect(groupIssuesByDetector([
      { detector: 'header', severity: 'High' },
      { detector: 'header', severity: 'High' },
    ])).toEqual([{ detector: 'header', severity: 'High' }]);
  });

  it('handles an empty list', () => {
    expect(groupIssuesByDetector([])).toEqual([]);
  });

  it('handles undefined issues without throwing', () => {
    // The API may omit `issues` entirely; the page passed it straight through.
    expect(groupIssuesByDetector(undefined)).toEqual([]);
  });
});
