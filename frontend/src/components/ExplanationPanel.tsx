import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import Divider from '@mui/material/Divider';
import Chip from '@mui/material/Chip';
import type { ScoreExplanation, Issue } from '../types';

const severityColors: Record<Issue['severity'], 'error' | 'warning' | 'default'> = {
  Critical: 'error',
  High: 'error',
  Medium: 'warning',
  Low: 'default',
};

function flagToKeyword(flag: string): string {
  const match = flag.match(/^([a-zA-Z_]+)/);
  if (!match) return flag;
  return match[1].replace(/_/g, ' ');
}

const DETECTOR_ORDER = ['header', 'content', 'url', 'qrcode', 'threat_intel', 'attachment'];
const DETECTOR_LABELS: Record<string, string> = {
  header: 'Header Analysis',
  content: 'Content Analysis',
  url: 'URL Analysis',
  qrcode: 'QR Code Detection',
  threat_intel: 'Threat Intelligence',
  attachment: 'Attachment Analysis',
};
function getIssuesForDetector(detector: string, issues: Issue[]): Issue[] {
  return issues.filter(i => i.detector === detector);
}
function getDetectorGrade(detectorIssues: Issue[]): Issue['severity'] | null {
  const severityRank: Record<Issue['severity'], number> = { Critical: 0, High: 1, Medium: 2, Low: 3 };
  if (detectorIssues.length === 0) return null;
  return detectorIssues.reduce((worst, issue) =>
    severityRank[issue.severity] < severityRank[worst] ? issue.severity : worst,
    detectorIssues[0].severity
  );
}

interface Props { explanation: ScoreExplanation; totalScore: number }

export default function ExplanationPanel({ explanation, totalScore }: Props) {
  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={1.5}>
        <Typography variant="h6" fontWeight={600}>
          Signal Breakdown
        </Typography>
        <Typography variant="body2" color="text.secondary">
          Model: {explanation.model_version}
        </Typography>
      </Box>


      {explanation.issues && explanation.issues.length > 0 && (
        <Box sx={{ mb: 2 }}>
          <Typography variant="subtitle2" fontWeight={600} mb={1}>
            Issues Found ({explanation.issues.length})
          </Typography>
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.75 }}>
            {explanation.issues.map((issue, idx) => (
              <Chip
                key={`${issue.detector}-${issue.flag}-${idx}`}
                label={flagToKeyword(issue.flag)}
                color={severityColors[issue.severity]}
                size="small"
                variant="outlined"
                title={`${issue.detector}: ${issue.severity}`}
              />
            ))}
          </Box>
        </Box>
      )}

      <Divider sx={{ mb: 2 }} />
      {DETECTOR_ORDER.map((detector) => {
        const detectorIssues = getIssuesForDetector(detector, explanation.issues || []);
        const grade = getDetectorGrade(detectorIssues);
        return (
          <Box key={detector} sx={{ mb: 1.5, p: 1.5, border: '1px solid', borderColor: 'divider', borderRadius: 2 }}>
            <Box display="flex" justifyContent="space-between" alignItems="center" mb={1}>
              <Typography variant="subtitle2" fontWeight={600}>
                {DETECTOR_LABELS[detector] || detector}
              </Typography>
              {grade && (
                <Chip
                  label={grade}
                  size="small"
                  color={severityColors[grade]}
                  sx={{ fontWeight: 600, fontSize: '0.68rem', height: 22 }}
                />
              )}
            </Box>
            {detectorIssues.length > 0 ? (
              detectorIssues.map((issue, idx) => (
                <Box key={idx} display="flex" alignItems="flex-start" gap={1} sx={{ mb: 0.75 }}>
                  <Chip
                    label={flagToKeyword(issue.flag)}
                    color={severityColors[issue.severity]}
                    size="small"
                    variant="outlined"
                    sx={{ flexShrink: 0, mt: 0.25 }}
                  />
                  <Typography variant="body2">
                    {issue.description}
                  </Typography>
                </Box>
              ))
            ) : (
              <Typography variant="body2" color="text.secondary">No issues</Typography>
            )}
          </Box>
        );
      })}
    </Box>
  );
}
