import Box from '@mui/material/Box';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import Chip from '@mui/material/Chip';
import Typography from '@mui/material/Typography';
import type { SignalBreakdown } from '../types';

interface Props { signal: SignalBreakdown; grade: 'Critical' | 'High' | 'Medium' | 'Low' | null }

const gradeColors: Record<string, 'error' | 'warning' | 'default'> = {
  Critical: 'error',
  High: 'error',
  Medium: 'warning',
  Low: 'default',
};

const SIGNAL_LABELS: Record<string, string> = {
  header: 'Header Analysis',
  content: 'Content Analysis',
  url: 'URL Analysis',
  qrcode: 'QR Code Detection',
  threat_intel: 'Threat Intelligence',
};

export default function SignalBreakdownCard({ signal, grade }: Props) {
  return (
    <Card variant="outlined" sx={{ mb: 1.5 }}>
      <CardContent sx={{ pb: '12px !important' }}>
        <Box display="flex" justifyContent="space-between" alignItems="center" mb={1}>
          <Typography variant="subtitle2" fontWeight={600}>
            {SIGNAL_LABELS[signal.signal_name] ?? signal.signal_name}
          </Typography>
          {grade && (
            <Chip
              label={grade}
              size="small"
              color={gradeColors[grade] || 'default'}
              sx={{ fontWeight: 600, fontSize: '0.68rem', height: 22 }}
            />
          )}
        </Box>

        {signal.flags.length > 0 && (
          <Box display="flex" flexWrap="wrap" gap={0.5} mt={0.5}>
            {signal.flags.map((flag, i) => (
              <Chip
                key={i}
                label={flag}
                size="small"
                variant="outlined"
                color="default"
                sx={{ fontSize: '0.68rem', height: 20 }}
              />
            ))}
          </Box>
        )}
      </CardContent>
    </Card>
  );
}
