import Box from '@mui/material/Box';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import Chip from '@mui/material/Chip';
import LinearProgress from '@mui/material/LinearProgress';
import Typography from '@mui/material/Typography';
import type { SignalBreakdown } from '../types';

interface Props { signal: SignalBreakdown }

const SIGNAL_LABELS: Record<string, string> = {
  header: 'Header Analysis',
  content: 'Content Analysis',
  url: 'URL Analysis',
  qrcode: 'QR Code Detection',
  threat_intel: 'Threat Intelligence',
};

export default function SignalBreakdownCard({ signal }: Props) {
  const contribution = Math.round(signal.weighted_contribution * 10) / 10;
  const barValue = Math.min(signal.raw_score, 100);
  const barColor = signal.raw_score >= 60 ? 'error' : signal.raw_score >= 30 ? 'warning' : 'success';

  return (
    <Card variant="outlined" sx={{ mb: 1.5 }}>
      <CardContent sx={{ pb: '12px !important' }}>
        <Box display="flex" justifyContent="space-between" alignItems="center" mb={1}>
          <Typography variant="subtitle2" fontWeight={600}>
            {SIGNAL_LABELS[signal.signal_name] ?? signal.signal_name}
          </Typography>
          <Typography variant="caption" color="text.secondary">
            {contribution} pts &nbsp;
            <span style={{ opacity: 0.6 }}>
              ({signal.raw_score.toFixed(1)} × {(signal.weight * 100).toFixed(0)}%)
            </span>
          </Typography>
        </Box>

        <LinearProgress
          variant="determinate"
          value={barValue}
          color={barColor}
          sx={{ height: 6, borderRadius: 3, mb: 1 }}
        />

        {signal.flags.length > 0 && (
          <Box display="flex" flexWrap="wrap" gap={0.5} mt={0.5}>
            {signal.flags.map((flag, i) => (
              <Chip
                key={i}
                label={flag}
                size="small"
                variant="outlined"
                color={barColor}
                sx={{ fontSize: '0.68rem', height: 20 }}
              />
            ))}
          </Box>
        )}
      </CardContent>
    </Card>
  );
}
