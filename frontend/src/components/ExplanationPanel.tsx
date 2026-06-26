import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import Divider from '@mui/material/Divider';
import SignalBreakdownCard from './SignalBreakdownCard';
import type { ScoreExplanation } from '../types';

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

      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          gap: 1,
          mb: 2,
          p: 1.5,
          bgcolor: 'grey.50',
          borderRadius: 2,
          border: '1px solid',
          borderColor: 'divider',
        }}
      >
        <Typography variant="body2" color="text.secondary">Total risk score</Typography>
        <Typography variant="h5" fontWeight={700} sx={{ ml: 'auto' }}>
          {totalScore.toFixed(1)}
          <Typography component="span" variant="body2" color="text.secondary"> / 100</Typography>
        </Typography>
      </Box>

      <Divider sx={{ mb: 2 }} />

      {explanation.signals.map((s) => (
        <SignalBreakdownCard key={s.signal_name} signal={s} />
      ))}

      <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
        No single signal triggers a block — the combined weight of evidence decides routing.
      </Typography>
    </Box>
  );
}
