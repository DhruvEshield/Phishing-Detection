import { useState } from 'react';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import TextField from '@mui/material/TextField';
import Typography from '@mui/material/Typography';
import CircularProgress from '@mui/material/CircularProgress';
import CheckCircleOutlineIcon from '@mui/icons-material/CheckCircleOutline';
import BlockIcon from '@mui/icons-material/Block';
import { submitVerdict } from '../lib/api';

interface Props {
  emailId: string;
  onComplete: (action: 'approve' | 'quarantine') => void;
}

export default function VerdictActions({ emailId, onComplete }: Props) {
  const [reason, setReason] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleVerdict = async (action: 'approve' | 'quarantine') => {
    setLoading(true);
    setError(null);
    try {
      await submitVerdict({ email_id: emailId, action, reason: reason || undefined });
      onComplete(action);
    } catch (err: unknown) {
      setError('Failed to submit verdict. Please try again.');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box>
      <Typography variant="subtitle2" fontWeight={600} mb={1}>
        Analyst Verdict
      </Typography>

      <TextField
        label="Reason (optional)"
        multiline
        rows={2}
        fullWidth
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        placeholder="Describe your reasoning..."
        variant="outlined"
        size="small"
        sx={{ mb: 2 }}
      />

      {error && (
        <Typography color="error" variant="caption" sx={{ mb: 1, display: 'block' }}>
          {error}
        </Typography>
      )}

      <Box display="flex" gap={1.5}>
        <Button
          id="btn-approve"
          variant="outlined"
          color="success"
          startIcon={loading ? <CircularProgress size={16} /> : <CheckCircleOutlineIcon />}
          onClick={() => handleVerdict('approve')}
          disabled={loading}
          fullWidth
        >
          Approve (Legitimate)
        </Button>
        <Button
          id="btn-quarantine"
          variant="contained"
          color="error"
          startIcon={loading ? <CircularProgress size={16} /> : <BlockIcon />}
          onClick={() => handleVerdict('quarantine')}
          disabled={loading}
          fullWidth
        >
          Quarantine (Phishing)
        </Button>
      </Box>
    </Box>
  );
}
