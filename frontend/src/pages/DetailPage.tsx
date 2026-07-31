import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import CircularProgress from '@mui/material/CircularProgress';
import Divider from '@mui/material/Divider';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import RiskBadge from '../components/RiskBadge';
import ExplanationPanel from '../components/ExplanationPanel';
import VerdictActions from '../components/VerdictActions';
import { getEmailDetail } from '../lib/api';
import type { EmailDetail } from '../types';

export default function DetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [email, setEmail] = useState<EmailDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [verdict, setVerdict] = useState<'approve' | 'quarantine' | null>(null);

  useEffect(() => {
    if (!id) return;
    getEmailDetail(id)
      .then(setEmail)
      .catch(() => setError('Email not found or API unavailable.'))
      .finally(() => setLoading(false));
  }, [id]);

  const handleVerdictComplete = (action: 'approve' | 'quarantine') => {
    setVerdict(action);
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" py={8}>
        <CircularProgress />
      </Box>
    );
  }

  if (error || !email) {
    return (
      <Box sx={{ maxWidth: 800, mx: 'auto', p: 3 }}>
        <Alert severity="error">{error ?? 'Unknown error'}</Alert>
        <Button startIcon={<ArrowBackIcon />} onClick={() => navigate('/queue')} sx={{ mt: 2 }}>
          Back to Queue
        </Button>
      </Box>
    );
  }

  return (
    <Box sx={{ maxWidth: 1100, mx: 'auto', p: 3 }}>
      {/* PageHeader */}
      <Box display="flex" alignItems="center" gap={1} mb={3}>
        <Button
          id="btn-back"
          startIcon={<ArrowBackIcon />}
          onClick={() => navigate('/queue')}
          variant="text"
        >
          Queue
        </Button>
        <Typography variant="body2" color="text.secondary">/</Typography>
        <Typography variant="body2" noWrap sx={{ maxWidth: 300 }}>
          {email.subject}
        </Typography>
      </Box>

      <Grid container spacing={3}>
        {/* Left: Email detail */}
        <Grid item xs={12} md={7}>
          <Card variant="outlined" sx={{ mb: 2 }}>
            <CardContent>
              <Box display="flex" justifyContent="space-between" alignItems="flex-start" mb={1}>
                <Typography variant="h6" fontWeight={600} sx={{ flexGrow: 1, mr: 2 }}>
                  {email.subject}
                </Typography>
                <RiskBadge tier={email.risk_tier} size="medium" />
              </Box>
              <Typography variant="body2" color="text.secondary">
                <strong>From:</strong> {email.sender}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                <strong>Received:</strong> {new Date(email.received_at).toLocaleString()}
              </Typography>
              <Typography variant="body2" color="text.secondary" mb={2}>
                <strong>Routing:</strong> {email.routing_decision} &nbsp;|&nbsp;
                <strong>Verdict:</strong> {email.verdict}
              </Typography>

              <Divider sx={{ my: 1.5 }} />

              <Typography variant="subtitle2" fontWeight={600} mb={0.5}>
                Email Body
              </Typography>
              <Box
                sx={{
                  bgcolor: 'grey.50',
                  border: '1px solid',
                  borderColor: 'divider',
                  borderRadius: 1.5,
                  p: 1.5,
                  maxHeight: 300,
                  overflow: 'auto',
                  fontFamily: 'monospace',
                  fontSize: '0.8rem',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-all',
                }}
              >
                {email.body_text || '(no plain-text body)'}
              </Box>
            </CardContent>
          </Card>
        </Grid>

        {/* Right: Explanation + verdict */}
        <Grid item xs={12} md={5}>
          <Card variant="outlined" sx={{ mb: 2 }}>
            <CardContent>
              <ExplanationPanel
                explanation={email.explanation}
              />
            </CardContent>
          </Card>

          {verdict ? (
            <Alert
              severity={verdict === 'quarantine' ? 'error' : 'success'}
              id="verdict-confirmation"
              sx={{ mb: 2 }}
            >
              Verdict recorded: <strong>{verdict}</strong>.
              <Button size="small" sx={{ ml: 1 }} onClick={() => navigate('/queue')}>
                Back to queue
              </Button>
            </Alert>
          ) : (
            <Card variant="outlined">
              <CardContent>
                <VerdictActions
                  emailId={email.email_id}
                  onComplete={handleVerdictComplete}
                />
              </CardContent>
            </Card>
          )}
        </Grid>
      </Grid>
    </Box>
  );
}
