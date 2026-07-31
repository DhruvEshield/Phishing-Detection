import { useEffect, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import Paper from '@mui/material/Paper';
import CircularProgress from '@mui/material/CircularProgress';
import Alert from '@mui/material/Alert';
import Pagination from '@mui/material/Pagination';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Divider from '@mui/material/Divider';
import ExplanationPanel from '../components/ExplanationPanel';
import { listQueue, ingestEml } from '../lib/api';
import type { EmailSummary, EmailDetail } from '../types';

const PAGE_SIZE = 20;

function groupIssuesByDetector(issues: { detector: string; flag: string; severity: string }[]): { detector: string; severity: string }[] {
  const severityRank: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 };
  const grouped: Record<string, string> = {};
  for (const issue of issues) {
    const current = grouped[issue.detector];
    if (!current || severityRank[issue.severity] < severityRank[current]) {
      grouped[issue.detector] = issue.severity;
    }
  }
  return Object.entries(grouped).map(([detector, severity]) => ({ detector, severity }));
}

const severityLabelColors: Record<string, string> = {
  Critical: '#c5221f',
  High: '#ea4335',
  Medium: '#b06000',
  Low: '#5f6368',
};

export default function QueuePage() {
  const navigate = useNavigate();
  const [items, setItems] = useState<EmailSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadResult, setUploadResult] = useState<string | null>(null);
  const [uploadedResult, setUploadedResult] = useState<EmailDetail | null>(null);

  const fetchQueue = useCallback(async () => {
    try {
      setLoading(true);
      const result = await listQueue(page, PAGE_SIZE);
      setItems(result.items);
      setTotal(result.total);
      setError(null);
    } catch {
      setError('Failed to load review queue. Is the API running?');
    } finally {
      setLoading(false);
    }
  }, [page]);

  useEffect(() => {
    fetchQueue();
    // Auto-refresh every 30 seconds
    const interval = setInterval(fetchQueue, 30_000);
    return () => clearInterval(interval);
  }, [fetchQueue]);

  const totalPages = Math.ceil(total / PAGE_SIZE);

  const handleEmlUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploading(true);
    setUploadResult(null);
    try {
      const result = await ingestEml(file);
      setUploadedResult(result);
      fetchQueue();
    } catch {
      setUploadResult('Failed to process email. Please try again.');
    } finally {
      setUploading(false);
      e.target.value = '';
    }
  };

  return (
    <Box sx={{ maxWidth: 1100, mx: 'auto', p: 3 }}>
      {/* PageHeader: layout order per phishskill-integration.md §3 */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
        <Box>
          <Typography variant="h4">PhishDetect — Review Queue</Typography>
          <Typography variant="body2" color="text.secondary">
            {total} email{total !== 1 ? 's' : ''} awaiting analyst review
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 1 }}>
          <label htmlFor="eml-upload">
            <input
              id="eml-upload"
              type="file"
              accept=".eml"
              style={{ display: 'none' }}
              onChange={handleEmlUpload}
              disabled={uploading}
            />
            <Button
              variant="contained"
              component="span"
              disabled={uploading}
              size="small"
            >
              {uploading ? 'Analysing...' : 'Upload .eml'}
            </Button>
          </label>
          {uploadResult && (
            <Typography variant="caption" color={uploadResult.startsWith('Failed') ? 'error' : 'success.main'}>
              {uploadResult}
            </Typography>
          )}
        </Box>
      </Box>

      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      {loading && items.length === 0 ? (
        <Box display="flex" justifyContent="center" py={6}>
          <CircularProgress />
        </Box>
      ) : (
        <>
          <TableContainer component={Paper} variant="outlined">
            <Table id="queue-table" size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: 'grey.50' }}>
                  <TableCell><strong>Sender</strong></TableCell>
                  <TableCell><strong>Subject</strong></TableCell>
                  <TableCell><strong>Received</strong></TableCell>
                  <TableCell><strong>Detected Issues</strong></TableCell>
                  <TableCell align="center"><strong>Status</strong></TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {items.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5} align="center" sx={{ py: 4 }}>
                      <Typography color="text.secondary">Queue is empty</Typography>
                    </TableCell>
                  </TableRow>
                ) : (
                  items.map((email) => (
                    <TableRow
                      key={email.email_id}
                      hover
                      sx={{ cursor: 'pointer' }}
                      onClick={() => navigate(`/queue/${email.email_id}`)}
                    >
                      <TableCell sx={{ maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {email.sender}
                      </TableCell>
                      <TableCell sx={{ maxWidth: 300 }}>{email.subject}</TableCell>
                      <TableCell>
                        {new Date(email.received_at).toLocaleString()}
                      </TableCell>
                      <TableCell>
                        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                          {groupIssuesByDetector(email.issues || []).map(({ detector, severity }) => (
                            <Typography
                              key={detector}
                              component="span"
                              variant="caption"
                              sx={{
                                color: severityLabelColors[severity] || '#5f6368',
                                fontWeight: 600,
                                border: '1px solid',
                                borderColor: severityLabelColors[severity] || '#5f6368',
                                borderRadius: 1,
                                px: 0.75,
                                py: 0.25,
                              }}
                            >
                              {detector}: {severity}
                            </Typography>
                          ))}
                          {(!email.issues || email.issues.length === 0) && (
                            <Typography variant="caption" color="text.secondary">No issues</Typography>
                          )}
                        </Box>
                      </TableCell>
                      <TableCell align="center">
                        <Typography
                          variant="caption"
                          sx={{
                            color: email.status === 'pending' ? 'warning.main' : 'success.main',
                            fontWeight: 600,
                          }}
                        >
                          {email.status}
                        </Typography>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </TableContainer>

          {totalPages > 1 && (
            <Box display="flex" justifyContent="center" mt={2}>
              <Pagination
                count={totalPages}
                page={page}
                onChange={(_, p) => setPage(p)}
                color="primary"
              />
            </Box>
          )}
        </>
      )}

      <Dialog
        open={!!uploadedResult}
        onClose={() => setUploadedResult(null)}
        maxWidth="md"
        fullWidth
      >
        {uploadedResult && (
          <>
            <DialogTitle>
              <Box display="flex" justifyContent="space-between" alignItems="center">
                <Typography variant="h6">Analysis Result</Typography>
              </Box>
              <Typography variant="body2" color="text.secondary" mt={0.5}>
                {uploadedResult.sender}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Subject: {uploadedResult.subject}
              </Typography>
              <Typography variant="body2" mt={0.5}>
                Verdict: <strong>{uploadedResult.verdict}</strong> → {uploadedResult.routing_decision}
              </Typography>
            </DialogTitle>
            <Divider />
            <DialogContent>
              <ExplanationPanel
                explanation={uploadedResult.explanation}
              />
            </DialogContent>
            <DialogActions>
              <Button onClick={() => setUploadedResult(null)}>Close</Button>
            </DialogActions>
          </>
        )}
      </Dialog>
    </Box>
  );
}
