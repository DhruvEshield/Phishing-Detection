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
import RiskBadge from '../components/RiskBadge';
import { listQueue } from '../lib/api';
import type { EmailSummary } from '../types';

const PAGE_SIZE = 20;

export default function QueuePage() {
  const navigate = useNavigate();
  const [items, setItems] = useState<EmailSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

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

  return (
    <Box sx={{ maxWidth: 1100, mx: 'auto', p: 3 }}>
      {/* PageHeader: layout order per phishskill-integration.md §3 */}
      <Box mb={3}>
        <Typography variant="h5" fontWeight={700}>
          PhishDetect — Review Queue
        </Typography>
        <Typography variant="body2" color="text.secondary" mt={0.5}>
          {total} email{total !== 1 ? 's' : ''} awaiting analyst review
        </Typography>
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
                  <TableCell align="center"><strong>Score</strong></TableCell>
                  <TableCell align="center"><strong>Risk</strong></TableCell>
                  <TableCell align="center"><strong>Status</strong></TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {items.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} align="center" sx={{ py: 4 }}>
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
                      <TableCell align="center">
                        <strong>{email.risk_score.toFixed(1)}</strong>
                      </TableCell>
                      <TableCell align="center">
                        <RiskBadge tier={email.risk_tier} />
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
    </Box>
  );
}
