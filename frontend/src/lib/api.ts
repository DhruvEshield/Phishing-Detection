/**Typed API client — all backend calls go through here.*/
import axios from 'axios';
import type {
  ApiResponse, EmailSummary, EmailDetail, VerdictRequest,
} from '../types';

const BASE = import.meta.env.VITE_API_BASE_URL || '';
const api = axios.create({ baseURL: `${BASE}/api/v1` });

export async function listQueue(
  page = 1, pageSize = 20
): Promise<{ items: EmailSummary[]; total: number }> {
  const res = await api.get<ApiResponse<EmailSummary[]>>(
    `/queue?page=${page}&page_size=${pageSize}`
  );
  return {
    items: res.data.data,
    total: (res.data.meta?.total as number) ?? 0,
  };
}

export async function getEmailDetail(emailId: string): Promise<EmailDetail> {
  const res = await api.get<ApiResponse<EmailDetail>>(`/queue/${emailId}`);
  return res.data.data;
}

export async function submitVerdict(req: VerdictRequest): Promise<void> {
  await api.post('/verdicts', req);
}

export async function ingestEml(file: File): Promise<EmailDetail> {
  const formData = new FormData();
  formData.append('file', file);
  const res = await axios.post<ApiResponse<EmailDetail>>(
    `${BASE}/api/v1/emails/ingest/eml`,
    formData,
    { headers: { 'Content-Type': 'multipart/form-data' } }
  );
  return res.data.data;
}
