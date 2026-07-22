import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { EmailDetail, EmailSummary, VerdictRequest } from '../src/types';

// Mock axios. api.ts creates one instance via axios.create() (used for GET /queue
// and POST /verdicts) and also calls axios.post() directly for the multipart
// ingest. vi.hoisted gives us handles to both so we can stub responses and
// assert on the exact URLs/args.
const { instance, mockAxios } = vi.hoisted(() => {
  const instance = { get: vi.fn(), post: vi.fn() };
  const mockAxios = { create: vi.fn(() => instance), post: vi.fn() };
  return { instance, mockAxios };
});
vi.mock('axios', () => ({ default: mockAxios }));

// Imported after the mock is registered (vi.mock/vi.hoisted are hoisted above this).
import { listQueue, getEmailDetail, submitVerdict, ingestEml } from '../src/lib/api';

beforeEach(() => {
  instance.get.mockReset();
  instance.post.mockReset();
  mockAxios.post.mockReset();
});

describe('listQueue', () => {
  it('requests the queue with paging params and unwraps items + total', async () => {
    const items: EmailSummary[] = [{ email_id: 'e1' } as EmailSummary];
    instance.get.mockResolvedValue({ data: { data: items, meta: { total: 42 } } });

    const result = await listQueue(2, 10);

    expect(instance.get).toHaveBeenCalledWith('/queue?page=2&page_size=10');
    expect(result).toEqual({ items, total: 42 });
  });

  it('defaults total to 0 when meta is absent', async () => {
    instance.get.mockResolvedValue({ data: { data: [] } });
    const result = await listQueue();
    expect(instance.get).toHaveBeenCalledWith('/queue?page=1&page_size=20');
    expect(result).toEqual({ items: [], total: 0 });
  });
});

describe('getEmailDetail', () => {
  it('requests /queue/:id and returns the unwrapped detail', async () => {
    const detail = { email_id: 'abc' } as EmailDetail;
    instance.get.mockResolvedValue({ data: { data: detail } });

    const result = await getEmailDetail('abc');

    expect(instance.get).toHaveBeenCalledWith('/queue/abc');
    expect(result).toBe(detail);
  });
});

describe('submitVerdict', () => {
  it('POSTs the verdict to /verdicts', async () => {
    instance.post.mockResolvedValue({ data: {} });
    const req: VerdictRequest = { email_id: 'e1', action: 'quarantine', reason: 'bad' };

    await submitVerdict(req);

    expect(instance.post).toHaveBeenCalledWith('/verdicts', req);
  });
});

describe('ingestEml', () => {
  it('POSTs multipart form data to the ingest endpoint and unwraps the detail', async () => {
    const detail = { email_id: 'ing1' } as EmailDetail;
    mockAxios.post.mockResolvedValue({ data: { data: detail } });
    const file = new File(['raw eml bytes'], 'sample.eml', { type: 'message/rfc822' });

    const result = await ingestEml(file);

    expect(mockAxios.post).toHaveBeenCalledTimes(1);
    const [url, body, config] = mockAxios.post.mock.calls[0];
    expect(url).toBe('/api/v1/emails/ingest/eml');
    expect(body).toBeInstanceOf(FormData);
    expect((body as FormData).get('file')).toBe(file);
    expect(config).toMatchObject({
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    expect(result).toBe(detail);
  });
});
