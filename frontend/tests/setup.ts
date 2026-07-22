// Vitest global setup: adds jest-dom matchers (toBeInTheDocument, etc.) and
// clears mocks between tests so spies don't leak across files.
import '@testing-library/jest-dom/vitest';
import { afterEach, vi } from 'vitest';
import { cleanup } from '@testing-library/react';

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});
