import { render, screen, waitFor } from '@testing-library/react';
import { expect, test, vi } from 'vitest';
import { App } from './App';

const { invoke } = vi.hoisted(() => ({
  invoke: vi.fn((command: string) => {
    if (command === 'status') return Promise.resolve({ datasetState: 'ready', capabilities: ['read'], schemaFingerprint: 'sha256:test' });
    if (command === 'sessions_list') return Promise.resolve([]);
    if (command === 'quarantines_list') return Promise.resolve([]);
    return Promise.resolve([]);
  }),
}));
vi.mock('@tauri-apps/api/core', () => ({ invoke }));

test('status view renders the locked dataset state and capabilities', async () => {
  render(<App />);
  await waitFor(() => expect(screen.getByText('ready')).toBeInTheDocument());
  expect(screen.getByText('read')).toBeInTheDocument();
  expect(screen.getByText('sha256:test')).toBeInTheDocument();
});
