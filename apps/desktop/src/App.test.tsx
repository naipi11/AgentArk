import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { expect, test, vi } from 'vitest';
import { App } from './App';
import { LocaleProvider } from './i18n';
import { afterEach } from 'vitest';

afterEach(() => cleanup());

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
  render(<LocaleProvider><App /></LocaleProvider>);
  await waitFor(() => expect(screen.getByText('ready')).toBeInTheDocument());
  expect(screen.getByText('read')).toBeInTheDocument();
  expect(screen.getByText('sha256:test')).toBeInTheDocument();
});

test('projects expose an Agent selector and pass it to the workspace query', async () => {
  render(<LocaleProvider><App /></LocaleProvider>);
  await waitFor(() => expect(screen.getByText('ready')).toBeInTheDocument());
  fireEvent.click(screen.getByRole('button', { name: 'Projects' }));
  const selector = await screen.findByRole('combobox', { name: 'Agent' });
  fireEvent.change(selector, { target: { value: 'claudeCode' } });
  await waitFor(() => expect(invoke).toHaveBeenCalledWith('workspaces_list', { limit: 100, offset: 0, agentKind: 'claudeCode' }));
});

test('transfer view exposes export and import session history actions', async () => {
  render(<LocaleProvider><App /></LocaleProvider>);
  await waitFor(() => expect(screen.getByText('ready')).toBeInTheDocument());
  fireEvent.click(screen.getByRole('button', { name: 'Transfer' }));
  expect(await screen.findByRole('button', { name: 'Export session history' })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Import session history' })).toBeInTheDocument();
});
