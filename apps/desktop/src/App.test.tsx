import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { expect, test, vi } from 'vitest';
import { App } from './App';
import { LocaleProvider } from './i18n';
import { afterEach, beforeEach } from 'vitest';

afterEach(() => cleanup());

const { invoke, dialog, dialogState } = vi.hoisted(() => ({
  dialogState: {
    exportPath: 'C:\\Users\\33384\\Documents\\AgentArk\\agent-history.ahbundle' as string | null,
    importPath: 'C:\\Users\\33384\\Documents\\AgentArk\\agent-history.ahbundle' as string | null,
  },
  dialog: {
    save: vi.fn<() => Promise<string | null>>(() => Promise.resolve('C:\\Users\\33384\\Documents\\AgentArk\\agent-history.ahbundle')),
    open: vi.fn<() => Promise<string | null>>(() => Promise.resolve('C:\\Users\\33384\\Documents\\AgentArk\\agent-history.ahbundle')),
  },
  invoke: vi.fn((command: string) => {
    if (command === 'status') return Promise.resolve({ datasetState: 'ready', capabilities: ['read'], schemaFingerprint: 'sha256:test' });
    if (command === 'sessions_list') return Promise.resolve([]);
    if (command === 'quarantines_list') return Promise.resolve([]);
    if (command === 'bundle_verify') return Promise.resolve({ format: '1.1', sessionCount: 0, entryCount: 0, workspaceCount: 0, fileCount: 0, conflictCount: 0, redacted: 0, redactionCount: 0, restoreScanId: null, agent: 'codex' });
    if (command === 'bundle_export') return Promise.resolve({ format: '1.1', sessionCount: 0, entryCount: 0, workspaceCount: 0, fileCount: 0, conflictCount: 0, redacted: 0, redactionCount: 0, restoreScanId: null, agent: 'codex' });
    return Promise.resolve([]);
  }),
}));
vi.mock('@tauri-apps/api/core', () => ({ invoke }));
vi.mock('@tauri-apps/plugin-dialog', () => dialog);

beforeEach(() => {
  invoke.mockClear();
  dialog.save.mockClear();
  dialog.open.mockClear();
  dialog.save.mockImplementation(() => Promise.resolve(dialogState.exportPath));
  dialog.open.mockImplementation(() => Promise.resolve(dialogState.importPath));
  dialogState.exportPath = 'C:\\Users\\33384\\Documents\\AgentArk\\agent-history.ahbundle';
  dialogState.importPath = 'C:\\Users\\33384\\Documents\\AgentArk\\agent-history.ahbundle';
});

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
  expect(screen.queryByText('Enter a bundle path before exporting or importing.')).not.toBeInTheDocument();
});

test('export asks for a destination before writing the bundle', async () => {
  render(<LocaleProvider><App /></LocaleProvider>);
  await waitFor(() => expect(screen.getByText('ready')).toBeInTheDocument());
  fireEvent.click(screen.getByRole('button', { name: 'Transfer' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Export session history' }));
  await waitFor(() => expect(dialog.save).toHaveBeenCalledWith(expect.objectContaining({ defaultPath: 'agent-history.ahbundle' })));
  await waitFor(() => expect(invoke).toHaveBeenCalledWith('bundle_export', expect.objectContaining({ path: dialogState.exportPath })));
});

test('import asks for a bundle file before verifying it', async () => {
  render(<LocaleProvider><App /></LocaleProvider>);
  await waitFor(() => expect(screen.getByText('ready')).toBeInTheDocument());
  fireEvent.click(screen.getByRole('button', { name: 'Transfer' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Import session history' }));
  await waitFor(() => expect(dialog.open).toHaveBeenCalledWith(expect.objectContaining({ multiple: false, directory: false })));
  await waitFor(() => expect(invoke).toHaveBeenCalledWith('bundle_verify', { path: dialogState.importPath }));
});

test('cancelled export does not call the bundle writer', async () => {
  dialogState.exportPath = null;
  render(<LocaleProvider><App /></LocaleProvider>);
  await waitFor(() => expect(screen.getByText('ready')).toBeInTheDocument());
  fireEvent.click(screen.getByRole('button', { name: 'Transfer' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Export session history' }));
  await waitFor(() => expect(dialog.save).toHaveBeenCalled());
  expect(invoke).not.toHaveBeenCalledWith('bundle_export', expect.anything());
});
