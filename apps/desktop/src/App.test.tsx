import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { expect, test, vi } from 'vitest';
import { App } from './App';
import { LocaleProvider } from './i18n';
import { afterEach, beforeEach } from 'vitest';

afterEach(() => cleanup());

const { invoke, dialog, dialogState, exportResult, importError, restoreError, restoreResult } = vi.hoisted(() => ({
  dialogState: {
    exportPath: 'C:\\Users\\33384\\Documents\\AgentArk\\agent-history.ahbundle' as string | null,
    importPath: 'C:\\Users\\33384\\Documents\\AgentArk\\agent-history.ahbundle' as string | null,
  },
  dialog: {
    save: vi.fn<() => Promise<string | null>>(() => Promise.resolve('C:\\Users\\33384\\Documents\\AgentArk\\agent-history.ahbundle')),
    open: vi.fn<() => Promise<string | null>>(() => Promise.resolve('C:\\Users\\33384\\Documents\\AgentArk\\agent-history.ahbundle')),
  },
  exportResult: {
    format: '1.2', sessionCount: 0, entryCount: 0, workspaceCount: 0, fileCount: 0, skippedFileCount: 0, conflictCount: 0, redacted: false, redactionCount: 0, restoreScanId: null, agent: 'codex', nativePayloadCount: 0, nativeImportedCount: 0, nativeSkippedCount: 0, nativeConflictCount: 0, nativeRestartRequired: false, nativeIdentityCount: 0, continuationCount: 0, archiveOnlyCount: 0, restoreMappingCount: 0, manualInterventionCount: 0, providerLabels: [],
  },
  importError: { value: null as string | null },
  restoreError: { value: null as string | null },
  restoreResult: {
    format: '1.1', sessionCount: 4, entryCount: 4, workspaceCount: 1, fileCount: 0, conflictCount: 0, redacted: false, redactionCount: 0, restoreScanId: 'scan-1', agent: 'codex', nativeIdentityCount: 2, continuationCount: 1, archiveOnlyCount: 1, restoreMappingCount: 3, manualInterventionCount: 0, recoveryError: undefined as string | undefined, providerLabels: ['openai'],
  },
  invoke: vi.fn((command: string) => {
    if (command === 'status') return Promise.resolve({ datasetState: 'ready', capabilities: ['read'], schemaFingerprint: 'sha256:test' });
    if (command === 'sessions_list') return Promise.resolve([]);
    if (command === 'quarantines_list') return Promise.resolve([]);
    if (command === 'bundle_verify') return importError.value
      ? Promise.reject(importError.value)
      : Promise.resolve({ format: '1.1', sessionCount: 0, entryCount: 0, workspaceCount: 0, fileCount: 0, conflictCount: 0, redacted: 0, redactionCount: 0, restoreScanId: null, agent: 'codex' });
    if (command === 'bundle_export') return Promise.resolve(exportResult);
    if (command === 'bundle_restore') return restoreError.value
      ? Promise.reject(restoreError.value)
      : Promise.resolve(restoreResult);
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
  exportResult.skippedFileCount = 0;
  importError.value = null;
  restoreError.value = null;
  restoreResult.manualInterventionCount = 0;
  restoreResult.recoveryError = undefined;
  restoreResult.nativeIdentityCount = 2;
  restoreResult.continuationCount = 1;
  restoreResult.archiveOnlyCount = 1;
  window.localStorage.clear();
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

test('codex restore reports automatic recovery outcomes without a native-target choice', async () => {
  render(<LocaleProvider><App /></LocaleProvider>);
  await waitFor(() => expect(screen.getByText('ready')).toBeInTheDocument());
  fireEvent.click(screen.getByRole('button', { name: 'Transfer' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Import session history' }));
  await waitFor(() => expect(screen.queryByRole('checkbox', { name: /restore into codex client/i })).not.toBeInTheDocument());
  fireEvent.click(screen.getByRole('button', { name: 'Restore imported history' }));
  await waitFor(() => expect(invoke).toHaveBeenCalledWith('bundle_restore', { path: expect.any(String) }));
  expect(await screen.findByText(/2 original sessions retained/i)).toBeInTheDocument();
  expect(screen.getByText(/1 continuation created/i)).toBeInTheDocument();
  expect(screen.getByText(/1 session available in AgentArk archive only/i)).toBeInTheDocument();
});

test('transfer outcome localizes the continuation count in Chinese', async () => {
  window.localStorage.setItem('agentark.locale', 'zh-CN');
  render(<LocaleProvider><App /></LocaleProvider>);
  await waitFor(() => expect(screen.getByText('状态')).toBeInTheDocument());
  fireEvent.click(screen.getByRole('button', { name: '迁移' }));
  fireEvent.click(await screen.findByRole('button', { name: '导入会话历史' }));
  fireEvent.click(await screen.findByRole('button', { name: '恢复导入的历史' }));
  expect(await screen.findByText(/已创建 1 个延续会话/)).toBeInTheDocument();
});

test('transfer replaces unsafe recovery diagnostics in the closed disclosure', async () => {
  restoreResult.manualInterventionCount = 1;
  restoreResult.recoveryError = 'https://token.example/recovery?access_token=secret';
  render(<LocaleProvider><App /></LocaleProvider>);
  await waitFor(() => expect(screen.getByText('ready')).toBeInTheDocument());
  fireEvent.click(screen.getByRole('button', { name: 'Transfer' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Import session history' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Restore imported history' }));
  expect(await screen.findByText(/2 original sessions retained/i)).toBeInTheDocument();
  expect(screen.getByText(/1 session needs manual intervention/i)).toBeInTheDocument();
  const diagnostics = screen.getByText('Recovery diagnostics').closest('details');
  expect(diagnostics).toBeInTheDocument();
  expect(diagnostics).not.toHaveAttribute('open');
  expect(screen.queryByText('https://token.example/recovery?access_token=secret')).not.toBeInTheDocument();
  expect(screen.getByText('Recovery diagnostics unavailable.')).toBeInTheDocument();
});

test('transfer displays the stable manual-intervention recovery diagnostic', async () => {
  restoreResult.recoveryError = 'manual-intervention-required';
  render(<LocaleProvider><App /></LocaleProvider>);
  await waitFor(() => expect(screen.getByText('ready')).toBeInTheDocument());
  fireEvent.click(screen.getByRole('button', { name: 'Transfer' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Import session history' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Restore imported history' }));
  expect(await screen.findByText('manual-intervention-required')).toBeInTheDocument();
});

test('transfer explains an integrity failure when importing a copied backup', async () => {
  importError.value = 'bundle-integrity-check-failed';
  render(<LocaleProvider><App /></LocaleProvider>);
  await waitFor(() => expect(screen.getByText('ready')).toBeInTheDocument());
  fireEvent.click(screen.getByRole('button', { name: 'Transfer' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Import session history' }));

  expect(await screen.findByText('Backup integrity check failed. Copy the bundle again and retry.')).toBeInTheDocument();
});

test('transfer preserves an integrity diagnostic if the bundle changes before restore', async () => {
  restoreError.value = 'bundle-integrity-check-failed';
  render(<LocaleProvider><App /></LocaleProvider>);
  await waitFor(() => expect(screen.getByText('ready')).toBeInTheDocument());
  fireEvent.click(screen.getByRole('button', { name: 'Transfer' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Import session history' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Restore imported history' }));

  expect(await screen.findByText('Backup integrity check failed. Copy the bundle again and retry.')).toBeInTheDocument();
});

test('transfer reports oversized project files skipped during export', async () => {
  exportResult.skippedFileCount = 2;
  render(<LocaleProvider><App /></LocaleProvider>);
  await waitFor(() => expect(screen.getByText('ready')).toBeInTheDocument());
  fireEvent.click(screen.getByRole('button', { name: 'Transfer' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Export session history' }));

  expect(await screen.findByText(/2 oversized project files were not included\./)).toBeInTheDocument();
});

test('transfer discloses audit persistence failure without claiming restore success', async () => {
  restoreResult.recoveryError = 'audit-persistence-failed';
  render(<LocaleProvider><App /></LocaleProvider>);
  await waitFor(() => expect(screen.getByText('ready')).toBeInTheDocument());
  fireEvent.click(screen.getByRole('button', { name: 'Transfer' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Import session history' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Restore imported history' }));

  expect(await screen.findByText('Archive restored, but vendor recovery needs attention.')).toBeInTheDocument();
  expect(screen.queryByText(/Backup operation completed/)).not.toBeInTheDocument();
  expect(screen.getByText('audit-persistence-failed')).toBeInTheDocument();
  expect(screen.getByText(/2 original sessions retained/i)).toBeInTheDocument();
});

test('transfer localizes the partial restore status in Chinese', async () => {
  window.localStorage.setItem('agentark.locale', 'zh-CN');
  restoreResult.manualInterventionCount = 1;
  render(<LocaleProvider><App /></LocaleProvider>);
  await waitFor(() => expect(screen.getByText('状态')).toBeInTheDocument());
  fireEvent.click(screen.getByRole('button', { name: '迁移' }));
  fireEvent.click(await screen.findByRole('button', { name: '导入会话历史' }));
  fireEvent.click(await screen.findByRole('button', { name: '恢复导入的历史' }));

  expect(await screen.findByText('归档已恢复，但 Agent 客户端恢复需要处理。')).toBeInTheDocument();
  expect(screen.queryByText(/备份操作已完成/)).not.toBeInTheDocument();
  expect(screen.getByText(/1 个会话需要手动处理/)).toBeInTheDocument();
});

test('transfer reports a pure archive-only restore as partial in English', async () => {
  restoreResult.nativeIdentityCount = 0;
  restoreResult.continuationCount = 0;
  restoreResult.archiveOnlyCount = 1;
  render(<LocaleProvider><App /></LocaleProvider>);
  await waitFor(() => expect(screen.getByText('ready')).toBeInTheDocument());
  fireEvent.click(screen.getByRole('button', { name: 'Transfer' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Import session history' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Restore imported history' }));

  expect(await screen.findByText('Archive restored, but vendor recovery needs attention.')).toBeInTheDocument();
  expect(screen.queryByText(/Backup operation completed/)).not.toBeInTheDocument();
  expect(screen.getByText('1 session available in AgentArk archive only')).toBeInTheDocument();
});

test('transfer reports a pure archive-only restore as partial in Chinese', async () => {
  window.localStorage.setItem('agentark.locale', 'zh-CN');
  restoreResult.nativeIdentityCount = 0;
  restoreResult.continuationCount = 0;
  restoreResult.archiveOnlyCount = 1;
  render(<LocaleProvider><App /></LocaleProvider>);
  await waitFor(() => expect(screen.getByText('状态')).toBeInTheDocument());
  fireEvent.click(screen.getByRole('button', { name: '迁移' }));
  fireEvent.click(await screen.findByRole('button', { name: '导入会话历史' }));
  fireEvent.click(await screen.findByRole('button', { name: '恢复导入的历史' }));

  expect(await screen.findByText('归档已恢复，但 Agent 客户端恢复需要处理。')).toBeInTheDocument();
  expect(screen.queryByText(/备份操作已完成/)).not.toBeInTheDocument();
  expect(screen.getByText('1 个会话仅在 AgentArk 归档中可用')).toBeInTheDocument();
});

test('transfer never renders credential-shaped recovery diagnostics that match the legacy lowercase pattern', async () => {
  restoreResult.manualInterventionCount = 1;
  restoreResult.recoveryError = 'sk-proj-lowercase-ui-canary-123456789';
  render(<LocaleProvider><App /></LocaleProvider>);
  await waitFor(() => expect(screen.getByText('ready')).toBeInTheDocument());
  fireEvent.click(screen.getByRole('button', { name: 'Transfer' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Import session history' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Restore imported history' }));
  expect(await screen.findByText('Recovery diagnostics unavailable.')).toBeInTheDocument();
  expect(screen.queryByText('sk-proj-lowercase-ui-canary-123456789')).not.toBeInTheDocument();
});

test('transfer uses English singular recovery outcome summaries', async () => {
  restoreResult.nativeIdentityCount = 1;
  restoreResult.continuationCount = 1;
  restoreResult.archiveOnlyCount = 1;
  restoreResult.manualInterventionCount = 1;
  render(<LocaleProvider><App /></LocaleProvider>);
  await waitFor(() => expect(screen.getByText('ready')).toBeInTheDocument());
  fireEvent.click(screen.getByRole('button', { name: 'Transfer' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Import session history' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Restore imported history' }));
  expect(await screen.findByText('1 original session retained')).toBeInTheDocument();
  expect(screen.getByText('1 continuation created')).toBeInTheDocument();
  expect(screen.getByText('1 session available in AgentArk archive only')).toBeInTheDocument();
  expect(screen.getByText('1 session needs manual intervention')).toBeInTheDocument();
});

test('transfer uses English plural recovery outcome summaries', async () => {
  restoreResult.nativeIdentityCount = 2;
  restoreResult.continuationCount = 2;
  restoreResult.archiveOnlyCount = 2;
  restoreResult.manualInterventionCount = 2;
  render(<LocaleProvider><App /></LocaleProvider>);
  await waitFor(() => expect(screen.getByText('ready')).toBeInTheDocument());
  fireEvent.click(screen.getByRole('button', { name: 'Transfer' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Import session history' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Restore imported history' }));
  expect(await screen.findByText('2 original sessions retained')).toBeInTheDocument();
  expect(screen.getByText('2 continuations created')).toBeInTheDocument();
  expect(screen.getByText('2 sessions available in AgentArk archive only')).toBeInTheDocument();
  expect(screen.getByText('2 sessions need manual intervention')).toBeInTheDocument();
});
