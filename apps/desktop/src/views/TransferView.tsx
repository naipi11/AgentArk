import { useEffect, useMemo, useState } from 'react';
import { open, save } from '@tauri-apps/plugin-dialog';
import { api, type AgentFilter, type BundleReport, type WorkspaceDto } from '../api';
import { AgentSelector } from '../components/AgentSelector';
import { useI18n } from '../i18n';

const bundleDialogFilters = [{ name: 'AgentArk bundle', extensions: ['ahbundle'] }];
const publicRecoveryReasonCodes = Object.freeze([
  'native-identity-verified',
  'target-default-continuation',
  'continuation-writer-unavailable',
  'missing-provider',
  'verification-failed',
  'target-conflict',
  'recovery-unavailable',
  'rollback-required',
  'manual-intervention-required',
  'native-payload-unavailable',
  'target-default-unavailable',
  'audit-persistence-failed',
] as const);

function isPublicRecoveryReasonCode(value: string): boolean {
  return (publicRecoveryReasonCodes as readonly string[]).includes(value);
}

export function TransferView({ refreshToken }: { refreshToken: number }) {
  const { t } = useI18n();
  const [agentKind, setAgentKind] = useState<AgentFilter>('codex');
  const [projects, setProjects] = useState<WorkspaceDto[]>([]);
  const [selected, setSelected] = useState<string[]>([]);
  const [includeFiles, setIncludeFiles] = useState(true);
  const [path, setPath] = useState('');
  const [preview, setPreview] = useState<BundleReport | null>(null);
  const [restoreReport, setRestoreReport] = useState<BundleReport | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [busyAction, setBusyAction] = useState<'export' | 'import' | 'restore' | null>(null);

  function safeRecoveryDiagnostic(value: string | undefined) {
    return value && isPublicRecoveryReasonCode(value)
      ? value
      : t('transfer.recoveryDiagnosticsUnavailable');
  }

  function recoveryOutcomeSummary(count: number, singular: Parameters<typeof t>[0], plural: Parameters<typeof t>[0]) {
    return t(count === 1 ? singular : plural).replace('{count}', String(count));
  }

  function importErrorMessage(error: unknown): string {
    const code = typeof error === 'string'
      ? error
      : error instanceof Error
        ? error.message
        : '';
    switch (code) {
      case 'bundle-file-unreadable': return t('transfer.importFileUnreadable');
      case 'bundle-integrity-check-failed': return t('transfer.importIntegrityFailed');
      case 'bundle-invalid-format': return t('transfer.importInvalidFormat');
      default: return t('backup.error');
    }
  }

  useEffect(() => {
    void api.workspacesList(100, 0, agentKind === 'all' ? undefined : agentKind).then((items) => {
      setProjects(items);
      setSelected(items.map((item) => item.id));
    }).catch(() => setProjects([]));
  }, [agentKind, refreshToken]);

  const selectedSet = useMemo(() => new Set(selected), [selected]);
  const toggleProject = (id: string) => setSelected((current) => current.includes(id) ? current.filter((value) => value !== id) : [...current, id]);

  async function exportHistory() {
    let selectedPath: string | null;
    try {
      selectedPath = await save({
        title: t('transfer.export'),
        defaultPath: 'agent-history.ahbundle',
        filters: bundleDialogFilters,
      });
    } catch {
      setMessage(t('backup.error'));
      return;
    }
    if (!selectedPath) return;
    if (!selectedPath.toLowerCase().endsWith('.ahbundle')) selectedPath += '.ahbundle';
    setPath(selectedPath);
    setBusy(true); setBusyAction('export'); setMessage(null); setPreview(null); setRestoreReport(null);
    try {
      const report = await api.bundleExport(selectedPath, agentKind === 'all' ? undefined : agentKind, selected, includeFiles);
      const skippedFiles = report.skippedFileCount ?? 0;
      setMessage([
        `${t('backup.success')} · ${report.sessionCount} sessions · ${report.fileCount} files`,
        skippedFiles > 0 ? t('transfer.filesSkipped').replace('{count}', String(skippedFiles)) : null,
      ].filter(Boolean).join(' · '));
    } catch { setMessage(t('backup.error')); }
    finally { setBusy(false); setBusyAction(null); }
  }

  async function inspectHistory() {
    let selectedPath: string | string[] | null;
    try {
      selectedPath = await open({
        title: t('transfer.import'),
        multiple: false,
        directory: false,
        filters: bundleDialogFilters,
      });
    } catch {
      setMessage(t('backup.error'));
      return;
    }
    const chosenPath = Array.isArray(selectedPath) ? selectedPath[0] : selectedPath;
    if (!chosenPath) return;
    setPath(chosenPath);
    setBusy(true); setBusyAction('import'); setMessage(null); setRestoreReport(null);
    try {
      const report = await api.bundleVerify(chosenPath);
      setPreview(report);
    }
    catch (error) { setMessage(importErrorMessage(error)); }
    finally { setBusy(false); setBusyAction(null); }
  }

  async function restoreHistory() {
    setBusy(true); setBusyAction('restore'); setMessage(null);
    try {
      const report = await api.bundleRestore(path);
      const needsRecoveryAttention = Boolean(report.recoveryError)
        || report.manualInterventionCount > 0
        || report.archiveOnlyCount > 0;
      setMessage(needsRecoveryAttention
        ? t('transfer.restorePartial')
        : `${t('backup.success')} · ${report.sessionCount} sessions · ${report.fileCount} files`);
      setRestoreReport(report);
      setPreview(null);
    } catch { setMessage(t('backup.error')); }
    finally { setBusy(false); setBusyAction(null); }
  }

  return (
    <section className="card transfer-view" aria-label={t('transfer.title')}>
      <div className="section-heading"><div><p className="eyebrow">{t('transfer.title')}</p><h2>{t('transfer.title')}</h2></div><AgentSelector value={agentKind} onChange={(value) => { setAgentKind(value); setPreview(null); }} /></div>
      <label className="field-label" htmlFor="transfer-path">{t('transfer.path')}</label>
      <input id="transfer-path" value={path} placeholder={t('transfer.placeholder')} readOnly aria-readonly="true" disabled={busy} />
      <p className="field-label">{t('transfer.projects')}</p>
      <div className="transfer-projects">
        {projects.length === 0 && <p className="muted">{t('transfer.noProjects')}</p>}
        {projects.map((project) => <label key={project.id} className="transfer-project"><input type="checkbox" checked={selectedSet.has(project.id)} onChange={() => toggleProject(project.id)} /><span>{project.pathNative}</span><small>{project.sessionCount} {t('projects.sessions')}</small></label>)}
      </div>
      <label className="transfer-files"><input type="checkbox" checked={includeFiles} onChange={(event) => setIncludeFiles(event.target.checked)} />{t('transfer.files')}</label>
      <div className="button-row">
        <button className="primary-button" type="button" disabled={busy} onClick={() => void exportHistory()}>{busyAction === 'export' ? t('transfer.exporting') : t('transfer.export')}</button>
        <button type="button" disabled={busy} onClick={() => void inspectHistory()}>{busyAction === 'import' ? t('transfer.importing') : t('transfer.import')}</button>
      </div>
      {preview && <div className="transfer-preview" role="status"><strong>{t('transfer.preview')}</strong><span>{preview.sessionCount} sessions · {preview.fileCount} files · {t('transfer.conflicts')}: {preview.conflictCount}</span><span className="muted">{t('transfer.automaticRecovery')}</span><button type="button" className="primary-button" disabled={busy || preview.conflictCount > 0} onClick={() => void restoreHistory()}>{busyAction === 'restore' ? t('transfer.restoring') : t('transfer.restore')}</button></div>}
      {message && <p className="muted" role="status">{message}</p>}
      {restoreReport && <div className="transfer-preview" role="status">
        <strong>{t('transfer.outcomeSummary')}</strong>
        <span>{recoveryOutcomeSummary(restoreReport.nativeIdentityCount, 'transfer.nativeIdentitySummaryOne', 'transfer.nativeIdentitySummaryMany')}</span>
        <span>{recoveryOutcomeSummary(restoreReport.continuationCount, 'transfer.continuationSummaryOne', 'transfer.continuationSummaryMany')}</span>
        <span>{recoveryOutcomeSummary(restoreReport.archiveOnlyCount, 'transfer.archiveOnlySummaryOne', 'transfer.archiveOnlySummaryMany')}</span>
        {restoreReport.manualInterventionCount > 0 && <span>{recoveryOutcomeSummary(restoreReport.manualInterventionCount, 'transfer.manualInterventionSummaryOne', 'transfer.manualInterventionSummaryMany')}</span>}
        {restoreReport.recoveryError && <details><summary>{t('transfer.recoveryDiagnostics')}</summary><span className="muted">{safeRecoveryDiagnostic(restoreReport.recoveryError)}</span></details>}
      </div>}
    </section>
  );
}
