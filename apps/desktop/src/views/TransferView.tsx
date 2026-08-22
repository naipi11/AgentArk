import { useEffect, useMemo, useState } from 'react';
import { open, save } from '@tauri-apps/plugin-dialog';
import { api, type AgentFilter, type BundleReport, type WorkspaceDto } from '../api';
import { AgentSelector } from '../components/AgentSelector';
import { useI18n } from '../i18n';

const bundleDialogFilters = [{ name: 'AgentArk bundle', extensions: ['ahbundle'] }];

export function TransferView({ refreshToken }: { refreshToken: number }) {
  const { t } = useI18n();
  const [agentKind, setAgentKind] = useState<AgentFilter>('codex');
  const [projects, setProjects] = useState<WorkspaceDto[]>([]);
  const [selected, setSelected] = useState<string[]>([]);
  const [includeFiles, setIncludeFiles] = useState(true);
  const [path, setPath] = useState('');
  const [preview, setPreview] = useState<BundleReport | null>(null);
  const [restoreNativeCodex, setRestoreNativeCodex] = useState(true);
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [busyAction, setBusyAction] = useState<'export' | 'import' | 'restore' | null>(null);

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
    setBusy(true); setBusyAction('export'); setMessage(null); setPreview(null);
    try {
      const report = await api.bundleExport(selectedPath, agentKind === 'all' ? undefined : agentKind, selected, includeFiles);
      setMessage(`${t('backup.success')} · ${report.sessionCount} sessions · ${report.fileCount} files`);
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
    setBusy(true); setBusyAction('import'); setMessage(null);
    try {
      const report = await api.bundleVerify(chosenPath);
      setPreview(report);
      setRestoreNativeCodex(report.agent === 'codex');
    }
    catch { setMessage(t('backup.error')); }
    finally { setBusy(false); setBusyAction(null); }
  }

  async function restoreHistory() {
    setBusy(true); setBusyAction('restore'); setMessage(null);
    try {
      const report = await api.bundleRestore(path, restoreNativeCodex);
      const nativeSummary = report.nativePayloadCount > 0
        ? ` · ${report.nativeImportedCount} ${t('transfer.nativeSummary')} · ${report.nativeSkippedCount} ${t('transfer.nativeSkipped')} · ${report.nativeConflictCount} ${t('transfer.nativeConflict')}`
        : '';
      const nativeBackup = report.nativeBackupPath
        ? ` · ${t('transfer.nativeBackup')}: ${report.nativeBackupPath}`
        : '';
      const nativeError = report.nativeError ? ` · ${t('transfer.nativeError')}: ${report.nativeError}` : '';
      setMessage(`${t('backup.success')} · ${report.sessionCount} sessions · ${report.fileCount} files${nativeSummary}${nativeBackup}${nativeError}`);
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
      {preview?.agent === 'codex' && <label className="transfer-files"><input type="checkbox" checked={restoreNativeCodex} onChange={(event) => setRestoreNativeCodex(event.target.checked)} />{t('transfer.nativeRestore')}</label>}
      <div className="button-row">
        <button className="primary-button" type="button" disabled={busy} onClick={() => void exportHistory()}>{busyAction === 'export' ? t('transfer.exporting') : t('transfer.export')}</button>
        <button type="button" disabled={busy} onClick={() => void inspectHistory()}>{busyAction === 'import' ? t('transfer.importing') : t('transfer.import')}</button>
      </div>
      {preview && <div className="transfer-preview" role="status"><strong>{t('transfer.preview')}</strong><span>{preview.sessionCount} sessions · {preview.fileCount} files · {t('transfer.conflicts')}: {preview.conflictCount}</span>{preview.agent === 'codex' && restoreNativeCodex && <span className="muted">{t('transfer.nativeRestart')}</span>}<button type="button" className="primary-button" disabled={busy || preview.conflictCount > 0} onClick={() => void restoreHistory()}>{busyAction === 'restore' ? t('transfer.restoring') : t('transfer.restore')}</button></div>}
      {message && <p className="muted" role="status">{message}</p>}
    </section>
  );
}
