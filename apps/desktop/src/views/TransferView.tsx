import { useEffect, useMemo, useState } from 'react';
import { api, type AgentFilter, type BundleReport, type WorkspaceDto } from '../api';
import { AgentSelector } from '../components/AgentSelector';
import { useI18n } from '../i18n';

export function TransferView({ refreshToken }: { refreshToken: number }) {
  const { t } = useI18n();
  const [agentKind, setAgentKind] = useState<AgentFilter>('codex');
  const [projects, setProjects] = useState<WorkspaceDto[]>([]);
  const [selected, setSelected] = useState<string[]>([]);
  const [includeFiles, setIncludeFiles] = useState(true);
  const [path, setPath] = useState('');
  const [preview, setPreview] = useState<BundleReport | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    void api.workspacesList(100, 0, agentKind === 'all' ? undefined : agentKind).then((items) => {
      setProjects(items);
      setSelected(items.map((item) => item.id));
    }).catch(() => setProjects([]));
  }, [agentKind, refreshToken]);

  const selectedSet = useMemo(() => new Set(selected), [selected]);
  const toggleProject = (id: string) => setSelected((current) => current.includes(id) ? current.filter((value) => value !== id) : [...current, id]);

  async function exportHistory() {
    setBusy(true); setMessage(null); setPreview(null);
    try {
      const report = await api.bundleExport(path, agentKind === 'all' ? undefined : agentKind, selected, includeFiles);
      setMessage(`${t('backup.success')} · ${report.sessionCount} sessions · ${report.fileCount} files`);
    } catch { setMessage(t('backup.error')); }
    finally { setBusy(false); }
  }

  async function inspectHistory() {
    setBusy(true); setMessage(null);
    try { setPreview(await api.bundleVerify(path)); }
    catch { setMessage(t('backup.error')); }
    finally { setBusy(false); }
  }

  async function restoreHistory() {
    setBusy(true); setMessage(null);
    try {
      const report = await api.bundleRestore(path);
      setMessage(`${t('backup.success')} · ${report.sessionCount} sessions · ${report.fileCount} files`);
      setPreview(null);
    } catch { setMessage(t('backup.error')); }
    finally { setBusy(false); }
  }

  return (
    <section className="card transfer-view" aria-label={t('transfer.title')}>
      <div className="section-heading"><div><p className="eyebrow">{t('transfer.title')}</p><h2>{t('transfer.title')}</h2></div><AgentSelector value={agentKind} onChange={(value) => { setAgentKind(value); setPreview(null); }} /></div>
      <label className="field-label" htmlFor="transfer-path">{t('transfer.path')}</label>
      <input id="transfer-path" value={path} onChange={(event) => setPath(event.target.value)} placeholder={t('transfer.placeholder')} disabled={busy} />
      <p className="field-label">{t('transfer.projects')}</p>
      <div className="transfer-projects">
        {projects.length === 0 && <p className="muted">{t('transfer.noProjects')}</p>}
        {projects.map((project) => <label key={project.id} className="transfer-project"><input type="checkbox" checked={selectedSet.has(project.id)} onChange={() => toggleProject(project.id)} /><span>{project.pathNative}</span><small>{project.sessionCount} {t('projects.sessions')}</small></label>)}
      </div>
      <label className="transfer-files"><input type="checkbox" checked={includeFiles} onChange={(event) => setIncludeFiles(event.target.checked)} />{t('transfer.files')}</label>
      <div className="button-row">
        <button className="primary-button" type="button" disabled={busy || !path.trim()} onClick={() => void exportHistory()}>{t('transfer.export')}</button>
        <button type="button" disabled={busy || !path.trim()} onClick={() => void inspectHistory()}>{t('transfer.import')}</button>
      </div>
      {preview && <div className="transfer-preview" role="status"><strong>{t('transfer.preview')}</strong><span>{preview.sessionCount} sessions · {preview.fileCount} files · {t('transfer.conflicts')}: {preview.conflictCount}</span><button type="button" className="primary-button" disabled={busy || preview.conflictCount > 0} onClick={() => void restoreHistory()}>{t('transfer.restore')}</button></div>}
      {message && <p className="muted" role="status">{message}</p>}
    </section>
  );
}
