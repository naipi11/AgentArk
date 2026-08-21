import { useState } from 'react';
import { api, type StatusDto } from '../api';
import { useI18n } from '../i18n';

export function StatusView({ status }: { status: StatusDto | null }) {
  const { t } = useI18n();
  const [path, setPath] = useState('');
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function run(operation: 'export' | 'verify' | 'restore') {
    setBusy(true); setMessage(null);
    try {
      const report = operation === 'export' ? await api.bundleExport(path) : operation === 'verify' ? await api.bundleVerify(path) : await api.bundleRestore(path);
      setMessage(`${t('backup.success')} · ${report.sessionCount} · ${report.format}`);
    } catch { setMessage(t('backup.error')); }
    finally { setBusy(false); }
  }
  if (!status) return <section className="card">{t('status.loading')}</section>;
  return (
    <section className="card" aria-label="Status">
      <p className="eyebrow">{t('status.dataset')}</p>
      <h2>{status.datasetState}</h2>
      <dl>
        <dt>{t('status.adapter')}</dt><dd>{status.adapterId ?? '—'}</dd>
        <dt>{t('status.executable')}</dt><dd>{status.executableVersion ?? '—'}</dd>
        <dt>{t('status.schema')}</dt><dd className="mono">{status.schemaFingerprint ?? '—'}</dd>
      </dl>
      <div className="chips">{status.capabilities.map((capability) => <span key={capability}>{capability}</span>)}</div>
      <div className="backup-panel">
        <p className="eyebrow">{t('backup.title')}</p>
        <label className="field-label" htmlFor="bundle-path">{t('backup.path')}</label>
        <input id="bundle-path" value={path} onChange={(event) => setPath(event.target.value)} placeholder={t('backup.placeholder')} disabled={busy} />
        <div className="button-row">
          <button type="button" className="primary-button" onClick={() => void run('export')} disabled={busy || !path.trim()}>{t('backup.export')}</button>
          <button type="button" onClick={() => void run('verify')} disabled={busy || !path.trim()}>{t('backup.verify')}</button>
          <button type="button" onClick={() => void run('restore')} disabled={busy || !path.trim()}>{t('backup.restore')}</button>
        </div>
        {message && <p className="muted" role="status">{message}</p>}
      </div>
    </section>
  );
}
