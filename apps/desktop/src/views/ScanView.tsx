import { useEffect, useState } from 'react';
import { api, type ScanReport } from '../api';
import { useI18n } from '../i18n';

type Props = { onScanned: () => void };

export function ScanView({ onScanned }: Props) {
  const [agent, setAgent] = useState<'codex' | 'claude' | 'hermes' | 'openclaw' | 'opencode'>('codex');
  const [sourceRoot, setSourceRoot] = useState('');
  const [report, setReport] = useState<ScanReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const { t } = useI18n();

  useEffect(() => {
    const rootCall = agent === 'codex' ? api.codexDefaultRoot() : agent === 'claude' ? api.claudeDefaultRoot() : agent === 'hermes' ? api.hermesDefaultRoot() : agent === 'openclaw' ? api.openclawDefaultRoot() : api.opencodeDefaultRoot();
    void rootCall.then((root) => {
      if (root) setSourceRoot(root);
    }).catch(() => undefined);
  }, [agent]);

  async function submit() {
    setRunning(true);
    setError(null);
    setReport(null);
    try {
      const nextReport = agent === 'codex' ? await api.scanCodex(sourceRoot) : agent === 'claude' ? await api.scanClaude(sourceRoot) : agent === 'hermes' ? await api.scanHermes(sourceRoot) : agent === 'openclaw' ? await api.scanOpenClaw(sourceRoot) : await api.scanOpenCode(sourceRoot);
      setReport(nextReport);
      onScanned();
    } catch (cause) {
      setError(typeof cause === 'string' ? cause : t('scan.error'));
    } finally {
      setRunning(false);
    }
  }

  return (
    <section className="card" aria-label={t('scan.title')}>
      <p className="eyebrow">{t('scan.import')}</p>
      <h2>{t('scan.title')}</h2>
      <p className="muted scan-description">{t('scan.description')}</p>
      <label className="field-label" htmlFor="codex-root">{t('scan.directory')}</label>
      <label className="field-label" htmlFor="scan-agent">{t('scan.agent')}</label>
      <select id="scan-agent" className="agent-select" value={agent} onChange={(event) => setAgent(event.target.value as typeof agent)} disabled={running}>
        <option value="codex">Codex</option>
        <option value="claude">Claude Code</option>
        <option value="hermes">Hermes</option>
        <option value="openclaw">OpenClaw</option>
        <option value="opencode">OpenCode</option>
      </select>
      <div className="scan-form">
        <input
          id="codex-root"
          aria-label={t('scan.directory')}
          value={sourceRoot}
          onChange={(event) => setSourceRoot(event.target.value)}
          placeholder={t('scan.placeholder')}
          disabled={running}
        />
        <button className="primary-button" type="button" onClick={() => void submit()} disabled={running}>
          {running ? t('scan.scanning') : t('scan.now')}
        </button>
      </div>
      <p className="muted scan-hint">{t('scan.hint')}</p>
      {error && <p className="error-message" role="alert">{error}</p>}
      {report && (
        <div className={`scan-result ${report.status}`} role="status">
          <strong>{report.status === 'complete' ? t('scan.complete') : report.status === 'failed' ? t('scan.failed') : t('scan.warnings')}</strong>
          <span>{report.indexed} indexed · {report.quarantined} quarantined · {report.retryable} retryable · {report.rejected} rejected</span>
          <span className="mono">{t('scan.id')}: {report.scanId}</span>
        </div>
      )}
    </section>
  );
}
