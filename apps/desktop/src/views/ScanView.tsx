import { useEffect, useState } from 'react';
import { api, type ScanReport } from '../api';

type Props = { onScanned: () => void };

export function ScanView({ onScanned }: Props) {
  const [sourceRoot, setSourceRoot] = useState('');
  const [report, setReport] = useState<ScanReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);

  useEffect(() => {
    void api.codexDefaultRoot().then((root) => {
      if (root) setSourceRoot(root);
    }).catch(() => undefined);
  }, []);

  async function submit() {
    setRunning(true);
    setError(null);
    setReport(null);
    try {
      const nextReport = await api.scanCodex(sourceRoot);
      setReport(nextReport);
      onScanned();
    } catch (cause) {
      setError(typeof cause === 'string' ? cause : '扫描失败，请检查 Codex 路径和版本。');
    } finally {
      setRunning(false);
    }
  }

  return (
    <section className="card" aria-label="Scan Codex">
      <p className="eyebrow">Import</p>
      <h2>Scan Codex</h2>
      <p className="muted scan-description">读取 Codex 会话并建立本地加密索引。Codex 原始目录不会被修改。</p>
      <label className="field-label" htmlFor="codex-root">Codex 数据目录</label>
      <div className="scan-form">
        <input
          id="codex-root"
          aria-label="Codex data directory"
          value={sourceRoot}
          onChange={(event) => setSourceRoot(event.target.value)}
          placeholder="C:\\Users\\你的用户名\\.codex"
          disabled={running}
        />
        <button className="primary-button" type="button" onClick={() => void submit()} disabled={running}>
          {running ? 'Scanning…' : 'Scan now'}
        </button>
      </div>
      <p className="muted scan-hint">首次使用可直接保留默认路径；应用会先检查 Codex 版本兼容性。</p>
      {error && <p className="error-message" role="alert">{error}</p>}
      {report && (
        <div className={`scan-result ${report.status}`} role="status">
          <strong>{report.status === 'complete' ? 'Scan complete' : 'Scan finished with warnings'}</strong>
          <span>{report.indexed} indexed · {report.quarantined} quarantined · {report.retryable} retryable · {report.rejected} rejected</span>
          <span className="mono">Scan ID: {report.scanId}</span>
        </div>
      )}
    </section>
  );
}
