import type { StatusDto } from '../api';

export function StatusView({ status }: { status: StatusDto | null }) {
  if (!status) return <section className="card">Loading status…</section>;
  return (
    <section className="card" aria-label="Status">
      <p className="eyebrow">Dataset</p>
      <h2>{status.datasetState}</h2>
      <dl>
        <dt>Adapter</dt><dd>{status.adapterId ?? '—'}</dd>
        <dt>Executable</dt><dd>{status.executableVersion ?? '—'}</dd>
        <dt>Schema fingerprint</dt><dd className="mono">{status.schemaFingerprint ?? '—'}</dd>
      </dl>
      <div className="chips">{status.capabilities.map((capability) => <span key={capability}>{capability}</span>)}</div>
    </section>
  );
}
