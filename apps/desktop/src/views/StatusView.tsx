import type { StatusDto } from '../api';
import { useI18n } from '../i18n';

export function StatusView({ status }: { status: StatusDto | null }) {
  const { t } = useI18n();
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
    </section>
  );
}
