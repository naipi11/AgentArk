import { useEffect, useState } from 'react';
import type { QuarantineDto } from '../api';
import { api } from '../api';
import { useI18n } from '../i18n';

export function QuarantineView() {
  const [items, setItems] = useState<QuarantineDto[]>([]);
  const { t } = useI18n();
  useEffect(() => { void api.quarantinesList().then(setItems).catch(() => setItems([])); }, []);
  return <section className="card" aria-label={t('quarantine.title')}><p className="eyebrow">{t('quarantine.safety')}</p><h2>{t('quarantine.title')}</h2><div className="quarantine-list">{items.map((item, index) => <article key={`${item.fingerprint}-${index}`}><strong>{item.reasonCode}</strong><span className="mono">{item.fingerprint}</span><span>{item.sanitizedLocator}</span></article>)}{items.length === 0 && <p className="muted">{t('quarantine.empty')}</p>}</div></section>;
}
