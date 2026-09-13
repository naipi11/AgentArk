import { useRef, useState, type FormEvent } from 'react';
import { api, type PublicSessionDetail, type SearchHit } from '../api';
import { useI18n } from '../i18n';

type Props = { onSelect: (detail: PublicSessionDetail) => void };

export function SearchView({ onSelect }: Props) {
  const { t } = useI18n();
  const [query, setQuery] = useState('');
  const [hits, setHits] = useState<SearchHit[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const requestId = useRef(0);

  async function submit(event: FormEvent) {
    event.preventDefault();
    const next = query.trim();
    if (!next || busy) return;
    const currentRequest = ++requestId.current;
    setBusy(true);
    setError(false);
    try {
      const nextHits = await api.search(next, 50);
      if (currentRequest === requestId.current) setHits(nextHits);
    } catch {
      if (currentRequest === requestId.current) {
        setHits([]);
        setError(true);
      }
    } finally {
      if (currentRequest === requestId.current) setBusy(false);
    }
  }

  async function openHit(hit: SearchHit) {
    try {
      onSelect(await api.sessionsShow(hit.sessionId));
    } catch {
      setError(true);
    }
  }

  return (
    <section className="card" aria-label={t('search.title')}>
      <p className="eyebrow">{t('search.title')}</p>
      <h2>{t('search.title')}</h2>
      <form className="scan-form" onSubmit={(event) => void submit(event)}>
        <input aria-label={t('search.placeholder')} value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t('search.placeholder')} />
        <button className="primary-button" type="submit" disabled={busy || !query.trim()}>{busy ? t('search.searching') : t('search.submit')}</button>
      </form>
      {error && <p className="error-message" role="alert">{t('search.error')}</p>}
      <div className="session-list">
        {!error && hits.length === 0 && query.trim() && !busy && <p className="muted">{t('search.noResults')}</p>}
        {hits.map((hit) => (
          <button className="session-item" key={hit.sessionId} type="button" onClick={() => void openHit(hit)}>
            <strong>{hit.title ?? t('sessions.untitled')}</strong>
            <span>{hit.snippet}</span>
          </button>
        ))}
      </div>
    </section>
  );
}
