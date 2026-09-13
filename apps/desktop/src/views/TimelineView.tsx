import type { PublicSessionDetail } from '../api';
import { VirtualTimeline } from '../components/VirtualTimeline';
import { useI18n } from '../i18n';

export function TimelineView({ session }: { session: PublicSessionDetail | null }) {
  const { t } = useI18n();
  if (!session) return <section className="card"><p className="muted">{t('timeline.select')}</p></section>;
  const provenanceUnavailable = session.rawProvenanceStatus === 'unresolved' || session.rawProvenanceStatus === 'unknown';
  return <section className="card" aria-label={t('timeline.title')}><p className="eyebrow">{t('timeline.title')}</p><h2>{session.title ?? t('timeline.untitled')}</h2>{provenanceUnavailable && <p className="muted" role="status">{t('timeline.rawProvenanceUnavailable')}</p>}<VirtualTimeline messages={session.messages} toolEvents={session.toolEvents} /></section>;
}
