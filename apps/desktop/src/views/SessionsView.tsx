import { useEffect, useState } from 'react';
import type { AgentFilter, PublicSessionDetail, SessionSummary } from '../api';
import { api } from '../api';
import { AgentSelector } from '../components/AgentSelector';
import { useI18n } from '../i18n';

type Props = { onSelect: (detail: PublicSessionDetail) => void; workspaceId?: string; workspaceName?: string; agentKind: AgentFilter; onAgentKindChange: (value: AgentFilter) => void };

export function SessionsView({ onSelect, workspaceId, workspaceName, agentKind, onAgentKindChange }: Props) {
  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [query, setQuery] = useState('');
  const { t } = useI18n();
  useEffect(() => { void api.sessionsList(50, 0, workspaceId, agentKind === 'all' ? undefined : agentKind).then(setSessions).catch(() => setSessions([])); }, [workspaceId, agentKind]);
  const visible = query.trim()
    ? sessions.filter((session) => (session.title ?? '').toLowerCase().includes(query.toLowerCase()))
    : sessions;
  return (
    <section className="card" aria-label="Sessions">
      <div className="section-heading"><div><p className="eyebrow">{workspaceName ? t('sessions.project') : t('sessions.archive')}</p><h2>{workspaceName ?? t('sessions.title')}</h2></div><div className="section-actions"><AgentSelector value={agentKind} onChange={onAgentKindChange} /><input aria-label={t('sessions.filter')} value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t('sessions.filter')} /></div></div>
      <div className="session-list">
        {visible.map((session) => (
          <button className="session-item" key={session.id} onClick={() => void api.sessionsShow(session.id).then(onSelect)}>
            <strong>{session.title ?? t('sessions.untitled')}</strong>
            <span>{session.sourceKind} · {session.completeness}{session.stale ? ` · ${t('sessions.stale')}` : ''}</span>
          </button>
        ))}
        {visible.length === 0 && <p className="muted">{t('sessions.noResults')}</p>}
      </div>
    </section>
  );
}
