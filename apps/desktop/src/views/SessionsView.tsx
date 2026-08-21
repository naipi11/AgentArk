import { useEffect, useState } from 'react';
import type { PublicSessionDetail, SessionSummary } from '../api';
import { api } from '../api';

type Props = { onSelect: (detail: PublicSessionDetail) => void; workspaceId?: string; workspaceName?: string };

export function SessionsView({ onSelect, workspaceId, workspaceName }: Props) {
  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [query, setQuery] = useState('');
  useEffect(() => { void api.sessionsList(50, 0, workspaceId).then(setSessions).catch(() => setSessions([])); }, [workspaceId]);
  const visible = query.trim()
    ? sessions.filter((session) => (session.title ?? '').toLowerCase().includes(query.toLowerCase()))
    : sessions;
  return (
    <section className="card" aria-label="Sessions">
      <div className="section-heading"><div><p className="eyebrow">{workspaceName ? 'Project' : 'Archive'}</p><h2>{workspaceName ?? 'Sessions'}</h2></div><input aria-label="Search sessions" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Filter sessions" /></div>
      <div className="session-list">
        {visible.map((session) => (
          <button className="session-item" key={session.id} onClick={() => void api.sessionsShow(session.id).then(onSelect)}>
            <strong>{session.title ?? 'Untitled session'}</strong>
            <span>{session.sourceKind} · {session.completeness}{session.stale ? ' · stale' : ''}</span>
          </button>
        ))}
        {visible.length === 0 && <p className="muted">No sessions found.</p>}
      </div>
    </section>
  );
}
