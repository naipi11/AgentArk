import { useEffect, useState } from 'react';
import { api, type PublicSessionDetail, type StatusDto } from './api';
import { QuarantineView } from './views/QuarantineView';
import { SessionsView } from './views/SessionsView';
import { StatusView } from './views/StatusView';
import { TimelineView } from './views/TimelineView';

type Tab = 'status' | 'sessions' | 'timeline' | 'quarantine';

export function App() {
  const [tab, setTab] = useState<Tab>('status');
  const [status, setStatus] = useState<StatusDto | null>(null);
  const [session, setSession] = useState<PublicSessionDetail | null>(null);
  useEffect(() => { void api.status().then(setStatus).catch(() => setStatus(null)); }, []);
  const tabs: [Tab, string][] = [['status', 'Status'], ['sessions', 'Sessions'], ['timeline', 'Timeline'], ['quarantine', 'Quarantine']];
  return (
    <main className="app-shell">
      <header className="app-header"><div><p className="eyebrow">Local archive</p><h1>AgentArk</h1></div><span className="lock-pill">Read-only</span></header>
      <nav className="tabs" aria-label="Primary navigation">{tabs.map(([value, label]) => <button className={tab === value ? 'active' : ''} key={value} onClick={() => setTab(value)}>{label}</button>)}</nav>
      <div className="content">{tab === 'status' && <StatusView status={status} />}{tab === 'sessions' && <SessionsView onSelect={(detail) => { setSession(detail); setTab('timeline'); }} />}{tab === 'timeline' && <TimelineView session={session} />}{tab === 'quarantine' && <QuarantineView />}</div>
    </main>
  );
}
