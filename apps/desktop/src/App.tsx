import { useEffect, useState } from 'react';
import { api, type PublicSessionDetail, type StatusDto } from './api';
import { QuarantineView } from './views/QuarantineView';
import { ProjectsView } from './views/ProjectsView';
import { ScanView } from './views/ScanView';
import { SessionsView } from './views/SessionsView';
import { StatusView } from './views/StatusView';
import { TimelineView } from './views/TimelineView';

type Tab = 'status' | 'scan' | 'projects' | 'sessions' | 'timeline' | 'quarantine';

export function App() {
  const [tab, setTab] = useState<Tab>('status');
  const [status, setStatus] = useState<StatusDto | null>(null);
  const [session, setSession] = useState<PublicSessionDetail | null>(null);
  const [refreshToken, setRefreshToken] = useState(0);
  useEffect(() => { void api.status().then(setStatus).catch(() => setStatus(null)); }, []);
  const tabs: [Tab, string][] = [['status', 'Status'], ['scan', 'Scan'], ['projects', 'Projects'], ['sessions', 'Sessions'], ['timeline', 'Timeline'], ['quarantine', 'Quarantine']];
  return (
    <main className="app-shell">
      <header className="app-header"><div><p className="eyebrow">Local archive</p><h1>AgentArk</h1></div><span className="lock-pill">Source read-only</span></header>
      <nav className="tabs" aria-label="Primary navigation">{tabs.map(([value, label]) => <button className={tab === value ? 'active' : ''} key={value} onClick={() => setTab(value)}>{label}</button>)}</nav>
      <div className="content">{tab === 'status' && <StatusView status={status} />}{tab === 'scan' && <ScanView onScanned={() => { setRefreshToken((value) => value + 1); void api.status().then(setStatus).catch(() => setStatus(null)); }} />}{tab === 'projects' && <ProjectsView key={refreshToken} />}{tab === 'sessions' && <SessionsView key={refreshToken} onSelect={(detail) => { setSession(detail); setTab('timeline'); }} />}{tab === 'timeline' && <TimelineView session={session} />}{tab === 'quarantine' && <QuarantineView />}</div>
    </main>
  );
}
