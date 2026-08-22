import { useEffect, useState } from 'react';
import { api, type AgentFilter, type PublicSessionDetail, type StatusDto, type WorkspaceDto } from './api';
import { QuarantineView } from './views/QuarantineView';
import { ProjectsView } from './views/ProjectsView';
import { ScanView } from './views/ScanView';
import { SessionsView } from './views/SessionsView';
import { StatusView } from './views/StatusView';
import { TimelineView } from './views/TimelineView';
import { TransferView } from './views/TransferView';
import { useI18n } from './i18n';

type Tab = 'status' | 'scan' | 'projects' | 'sessions' | 'timeline' | 'quarantine' | 'transfer';

export function App() {
  const [tab, setTab] = useState<Tab>('status');
  const [status, setStatus] = useState<StatusDto | null>(null);
  const [session, setSession] = useState<PublicSessionDetail | null>(null);
  const [workspace, setWorkspace] = useState<WorkspaceDto | null>(null);
  const [agentKind, setAgentKind] = useState<AgentFilter>('all');
  const { locale, setLocale, t } = useI18n();
  const [refreshToken, setRefreshToken] = useState(0);
  useEffect(() => { void api.status().then(setStatus).catch(() => setStatus(null)); }, []);
  const tabs: [Tab, string][] = [['status', t('tabs.status')], ['scan', t('tabs.scan')], ['projects', t('tabs.projects')], ['sessions', t('tabs.sessions')], ['timeline', t('tabs.timeline')], ['transfer', t('tabs.transfer')], ['quarantine', t('tabs.quarantine')]];
  return (
    <main className="app-shell">
      <header className="app-header"><div><p className="eyebrow">{t('brand.eyebrow')}</p><h1>AgentArk</h1></div><div className="header-actions"><label className="language-control"><span className="sr-only">{t('locale.label')}</span><select value={locale} onChange={(event) => setLocale(event.target.value as typeof locale)}><option value="en-US">{t('locale.en')}</option><option value="zh-CN">{t('locale.zh')}</option></select></label><span className="lock-pill">{t('brand.sourceReadonly')}</span></div></header>
      <nav className="tabs" aria-label="Primary navigation">{tabs.map(([value, label]) => <button className={tab === value ? 'active' : ''} key={value} onClick={() => setTab(value)}>{label}</button>)}</nav>
      <div className="content">{tab === 'status' && <StatusView status={status} />}{tab === 'scan' && <ScanView onScanned={() => { setRefreshToken((value) => value + 1); void api.status().then(setStatus).catch(() => setStatus(null)); }} />}{tab === 'projects' && <ProjectsView key={`${refreshToken}-${agentKind}`} agentKind={agentKind} onAgentKindChange={(value) => { setAgentKind(value); setWorkspace(null); }} onSelect={(project) => { setWorkspace(project); setTab('sessions'); }} />}{tab === 'sessions' && <SessionsView key={`${refreshToken}-${workspace?.id ?? 'all'}-${agentKind}`} agentKind={agentKind} onAgentKindChange={(value) => { setAgentKind(value); setWorkspace(null); }} workspaceId={workspace?.id} workspaceName={workspace?.pathNative.split(/[\\/]/).filter(Boolean).at(-1)} onSelect={(detail) => { setSession(detail); setTab('timeline'); }} />}{tab === 'timeline' && <TimelineView session={session} />}{tab === 'transfer' && <TransferView refreshToken={refreshToken} />}{tab === 'quarantine' && <QuarantineView />}</div>
    </main>
  );
}
