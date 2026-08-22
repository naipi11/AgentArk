import { createContext, useContext, useMemo, useState, type ReactNode } from 'react';

export type Locale = 'en-US' | 'zh-CN';
type MessageKey =
  | 'brand.eyebrow' | 'brand.sourceReadonly'
  | 'tabs.status' | 'tabs.scan' | 'tabs.projects' | 'tabs.sessions' | 'tabs.timeline' | 'tabs.quarantine' | 'tabs.transfer'
  | 'locale.label' | 'locale.en' | 'locale.zh'
  | 'status.loading' | 'status.dataset' | 'status.adapter' | 'status.executable' | 'status.schema'
  | 'scan.import' | 'scan.title' | 'scan.description' | 'scan.directory' | 'scan.placeholder' | 'scan.agent'
  | 'scan.scanning' | 'scan.now' | 'scan.hint' | 'scan.complete' | 'scan.warnings' | 'scan.failed'
  | 'scan.error' | 'scan.id'
  | 'agents.all' | 'agents.codex' | 'agents.claudeCode' | 'agents.hermes' | 'agents.openClaw' | 'agents.openCode' | 'agents.grokBuild'
  | 'projects.workspaces' | 'projects.title' | 'projects.countOne' | 'projects.countMany'
  | 'projects.failed' | 'projects.empty' | 'projects.sessions' | 'projects.git'
  | 'sessions.archive' | 'sessions.project' | 'sessions.title' | 'sessions.filter'
  | 'sessions.untitled' | 'sessions.noResults' | 'sessions.stale'
  | 'timeline.title' | 'timeline.untitled' | 'timeline.select'
  | 'quarantine.safety' | 'quarantine.title' | 'quarantine.empty'
  | 'backup.title' | 'backup.path' | 'backup.placeholder' | 'backup.export' | 'backup.verify' | 'backup.restore' | 'backup.success' | 'backup.error'
  | 'transfer.title' | 'transfer.export' | 'transfer.import' | 'transfer.restore' | 'transfer.agent' | 'transfer.projects' | 'transfer.files' | 'transfer.noProjects' | 'transfer.preview' | 'transfer.conflicts' | 'transfer.path' | 'transfer.placeholder' | 'transfer.exporting' | 'transfer.importing' | 'transfer.restoring' | 'transfer.nativeRestore' | 'transfer.nativeRestart' | 'transfer.nativeSummary' | 'transfer.nativeSkipped' | 'transfer.nativeConflict' | 'transfer.nativeBackup' | 'transfer.nativeError';

const messages: Record<Locale, Record<MessageKey, string>> = {
  'en-US': {
    'brand.eyebrow': 'Local archive', 'brand.sourceReadonly': 'Source read-only',
    'tabs.status': 'Status', 'tabs.scan': 'Scan', 'tabs.projects': 'Projects', 'tabs.sessions': 'Sessions', 'tabs.timeline': 'Timeline', 'tabs.quarantine': 'Quarantine', 'tabs.transfer': 'Transfer',
    'locale.label': 'Language', 'locale.en': 'English', 'locale.zh': '中文',
    'status.loading': 'Loading status…', 'status.dataset': 'Dataset', 'status.adapter': 'Adapter', 'status.executable': 'Executable', 'status.schema': 'Schema fingerprint',
    'scan.import': 'Import', 'scan.title': 'Scan agent data', 'scan.description': 'Read supported agent sessions and build a local encrypted index. Source data is never modified.', 'scan.directory': 'Agent data directory', 'scan.placeholder': 'Select an agent or enter its data directory', 'scan.agent': 'Agent', 'scan.scanning': 'Scanning…', 'scan.now': 'Scan now', 'scan.hint': 'Keep the detected path for the first scan; AgentArk validates the source before indexing.', 'scan.complete': 'Scan complete', 'scan.warnings': 'Scan finished with warnings', 'scan.failed': 'Scan failed', 'scan.error': 'Scan failed. Check the selected agent path and version.', 'scan.id': 'Scan ID',
    'agents.all': 'All Agents', 'agents.codex': 'Codex', 'agents.claudeCode': 'Claude Code', 'agents.hermes': 'Hermes', 'agents.openClaw': 'OpenClaw', 'agents.openCode': 'OpenCode', 'agents.grokBuild': 'Grok Build',
    'projects.workspaces': 'Workspaces', 'projects.title': 'Projects', 'projects.countOne': 'project', 'projects.countMany': 'projects', 'projects.failed': 'Unable to read the project index. Reopen the client.', 'projects.empty': 'No project assignment yet. Run a Codex scan from the Scan page.', 'projects.sessions': 'sessions', 'projects.git': 'Git',
    'sessions.archive': 'Archive', 'sessions.project': 'Project', 'sessions.title': 'Sessions', 'sessions.filter': 'Filter sessions', 'sessions.untitled': 'Untitled session', 'sessions.noResults': 'No sessions found.', 'sessions.stale': 'stale',
    'timeline.title': 'Timeline', 'timeline.untitled': 'Untitled session', 'timeline.select': 'Select a session to inspect its timeline.',
    'quarantine.safety': 'Safety boundary', 'quarantine.title': 'Quarantine', 'quarantine.empty': 'No quarantined records.',
    'backup.title': 'Portable backup (.ahbundle)', 'backup.path': 'Bundle path', 'backup.placeholder': 'C:\\Users\\YourName\\agentark-backup.ahbundle', 'backup.export': 'Create backup', 'backup.verify': 'Verify backup', 'backup.restore': 'Restore backup', 'backup.success': 'Backup operation completed', 'backup.error': 'Backup operation failed.',
    'transfer.title': 'Session history transfer', 'transfer.export': 'Export session history', 'transfer.import': 'Import session history', 'transfer.restore': 'Restore imported history', 'transfer.agent': 'Export Agent', 'transfer.projects': 'Projects to include', 'transfer.files': 'Include project files', 'transfer.noProjects': 'No projects for this Agent.', 'transfer.preview': 'Verified bundle', 'transfer.conflicts': 'Conflicts', 'transfer.path': 'Selected bundle path', 'transfer.placeholder': 'Choose a destination or an .ahbundle file with the buttons below', 'transfer.exporting': 'Exporting…', 'transfer.importing': 'Checking…', 'transfer.restoring': 'Restoring…', 'transfer.nativeRestore': 'Restore into Codex client', 'transfer.nativeRestart': 'Restart Codex after restore to refresh its session list.', 'transfer.nativeSummary': 'Codex client threads imported', 'transfer.nativeSkipped': 'Codex threads skipped', 'transfer.nativeConflict': 'Codex conflicts', 'transfer.nativeBackup': 'Codex backup', 'transfer.nativeError': 'Codex native restore failed',
  },
  'zh-CN': {
    'brand.eyebrow': '本地归档', 'brand.sourceReadonly': '源目录只读',
    'tabs.status': '状态', 'tabs.scan': '扫描', 'tabs.projects': '项目', 'tabs.sessions': '会话', 'tabs.timeline': '时间线', 'tabs.quarantine': '隔离区', 'tabs.transfer': '迁移',
    'locale.label': '语言', 'locale.en': 'English', 'locale.zh': '中文',
    'status.loading': '正在加载状态…', 'status.dataset': '数据集', 'status.adapter': '适配器', 'status.executable': '可执行版本', 'status.schema': 'Schema 指纹',
    'scan.import': '导入', 'scan.title': '扫描 Agent 数据', 'scan.description': '读取已支持 Agent 的会话并建立本地加密索引，不会修改源数据。', 'scan.directory': 'Agent 数据目录', 'scan.placeholder': '请选择 Agent，或输入数据目录', 'scan.agent': 'Agent', 'scan.scanning': '扫描中…', 'scan.now': '开始扫描', 'scan.hint': '首次使用可保留检测到的路径；应用会先验证源数据再建立索引。', 'scan.complete': '扫描完成', 'scan.warnings': '扫描完成，但有警告', 'scan.failed': '扫描失败', 'scan.error': '扫描失败，请检查所选 Agent 的路径和版本。', 'scan.id': '扫描 ID',
    'agents.all': '全部 Agent', 'agents.codex': 'Codex', 'agents.claudeCode': 'Claude Code', 'agents.hermes': 'Hermes', 'agents.openClaw': 'OpenClaw', 'agents.openCode': 'OpenCode', 'agents.grokBuild': 'Grok Build',
    'projects.workspaces': '工作区', 'projects.title': '项目', 'projects.countOne': '个项目', 'projects.countMany': '个项目', 'projects.failed': '无法读取项目索引，请重新打开客户端。', 'projects.empty': '尚未建立项目归属，请在扫描页面重新扫描 Codex。', 'projects.sessions': '个会话', 'projects.git': 'Git',
    'sessions.archive': '归档', 'sessions.project': '项目', 'sessions.title': '会话', 'sessions.filter': '筛选会话', 'sessions.untitled': '未命名会话', 'sessions.noResults': '没有找到会话。', 'sessions.stale': '过期',
    'timeline.title': '时间线', 'timeline.untitled': '未命名会话', 'timeline.select': '请选择一个会话查看时间线。',
    'quarantine.safety': '安全边界', 'quarantine.title': '隔离区', 'quarantine.empty': '没有隔离记录。',
    'backup.title': '可携带备份（.ahbundle）', 'backup.path': '备份路径', 'backup.placeholder': 'C:\\Users\\你的用户名\\agentark-backup.ahbundle', 'backup.export': '创建备份', 'backup.verify': '验证备份', 'backup.restore': '恢复备份', 'backup.success': '备份操作已完成', 'backup.error': '备份操作失败。',
    'transfer.title': '会话历史迁移', 'transfer.export': '导出会话历史', 'transfer.import': '导入会话历史', 'transfer.restore': '恢复导入的历史', 'transfer.agent': '导出 Agent', 'transfer.projects': '包含的项目', 'transfer.files': '包含项目文件', 'transfer.noProjects': '该 Agent 没有项目。', 'transfer.preview': '备份校验通过', 'transfer.conflicts': '冲突', 'transfer.path': '已选择的备份路径', 'transfer.placeholder': '请使用下方按钮选择保存位置或 .ahbundle 文件', 'transfer.exporting': '正在导出…', 'transfer.importing': '正在校验…', 'transfer.restoring': '正在恢复…', 'transfer.nativeRestore': '恢复到 Codex 客户端', 'transfer.nativeRestart': '恢复完成后请重启 Codex，以刷新会话列表。', 'transfer.nativeSummary': '已导入 Codex 客户端会话', 'transfer.nativeSkipped': '跳过的 Codex 会话', 'transfer.nativeConflict': 'Codex 会话冲突', 'transfer.nativeBackup': 'Codex 备份', 'transfer.nativeError': 'Codex 原生恢复失败',
  },
};

type I18nContextValue = { locale: Locale; setLocale: (locale: Locale) => void; t: (key: MessageKey) => string };
const I18nContext = createContext<I18nContextValue | null>(null);

function initialLocale(): Locale {
  if (typeof window !== 'undefined') {
    const saved = window.localStorage.getItem('agentark.locale');
    if (saved === 'en-US' || saved === 'zh-CN') return saved;
    if (window.navigator.language.toLowerCase().startsWith('zh')) return 'zh-CN';
  }
  return 'en-US';
}

export function LocaleProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(initialLocale);
  const setLocale = (next: Locale) => {
    setLocaleState(next);
    window.localStorage.setItem('agentark.locale', next);
  };
  const value = useMemo(() => ({ locale, setLocale, t: (key: MessageKey) => messages[locale][key] }), [locale]);
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n() {
  const value = useContext(I18nContext);
  if (!value) throw new Error('useI18n must be used inside LocaleProvider');
  return value;
}
