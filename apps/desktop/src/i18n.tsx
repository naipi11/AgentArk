import { createContext, useContext, useMemo, useState, type ReactNode } from 'react';

export type Locale = 'en-US' | 'zh-CN';
type MessageKey =
  | 'brand.eyebrow' | 'brand.sourceReadonly'
  | 'tabs.status' | 'tabs.scan' | 'tabs.projects' | 'tabs.sessions' | 'tabs.timeline' | 'tabs.quarantine'
  | 'locale.label' | 'locale.en' | 'locale.zh'
  | 'status.loading' | 'status.dataset' | 'status.adapter' | 'status.executable' | 'status.schema'
  | 'scan.import' | 'scan.title' | 'scan.description' | 'scan.directory' | 'scan.placeholder'
  | 'scan.scanning' | 'scan.now' | 'scan.hint' | 'scan.complete' | 'scan.warnings' | 'scan.failed'
  | 'scan.error' | 'scan.id'
  | 'projects.workspaces' | 'projects.title' | 'projects.countOne' | 'projects.countMany'
  | 'projects.failed' | 'projects.empty' | 'projects.sessions' | 'projects.git'
  | 'sessions.archive' | 'sessions.project' | 'sessions.title' | 'sessions.filter'
  | 'sessions.untitled' | 'sessions.noResults' | 'sessions.stale'
  | 'timeline.title' | 'timeline.untitled' | 'timeline.select'
  | 'quarantine.safety' | 'quarantine.title' | 'quarantine.empty';

const messages: Record<Locale, Record<MessageKey, string>> = {
  'en-US': {
    'brand.eyebrow': 'Local archive', 'brand.sourceReadonly': 'Source read-only',
    'tabs.status': 'Status', 'tabs.scan': 'Scan', 'tabs.projects': 'Projects', 'tabs.sessions': 'Sessions', 'tabs.timeline': 'Timeline', 'tabs.quarantine': 'Quarantine',
    'locale.label': 'Language', 'locale.en': 'English', 'locale.zh': '中文',
    'status.loading': 'Loading status…', 'status.dataset': 'Dataset', 'status.adapter': 'Adapter', 'status.executable': 'Executable', 'status.schema': 'Schema fingerprint',
    'scan.import': 'Import', 'scan.title': 'Scan Codex', 'scan.description': 'Read Codex sessions and build a local encrypted index. The Codex source directory is never modified.', 'scan.directory': 'Codex data directory', 'scan.placeholder': 'C:\\Users\\YourName\\.codex', 'scan.scanning': 'Scanning…', 'scan.now': 'Scan now', 'scan.hint': 'Keep the default path for the first scan; AgentArk checks Codex compatibility first.', 'scan.complete': 'Scan complete', 'scan.warnings': 'Scan finished with warnings', 'scan.failed': 'Scan failed', 'scan.error': 'Scan failed. Check the Codex path and version.', 'scan.id': 'Scan ID',
    'projects.workspaces': 'Workspaces', 'projects.title': 'Projects', 'projects.countOne': 'project', 'projects.countMany': 'projects', 'projects.failed': 'Unable to read the project index. Reopen the client.', 'projects.empty': 'No project assignment yet. Run a Codex scan from the Scan page.', 'projects.sessions': 'sessions', 'projects.git': 'Git',
    'sessions.archive': 'Archive', 'sessions.project': 'Project', 'sessions.title': 'Sessions', 'sessions.filter': 'Filter sessions', 'sessions.untitled': 'Untitled session', 'sessions.noResults': 'No sessions found.', 'sessions.stale': 'stale',
    'timeline.title': 'Timeline', 'timeline.untitled': 'Untitled session', 'timeline.select': 'Select a session to inspect its timeline.',
    'quarantine.safety': 'Safety boundary', 'quarantine.title': 'Quarantine', 'quarantine.empty': 'No quarantined records.',
  },
  'zh-CN': {
    'brand.eyebrow': '本地归档', 'brand.sourceReadonly': '源目录只读',
    'tabs.status': '状态', 'tabs.scan': '扫描', 'tabs.projects': '项目', 'tabs.sessions': '会话', 'tabs.timeline': '时间线', 'tabs.quarantine': '隔离区',
    'locale.label': '语言', 'locale.en': 'English', 'locale.zh': '中文',
    'status.loading': '正在加载状态…', 'status.dataset': '数据集', 'status.adapter': '适配器', 'status.executable': '可执行版本', 'status.schema': 'Schema 指纹',
    'scan.import': '导入', 'scan.title': '扫描 Codex', 'scan.description': '读取 Codex 会话并建立本地加密索引，不会修改 Codex 原始目录。', 'scan.directory': 'Codex 数据目录', 'scan.placeholder': 'C:\\Users\\你的用户名\\.codex', 'scan.scanning': '扫描中…', 'scan.now': '开始扫描', 'scan.hint': '首次使用可保留默认路径；应用会先检查 Codex 版本兼容性。', 'scan.complete': '扫描完成', 'scan.warnings': '扫描完成，但有警告', 'scan.failed': '扫描失败', 'scan.error': '扫描失败，请检查 Codex 路径和版本。', 'scan.id': '扫描 ID',
    'projects.workspaces': '工作区', 'projects.title': '项目', 'projects.countOne': '个项目', 'projects.countMany': '个项目', 'projects.failed': '无法读取项目索引，请重新打开客户端。', 'projects.empty': '尚未建立项目归属，请在扫描页面重新扫描 Codex。', 'projects.sessions': '个会话', 'projects.git': 'Git',
    'sessions.archive': '归档', 'sessions.project': '项目', 'sessions.title': '会话', 'sessions.filter': '筛选会话', 'sessions.untitled': '未命名会话', 'sessions.noResults': '没有找到会话。', 'sessions.stale': '过期',
    'timeline.title': '时间线', 'timeline.untitled': '未命名会话', 'timeline.select': '请选择一个会话查看时间线。',
    'quarantine.safety': '安全边界', 'quarantine.title': '隔离区', 'quarantine.empty': '没有隔离记录。',
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
