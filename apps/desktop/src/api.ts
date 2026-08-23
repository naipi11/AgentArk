import { invoke } from '@tauri-apps/api/core';

export type AgentKind = 'codex' | 'claudeCode' | 'hermes' | 'openClaw' | 'openCode' | 'grokBuild';
export type AgentFilter = AgentKind | 'all';

export type StatusDto = {
  datasetState: string;
  adapterId?: string;
  executableVersion?: string;
  schemaFingerprint?: string;
  capabilities: string[];
  quarantineReason?: string;
};

export type SessionSummary = {
  id: string;
  title?: string;
  sourceKind: string;
  archived: boolean;
  completeness: string;
  stale: boolean;
};

export type PublicMessage = { ordinal: number; role: string; text: string };
export type PublicToolEvent = {
  ordinal: number;
  toolName: string;
  status: string;
  visibleInput?: string;
  visibleOutput?: string;
};
export type PublicSessionDetail = {
  id: string;
  title?: string;
  archived: boolean;
  completeness: string;
  messages: PublicMessage[];
  toolEvents: PublicToolEvent[];
};
export type SearchHit = { sessionId: string; title?: string; snippet: string; score: number };
export type QuarantineDto = {
  reasonCode: string;
  fingerprint: string;
  sanitizedLocator: string;
};
export type WorkspaceDto = {
  id: string;
  pathNative: string;
  canonicalUri: string;
  gitCommit?: string;
  sessionCount: number;
};
export type ScanReport = {
  scanId: string;
  status: 'complete' | 'partial' | 'failed';
  indexed: number;
  quarantined: number;
  retryable: number;
  rejected: number;
};
export type BundleReport = {
  format: string;
  agent?: string;
  sessionCount: number;
  entryCount: number;
  workspaceCount: number;
  fileCount: number;
  conflictCount: number;
  redacted: boolean;
  redactionCount: number;
  restoreScanId?: string;
  nativePayloadCount: number;
  nativeImportedCount: number;
  nativeSkippedCount: number;
  nativeConflictCount: number;
  nativeBackupPath?: string;
  nativeRestartRequired: boolean;
  nativeError?: string;
  nativeIdentityCount: number;
  continuationCount: number;
  archiveOnlyCount: number;
  restoreMappingCount: number;
  recoveryError?: string;
  manualInterventionCount: number;
  providerLabels: string[];
};
export type AuditVerification = { valid: boolean; eventCount: number; lastHash?: string; error?: string };

export const api = {
  status: () => invoke<StatusDto>('status'),
  sessionsList: (limit = 50, offset = 0, workspaceId?: string, agentKind?: AgentKind) => invoke<SessionSummary[]>('sessions_list', { limit, offset, workspaceId, agentKind }),
  sessionsShow: (sessionId: string) => invoke<PublicSessionDetail>('sessions_show', { sessionId }),
  search: (query: string, limit = 50) => invoke<SearchHit[]>('search', { query, limit }),
  quarantinesList: () => invoke<QuarantineDto[]>('quarantines_list'),
  codexDefaultRoot: () => invoke<string | null>('codex_default_root'),
  claudeDefaultRoot: () => invoke<string | null>('claude_default_root'),
  hermesDefaultRoot: () => invoke<string | null>('hermes_default_root'),
  openclawDefaultRoot: () => invoke<string | null>('openclaw_default_root'),
  opencodeDefaultRoot: () => invoke<string | null>('opencode_default_root'),
  grokBuildDefaultRoot: () => invoke<string | null>('grok_build_default_root'),
  scanCodex: (sourceRoot: string) => invoke<ScanReport>('scan_codex', { sourceRoot }),
  scanClaude: (sourceRoot: string) => invoke<ScanReport>('scan_claude', { sourceRoot }),
  scanHermes: (sourceRoot: string) => invoke<ScanReport>('scan_hermes', { sourceRoot }),
  scanOpenClaw: (sourceRoot: string) => invoke<ScanReport>('scan_openclaw', { sourceRoot }),
  scanOpenCode: (sourceRoot: string) => invoke<ScanReport>('scan_opencode', { sourceRoot }),
  scanGrokBuild: (sourceRoot: string) => invoke<ScanReport>('scan_grok_build', { sourceRoot }),
  bundleExport: (path: string, agentKind?: AgentKind, workspaceIds: string[] = [], includeFiles = false) => invoke<BundleReport>('bundle_export', { path, agentKind: agentKind ?? null, workspaceIds, includeFiles }),
  bundleVerify: (path: string) => invoke<BundleReport>('bundle_verify', { path }),
  bundleRestore: (path: string) => invoke<BundleReport>('bundle_restore', { path }),
  auditVerify: () => invoke<AuditVerification>('audit_verify'),
  workspacesList: (limit = 100, offset = 0, agentKind?: AgentKind) => invoke<WorkspaceDto[]>('workspaces_list', { limit, offset, agentKind }),
};
