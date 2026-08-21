import { invoke } from '@tauri-apps/api/core';

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

export const api = {
  status: () => invoke<StatusDto>('status'),
  sessionsList: (limit = 50, offset = 0) => invoke<SessionSummary[]>('sessions_list', { limit, offset }),
  sessionsShow: (sessionId: string) => invoke<PublicSessionDetail>('sessions_show', { sessionId }),
  search: (query: string, limit = 50) => invoke<SearchHit[]>('search', { query, limit }),
  quarantinesList: () => invoke<QuarantineDto[]>('quarantines_list'),
  codexDefaultRoot: () => invoke<string | null>('codex_default_root'),
  scanCodex: (sourceRoot: string) => invoke<ScanReport>('scan_codex', { sourceRoot }),
  workspacesList: (limit = 100, offset = 0) => invoke<WorkspaceDto[]>('workspaces_list', { limit, offset }),
};
