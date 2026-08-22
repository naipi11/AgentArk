# Agent 分类与跨设备会话历史迁移 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Agent-scoped browsing and a safe, project-aware export/import workflow for session history.

**Architecture:** Extend the existing encrypted index query layer with an optional AgentKind filter. Extend the bundle layer with agent/workspace/file entries and a two-phase inspect/restore API; the Tauri UI uses the same typed commands for filtering, export, preview, and import. Vendor source adapters remain read-only, while restore writes only AgentArk-owned index/CAS data.

**Tech Stack:** Rust workspace, SQLCipher/SQLite, existing Tauri 2 + React/TypeScript desktop, `SecretScanner`, `.ahbundle` framing, SHA-256, Vitest and Rust fixtures.

**Spec:** `docs/superpowers/specs/2026-08-22-agent-filter-transfer-design.md`

## Global Constraints

- Source Agent files/databases are read-only and are never modified.
- Unknown schema, unsafe path, hash mismatch, credential-like data, and partial restore fail closed.
- Every production behavior change starts with a failing test and ends with focused plus workspace verification.
- Agent values are `all | codex | claude-code | hermes | openclaw | opencode | grok-build`.
- Credentials, OAuth tokens, cookies, private keys, and auth files are never exported.

---

### Task 1: Agent-filtered index queries

**Files:**
- Modify: `crates/index/src/query.rs`
- Modify: `crates/app/src/services.rs`
- Modify: `apps/desktop/src-tauri/src/commands.rs`
- Test: `crates/index/tests/encrypted_index.rs`

**Interfaces:**
- Add `SessionQuery::list_sessions_filtered(agent_kind: Option<AgentKind>, limit: u32, offset: u32)`.
- Add `SessionQuery::list_workspaces_filtered(agent_kind: Option<AgentKind>, limit: u32, offset: u32)`.
- Tauri `sessions_list` and `workspaces_list` accept optional serialized `agentKind`.

- [x] Write a failing Rust test inserting Codex and Claude installs with separate workspaces, then assert `list_sessions_filtered(Some(AgentKind::Codex), ...)` and workspace counts exclude Claude.
- [x] Run `cargo test -p agentark-index --test encrypted_index --offline`; expect the new test to fail because the filter methods do not exist.
- [x] Implement SQL joins through `agent_installs.kind`, preserving `None` as the existing unfiltered query.
- [x] Update `QueryUseCase`, `LockedIndexQueryService`, Tauri commands, and TypeScript API types.
- [x] Run the focused test and `cargo clippy -p agentark-index --all-targets --offline -- -D warnings`.
- [x] Commit `feat: filter projects and sessions by agent`.

### Task 2: Agent selector in Projects, Sessions, and Timeline navigation

**Files:**
- Modify: `apps/desktop/src/views/ProjectsView.tsx`
- Modify: `apps/desktop/src/views/SessionsView.tsx`
- Modify: `apps/desktop/src/App.tsx`
- Modify: `apps/desktop/src/i18n.tsx`
- Modify: `apps/desktop/src/styles.css`
- Test: `apps/desktop/src/App.test.tsx`

**Interfaces:**
- Add shared `AgentKind`/`AgentFilter` TypeScript union.
- Project/session callbacks carry `{ agentKind, workspaceId }` so a project opened from a filtered view keeps the filter.

- [x] Add a failing Vitest test that selects Claude Code and asserts the API calls receive `agentKind: 'claude-code'`.
- [x] Run `pnpm --dir apps/desktop test -- App.test.tsx`; expect failure because no Agent selector exists.
- [x] Implement a shared selector and filter state at App level; pass it to ProjectsView and SessionsView.
- [x] Translate selector labels and empty states in both English and Chinese.
- [x] Run focused Vitest and `pnpm --dir apps/desktop exec tsc -b --pretty false`.
- [x] Commit `feat: add agent-scoped project and session browsing`.

### Task 3: Agent-specific bundle manifest and project-file collection

**Files:**
- Modify: `crates/bundle/src/lib.rs`
- Create: `crates/bundle/tests/agent_project_bundle.rs`
- Modify: `crates/index/src/query.rs`

**Interfaces:**
- Extend `BundleManifest` with `agent`, `source_root`, `workspace_count`, and `file_count`.
- Add `BundleExportSelection { agent_kind, workspace_ids, include_files, max_file_bytes }`.
- Add `write_selected_sessions(path, sessions, workspaces, selection, scanner)`.
- Add `Bundle::inspect()` returning manifest counts and conflict-safe entry metadata.

- [x] Write failing fixture test for a Codex session plus workspace files; assert the bundle includes only selected relative files, excludes `auth.json`, and records hashes.
- [x] Run `cargo test -p agentark-bundle --test agent_project_bundle --offline`; verify it fails before implementation.
- [x] Implement regular-file containment checks, reparse/symlink rejection, file-size limits, secret redaction, and manifest version `1.1`.
- [x] Preserve existing `.ahbundle` v1 reader compatibility and return a typed unsupported-version error for unknown versions.
- [x] Run focused bundle tests, path-policy tests, and secret-canary checks.
- [x] Commit `feat: export agent-scoped sessions and project files`.

### Task 4: Transactional import preview and restore

**Files:**
- Modify: `crates/bundle/src/lib.rs`
- Modify: `crates/index/src/write.rs`
- Create: `crates/bundle/tests/import_restore.rs`
- Modify: `apps/desktop/src-tauri/src/state.rs`
- Modify: `apps/desktop/src-tauri/src/commands.rs`

**Interfaces:**
- Add `BundleImportPreview { agent_kind, sessions, projects, files, conflicts, verified }`.
- Add `BundleImportMode::{NewWorkspace, Merge}`.
- Add `IndexDb::restore_bundle(preview, mode) -> Result<RestoreReport, IndexError>`.

- [x] Write failing restore tests for new-workspace import, duplicate import idempotency, file hash mismatch, and interrupted transaction rollback.
- [x] Run the focused test; confirm failures are caused by missing preview/restore behavior.
- [x] Implement inspect-before-write, checkpoint creation, one SQLCipher transaction, CAS writes, file hash verification, and rollback on mismatch.
- [x] Record `bundle.import.started`, `bundle.import.completed`, and `bundle.import.rolled_back` audit events with only sanitized metadata.
- [x] Run focused tests plus `cargo test --workspace --all-features --offline`.
- [x] Commit `feat: restore agent bundles transactionally`.

### Task 5: Desktop export/import workflow

**Files:**
- Modify: `apps/desktop/src/views/StatusView.tsx`
- Create: `apps/desktop/src/views/TransferView.tsx`
- Modify: `apps/desktop/src/App.tsx`
- Modify: `apps/desktop/src/api.ts`
- Modify: `apps/desktop/src/i18n.tsx`
- Modify: `apps/desktop/src/styles.css`
- Test: `apps/desktop/src/App.test.tsx`

**Interfaces:**
- Tauri commands: `bundle_export_preview`, `bundle_export`, `bundle_import_preview`, `bundle_import`.
- UI state: `TransferStep = 'select' | 'preview' | 'complete' | 'error'`.

- [x] Add failing Vitest tests for both primary buttons, Agent selection, preview rendering, and confirmation gating.
- [x] Run focused tests and verify RED.
- [x] Implement TransferView with separate “导出会话历史” and “导入会话历史” buttons, Agent/project selectors, preview summary, conflict list, and progress/error states.
- [x] Keep Status backup controls backwards-compatible or link them into TransferView.
- [x] Run Vitest, TypeScript build, and Tauri command unit tests.
- [x] Commit `feat: add desktop session history transfer workflow`.

### Task 6: CLI parity and documentation

**Files:**
- Modify: `cli/src/args.rs`
- Modify: `cli/src/main.rs`
- Modify: `cli/src/runtime.rs`
- Modify: `cli/tests/cli_json.rs`
- Modify: `docs/implementation-status.md`

**Interfaces:**
- Add `bundle export --agent <agent> --project <workspace-id> --include-files <path>`.
- Add `bundle inspect <path>` and `bundle restore <path> --mode new-workspace|merge`.

- [x] Add failing JSON envelope tests for Agent-specific export and inspect preview.
- [x] Implement commands with the same Rust bundle/index APIs as Tauri.
- [x] Verify error envelopes do not expose source contents or credentials.
- [x] Run CLI tests and docs checks.
- [x] Commit `feat: add CLI session history transfer commands`.

### Task 7: Release verification

**Files:**
- Modify: `.github/workflows/release.yml`
- Modify: `compat/matrix.toml`
- Modify: `docs/implementation-status.md`

- [x] Run `cargo fmt --all -- --check`.
- [x] Run `cargo clippy --workspace --all-targets --offline -- -D warnings`.
- [x] Run `cargo test --workspace --all-features --offline`.
- [x] Run `pnpm --dir apps/desktop test` and `pnpm --dir apps/desktop build`.
- [x] Build MSI/NSIS, calculate SHA-256, install with administrator elevation, verify registry version and responsive launch.
- [x] Commit release notes only after all commands exit 0.
