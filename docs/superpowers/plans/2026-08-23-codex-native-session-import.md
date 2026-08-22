# Codex Native Session Import Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task with review checkpoints. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore Codex sessions from an AgentArk `.ahbundle` into target `CODEX_HOME` as visible, resumable Codex client threads.

**Architecture:** Keep the existing AgentArk SQLCipher restore as the authoritative archive and add a version-gated Codex native writer in the Codex adapter. The writer materializes canonical visible messages into validated Codex rollout JSONL, publishes it atomically into `CODEX_HOME/sessions`, and verifies visibility through the local App Server before reporting success. The UI performs native restore only for Codex, preserves the existing non-Codex flow, and explicitly reports the required Codex restart.

**Tech Stack:** Rust 2024, Tauri 2, React/TypeScript, Codex App Server JSON-RPC, JSONL rollout files, SQLCipher AgentArk index, Vitest, Cargo tests.

**Spec:** `docs/superpowers/specs/2026-08-23-codex-native-session-import-design.md`

## Global Constraints

- Support and verify the installed Codex CLI `0.146.0`; unknown versions fail closed to AgentArk-only restore.
- Never write Codex while a Codex client process is running; never kill the user process automatically.
- Use a timestamped `CODEX_HOME` backup, temporary files, `sync_all`, atomic rename, conflict detection, and rollback.
- Never migrate credentials, hidden reasoning, raw secrets, or unverifiable tool outputs.
- Keep vendor source scanning read-only; only the explicit Codex native-restore action may write target `CODEX_HOME`.
- Preserve existing `.ahbundle` v1/v1.1 compatibility and existing AgentArk restore behavior.
- Every native restore result is sanitized and audited without message bodies or credential values.

---

### Task 1: Define Codex native rollout materialization and fixture coverage

**Files:**
- Create: `crates/adapters/codex/src/native_import.rs`
- Modify: `crates/adapters/codex/src/lib.rs`
- Test: `crates/adapters/codex/tests/native_import.rs`

**Interfaces:**
- Produces `NativeImportOptions`, `NativeImportReport`, `NativeThreadMapping`, `NativeImportError`.
- Produces `build_rollout_lines(session: &CanonicalSession, target_thread_id: &str, cwd: &Path) -> Result<Vec<Vec<u8>>, NativeImportError>`.
- Produces `write_rollout_atomic(path: &Path, lines: &[Vec<u8>]) -> Result<Sha256Digest, NativeImportError>`.

- [ ] **Step 1: Write failing fixture tests for visible turns and redaction boundaries.**

The test file must define these concrete helpers before the tests: both return a
`CanonicalSession` with one workspace, a Codex `source_kind`, one user message,
one assistant message, stable UUIDs, and empty attachments; the second helper
also places a canary secret in `raw_extra` and a hidden-reasoning canary in a
non-visible field so the writer can prove they are excluded.

```rust
#[test]
fn materializes_user_and_assistant_turn_events() {
    let session = fixture_session_with_user_and_assistant_messages();
    let lines = build_rollout_lines(&session, "01native-thread", Path::new(r"C:\\restore\\project")).unwrap();
    let values: Vec<Value> = lines.iter().map(|line| serde_json::from_slice(line).unwrap()).collect();
    assert!(values.iter().any(|value| value["type"] == "session_meta"));
    assert!(values.iter().any(|value| value["type"] == "event_msg" && value["payload"]["type"] == "user_message"));
    assert!(values.iter().any(|value| value["type"] == "event_msg" && value["payload"]["type"] == "agent_message"));
    assert!(values.iter().any(|value| value["type"] == "event_msg" && value["payload"]["type"] == "task_complete"));
}

#[test]
fn materializer_excludes_credentials_and_hidden_reasoning() {
    let session = fixture_session_with_secret_and_reasoning_metadata();
    let bytes = build_rollout_lines(&session, "01native-thread", Path::new(r"C:\\restore\\project")).unwrap().concat();
    let text = String::from_utf8(bytes).unwrap();
    assert!(!text.contains("fixture-secret-value"));
    assert!(!text.contains("hidden-reasoning-value"));
}
```

- [ ] **Step 2: Run the focused test to verify the expected RED state.**

Run: `cargo test -p agentark-adapter-codex --test native_import --offline`

Expected: compile/test failure because the native materializer API does not exist.

- [ ] **Step 3: Implement the minimal deterministic rollout builder.**

Implement these records in order for each session:

```rust
session_meta
event_msg.task_started
turn_context
response_item.message(role=user)
event_msg.user_message
response_item.message(role=assistant)
event_msg.agent_message
event_msg.task_complete
```

Use a new UUIDv7 target thread ID, the restored workspace as `cwd`, sanitized
visible message text, and `source_session_id` only in the AgentArk mapping.
Count unsupported attachments/tool details as `loss_count`; never serialize
`raw_extra` values that match credential or hidden-reasoning rules.

- [ ] **Step 4: Add atomic write and idempotency helpers.**

Write to `.<filename>.<uuid>.tmp`, call `sync_all`, rename into the target
directory, and return the SHA-256 of the complete file. If the destination
already exists, return `Skipped` for an equal hash and `Conflict` for a
different hash without overwriting it.

- [ ] **Step 5: Run the focused tests to verify GREEN.**

Run: `cargo test -p agentark-adapter-codex --test native_import --offline`

Expected: all native materializer and hash/idempotency tests pass.

- [ ] **Step 6: Commit the self-contained adapter fixture work.**

```powershell
git add crates/adapters/codex/src/native_import.rs crates/adapters/codex/src/lib.rs crates/adapters/codex/tests/native_import.rs
git commit -m "feat: materialize codex native rollout history"
```

### Task 2: Add Codex capability probing, backup, process guard, and App Server verification

**Files:**
- Modify: `crates/adapters/codex/src/native_import.rs`
- Modify: `crates/adapters/codex/src/process.rs`
- Modify: `crates/adapters/codex/src/probe.rs`
- Test: `crates/adapters/codex/tests/native_import.rs`
- Test: `crates/adapters/codex/tests/probe.rs`

**Interfaces:**
- `pub fn probe_native_import(executable: &Path) -> Result<NativeCapability, NativeImportError>`.
- `pub fn ensure_codex_not_running() -> Result<(), NativeImportError>` on Windows.
- `pub fn backup_codex_targets(codex_home: &Path, backup_root: &Path, files: &[PathBuf]) -> Result<PathBuf, NativeImportError>`.
- `pub fn verify_rollout_with_app_server(executable: &Path, codex_home: &Path, rollout: &Path, expected: &NativeThreadExpectation) -> Result<(), NativeImportError>`.

- [ ] **Step 1: Write failing tests for version gating and process-output parsing.**

Add `verify_thread_listing(value: &Value, expected: &NativeThreadExpectation)`
to the native module. It must locate `result.data[]` by target thread ID,
require a non-empty preview and cwd, and return `NativeImportError::Verification`
when the thread or visible-turn count is missing. `expected_thread(id)` is a
test-only constructor with the same ID and expected visible-text SHA-256.

```rust
#[test]
fn unknown_codex_version_disables_native_writer() {
    let report = CodexProbe::from_outputs("codex-cli 0.999.0\n", "Usage: codex app-server --listen stdio://\n").unwrap();
    assert_eq!(report.native_import, NativeCapability::Unsupported);
}

#[test]
fn rollout_verification_requires_visible_turns() {
    let result = verify_thread_listing(&json!({"data": []}), &expected_thread("01native"));
    assert!(matches!(result, Err(NativeImportError::Verification(_))));
}
```

- [ ] **Step 2: Run focused tests and confirm RED.**

Run: `cargo test -p agentark-adapter-codex --test native_import --test probe --offline`

Expected: failures for the missing native capability and verification APIs.

- [ ] **Step 3: Implement exact-version capability gating.**

Allow native writing only when the executable version equals the supported
Codex version and the App Server probe exposes `thread/resume`/rollout path
support. Return a sanitized unsupported-capability error for every other
version or protocol shape.

- [ ] **Step 4: Implement the Windows process guard and backup manifest.**

Use `tasklist.exe` output parsing in a small pure helper, matching Codex client
image names only. Before writing, copy every affected rollout and Codex state
database sidecar into `CODEX_HOME\agentark-backups\<timestamp>\`, write a
manifest of paths/hashes, and never delete the original files.

- [ ] **Step 5: Implement App Server verification.**

Use the existing line-delimited JSON transport to send `initialize`,
`initialized`, `thread/resume` with the staged rollout path, `thread/read` with
turns, and `thread/list`. Require matching target ID/title/cwd, at least one
visible user/assistant turn, and the expected visible message hash before
publishing the rollout.

- [ ] **Step 6: Run focused tests GREEN and commit.**

Run: `cargo test -p agentark-adapter-codex --test native_import --test probe --offline`

```powershell
git add crates/adapters/codex/src/native_import.rs crates/adapters/codex/src/process.rs crates/adapters/codex/src/probe.rs crates/adapters/codex/tests/native_import.rs crates/adapters/codex/tests/probe.rs
git commit -m "feat: verify codex native import capability"
```

### Task 3: Integrate native restore into desktop state and Tauri commands

**Files:**
- Modify: `apps/desktop/src-tauri/src/state.rs`
- Modify: `apps/desktop/src-tauri/src/commands.rs`
- Modify: `apps/desktop/src-tauri/src/lib.rs`
- Modify: `apps/desktop/src/api.ts`
- Test: `apps/desktop/src-tauri/src/state.rs` tests or a new `apps/desktop/src-tauri/tests/native_restore.rs`

**Interfaces:**
- Extend `BundleReport` with `native_target`, `native_imported_count`, `native_skipped_count`, `native_conflict_count`, `native_backup_path`, `native_restart_required`.
- Add `AppState::bundle_restore(path: PathBuf, native_target: bool)` with native execution only when the manifest Agent is Codex.
- Add Tauri command `bundle_restore` argument `native_target: bool` and register it in the handler.
- Add `api.bundleRestore(path, nativeTarget)` matching the Rust camelCase payload.

- [ ] **Step 1: Write failing state tests for native and archive-only branches.**

The test harness creates a temporary AgentArk data root, writes a verified
fixture bundle with `write_selected_sessions`, and injects a fake native writer
result through the adapter boundary. `restore_fixture_bundle_with_native_target`
must return a Codex manifest and one selected session; `restore_fixture_bundle_for_claude`
must return a Claude manifest and one selected session. Neither helper may touch
the user's real data directory.

```rust
#[test]
fn restore_report_marks_codex_native_mapping_and_restart() {
    let report = restore_fixture_bundle_with_native_target(true).unwrap();
    assert_eq!(report.native_imported_count, 1);
    assert!(report.native_restart_required);
    assert!(report.native_backup_path.is_some());
}

#[test]
fn non_codex_restore_never_calls_native_writer() {
    let report = restore_fixture_bundle_for_claude(true).unwrap();
    assert_eq!(report.native_imported_count, 0);
    assert!(!report.native_restart_required);
}
```

- [ ] **Step 2: Run the desktop Rust tests and confirm RED.**

Run: `cargo test -p agentark-desktop --offline native_restore`

Expected: failures because the report fields and native branch are absent.

- [ ] **Step 3: Implement archive-first then native restore sequencing.**

Keep the existing verified bundle read, conflict checks, project restore, and
AgentArk `restore_sessions` transaction. When `native_target` is true and the
bundle manifest is Codex, call the adapter native writer with the restored
workspace mapping. Record separate `bundle.native_restore.started`,
`bundle.native_restore.completed`, and `bundle.native_restore.failed` audit
events with counts, hashes, and basenames only.

- [ ] **Step 4: Implement sanitized report mapping and command/API plumbing.**

Return native mappings/counts and `native_restart_required=true` only after App
Server verification passes. Native failure must leave the verified AgentArk
archive available while reporting the failure explicitly.

- [ ] **Step 5: Run desktop Rust tests and full command compilation GREEN.**

Run: `cargo test -p agentark-desktop --offline native_restore`
Run: `cargo check -p agentark-desktop --offline`

- [ ] **Step 6: Commit the state and command integration.**

```powershell
git add apps/desktop/src-tauri/src/state.rs apps/desktop/src-tauri/src/commands.rs apps/desktop/src-tauri/src/lib.rs apps/desktop/src/api.ts apps/desktop/src-tauri/tests/native_restore.rs
git commit -m "feat: restore codex sessions into native home"
```

### Task 4: Add the Codex native restore mode to the desktop transfer UI

**Files:**
- Modify: `apps/desktop/src/views/TransferView.tsx`
- Modify: `apps/desktop/src/i18n.tsx`
- Modify: `apps/desktop/src/App.test.tsx`
- Modify: `apps/desktop/src/styles.css`

**Interfaces:**
- Codex preview exposes a checked `restoreNativeCodex` option; non-Codex previews hide it.
- Restore calls `api.bundleRestore(path, restoreNativeCodex)`.
- Completion status displays native imported/skipped/conflict counts, backup path basename, and restart-required text.

- [ ] **Step 1: Write failing Vitest tests for the Codex native option and report.**

The test-only `openTransferAndVerifyCodexBundle()` helper must click the Transfer
tab, mock `bundle_verify` with `{agent: 'codex', sessionCount: 1, fileCount: 0,
conflictCount: 0}`, and wait for the preview status before asserting the native
checkbox and restore invocation.

```tsx
test('codex restore enables native client import by default', async () => {
  render(<LocaleProvider><App /></LocaleProvider>);
  await openTransferAndVerifyCodexBundle();
  expect(screen.getByRole('checkbox', { name: 'Restore into Codex client' })).toBeChecked();
  fireEvent.click(screen.getByRole('button', { name: 'Restore imported history' }));
  await waitFor(() => expect(invoke).toHaveBeenCalledWith('bundle_restore', { path: expect.any(String), nativeTarget: true }));
});
```

- [ ] **Step 2: Run `pnpm --dir apps/desktop test -- App.test.tsx` and confirm RED.**

- [ ] **Step 3: Implement the checkbox, translated labels, native report, and restart notice.**

The existing two primary buttons remain unchanged. The native option appears
only for Codex and defaults on; cancellation and archive-only non-Codex imports
retain current behavior. Disable restore while native work is active and never
hide a native failure behind the AgentArk success message.

- [ ] **Step 4: Run frontend tests and TypeScript build GREEN.**

Run: `pnpm --dir apps/desktop test`
Run: `pnpm --dir apps/desktop build`

- [ ] **Step 5: Commit the UI workflow.**

```powershell
git add apps/desktop/src/views/TransferView.tsx apps/desktop/src/i18n.tsx apps/desktop/src/App.test.tsx apps/desktop/src/styles.css
git commit -m "feat: expose codex native restore in transfer ui"
```

### Task 5: Validate with an isolated real Codex home and document the contract

**Files:**
- Create: `crates/adapters/codex/tests/native_import_app_server.rs` (ignored unless `AGENTARK_CODEX_BIN` is set)
- Modify: `docs/implementation-status.md`
- Modify: `AgentArk.md`
- Modify: `apps/desktop/package.json`
- Modify: `apps/desktop/src-tauri/tauri.conf.json`

**Interfaces:**
- The ignored integration test creates a temporary `CODEX_HOME`, materializes a
  two-turn fixture, launches the installed Codex executable, and asserts
  `thread/list`/`thread/read` expose the native thread after restart.

- [ ] **Step 1: Write the ignored real-Codex integration test.**

```rust
#[test]
#[ignore = "requires a locally installed compatible Codex executable"]
fn copied_native_rollout_is_visible_after_app_server_restart() {
    let report = run_isolated_native_round_trip().unwrap();
    assert_eq!(report.visible_threads, 1);
    assert_eq!(report.visible_turns, 2);
}
```

- [ ] **Step 2: Run the test with the current executable and capture evidence.**

Run: `$env:AGENTARK_CODEX_BIN='C:\\Users\\33384\\AppData\\Roaming\\npm\\codex.opencodex-real.cmd'; cargo test -p agentark-adapter-codex --test native_import_app_server --offline -- --ignored --nocapture`

Expected: a temporary home is used; the real user `CODEX_HOME` is never modified.

- [ ] **Step 3: Update project contract and release version to 0.5.0.**

Document that Codex native restore is version-gated, creates new thread IDs,
requires Codex closed during import and restarted afterward, excludes
credentials/hidden reasoning, and falls back to AgentArk-only restore when the
probe or verification fails.

- [ ] **Step 4: Run the full release gate.**

Run: `cargo fmt --all -- --check`
Run: `cargo clippy --workspace --all-targets --offline -- -D warnings`
Run: `cargo test --workspace --all-features --offline`
Run: `pnpm --dir apps/desktop test`
Run: `pnpm --dir apps/desktop build`
Run: `pnpm --dir apps/desktop tauri build`

- [ ] **Step 5: Install and verify the new Windows package.**

Copy MSI/NSIS artifacts to `dist`, calculate SHA-256, install with elevated
`msiexec`, verify registry version `0.5.0`, launch AgentArk, and confirm the
window is responsive. Do not run native restore against the user's live
`CODEX_HOME` as part of packaging verification.

- [ ] **Step 6: Commit the release documentation and version.**

```powershell
git add crates/adapters/codex/tests/native_import_app_server.rs docs/implementation-status.md AgentArk.md apps/desktop/package.json apps/desktop/src-tauri/tauri.conf.json
git commit -m "feat: release codex native session migration"
```
