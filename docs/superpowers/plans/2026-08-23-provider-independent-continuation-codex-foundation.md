# Provider-Independent Codex Continuation Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Automatically retain a compatible Codex native session ID or create a new Codex continuation under the target device's default provider/model, without exporting credentials or asking the user to choose a mode.

**Architecture:** Add a provider-neutral recovery decision model, durable restore mappings, and a Codex executor with two verified paths. The executor first attempts same-provider native identity restore; when that cannot be verified, it uses the Codex App Server `thread/fork` path with the target provider/model override to create a new native thread that carries visible history. Agents without a verified continuation writer remain archive-only behind the same decision interface.

**Tech Stack:** Rust 2024, SQLCipher/rusqlite, Tauri 2, React/TypeScript, Codex App Server JSON-RPC, JSONL rollouts, Vitest, Cargo tests.

**Spec:** `docs/superpowers/specs/2026-08-23-provider-independent-continuation-design.md`

## Scope Boundary

This plan delivers the generic decision/mapping foundation and a fully verified
Codex implementation. Claude Code, Hermes, OpenClaw, OpenCode, and Grok Build
get the same archive-only reporting contract in this tranche; each native
continuation writer requires its own isolated protocol spike and follow-on plan
before it can be enabled. Do not write guessed vendor records.

## Global Constraints

- The user invokes one restore action; no individual session exposes a mode picker.
- Same-provider, verifiable Codex sessions retain their original native ID.
- Provider mismatch or unavailable source configuration falls back to a new Codex continuation using the target Codex default provider/model.
- Never export, log, compare, or copy provider credentials, custom endpoint secrets, or account identifiers.
- Require Codex closed before every native write; never terminate its process automatically.
- Native identity and continuation writes use separate temporary files, target backups, conflict checks, App Server verification, and rollback.
- A failed vendor-native recovery never rolls back the verified AgentArk archive restore.
- `thread/inject_items` is not a continuation implementation because it does not create visible persisted turns.
- Only advertise a continuation outcome after `thread/list`, `thread/read`, and a target-provider subsequent-turn integration check succeed in an isolated `CODEX_HOME`.
- Preserve `.ahbundle` v1/v1.1 read compatibility; introduce additive metadata only.

---

### Task 1: Add provider-neutral recovery decisions and unit coverage

**Files:**
- Create: `crates/migration/src/recovery.rs`
- Modify: `crates/migration/src/lib.rs`
- Test: `crates/migration/tests/recovery.rs`

**Interfaces:**

```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderIdentity {
    pub provider: Option<String>,
    pub model: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RestoreOutcome {
    NativeIdentity,
    Continuation,
    ArchiveOnly,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetRecoveryCapabilities {
    pub native_identity_verified: bool,
    pub continuation_writer_verified: bool,
    pub target_default: Option<ProviderIdentity>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryDecision {
    pub outcome: RestoreOutcome,
    pub source_provider: ProviderIdentity,
    pub target_provider: Option<ProviderIdentity>,
    pub reason_code: String,
}

pub fn decide_recovery(
    source: ProviderIdentity,
    capabilities: TargetRecoveryCapabilities,
) -> RecoveryDecision;
```

`ProviderIdentity` contains only labels already present in a canonical session;
callers must normalize blank strings to `None` before constructing it.

- [ ] **Step 1: Write failing decision tests.**

Create `crates/migration/tests/recovery.rs` with these exact cases:

```rust
#[test]
fn same_provider_with_verified_identity_keeps_native_id() {
    let decision = decide_recovery(
        ProviderIdentity { provider: Some("openai".into()), model: Some("gpt-5".into()) },
        TargetRecoveryCapabilities {
            native_identity_verified: true,
            continuation_writer_verified: true,
            target_default: Some(ProviderIdentity { provider: Some("openai".into()), model: Some("gpt-5".into()) }),
        },
    );
    assert_eq!(decision.outcome, RestoreOutcome::NativeIdentity);
    assert_eq!(decision.reason_code, "native-identity-verified");
}

#[test]
fn unavailable_source_provider_uses_target_default_continuation() {
    let decision = decide_recovery(
        ProviderIdentity { provider: Some("custom".into()), model: Some("claude".into()) },
        TargetRecoveryCapabilities {
            native_identity_verified: false,
            continuation_writer_verified: true,
            target_default: Some(ProviderIdentity { provider: Some("openai".into()), model: Some("gpt-5".into()) }),
        },
    );
    assert_eq!(decision.outcome, RestoreOutcome::Continuation);
    assert_eq!(decision.target_provider.unwrap().provider.as_deref(), Some("openai"));
    assert_eq!(decision.reason_code, "target-default-continuation");
}

#[test]
fn unavailable_writer_stays_archive_only() {
    let decision = decide_recovery(
        ProviderIdentity { provider: None, model: None },
        TargetRecoveryCapabilities {
            native_identity_verified: false,
            continuation_writer_verified: false,
            target_default: None,
        },
    );
    assert_eq!(decision.outcome, RestoreOutcome::ArchiveOnly);
    assert_eq!(decision.reason_code, "continuation-writer-unavailable");
}
```

- [ ] **Step 2: Run the focused test and verify RED.**

Run:

```powershell
cargo test -p agentark-migration --test recovery --offline
```

Expected: compilation failure because the recovery module and exported types do not exist.

- [ ] **Step 3: Implement the pure decision module.**

Create `recovery.rs`; make the decision order deterministic:

```rust
pub fn decide_recovery(
    source: ProviderIdentity,
    capabilities: TargetRecoveryCapabilities,
) -> RecoveryDecision {
    if capabilities.native_identity_verified {
        return RecoveryDecision {
            outcome: RestoreOutcome::NativeIdentity,
            source_provider: source,
            target_provider: capabilities.target_default,
            reason_code: "native-identity-verified".into(),
        };
    }
    if capabilities.continuation_writer_verified {
        if let Some(target_provider) = capabilities.target_default {
            return RecoveryDecision {
                outcome: RestoreOutcome::Continuation,
                source_provider: source,
                target_provider: Some(target_provider),
                reason_code: "target-default-continuation".into(),
            };
        }
    }
    RecoveryDecision {
        outcome: RestoreOutcome::ArchiveOnly,
        source_provider: source,
        target_provider: None,
        reason_code: "continuation-writer-unavailable".into(),
    }
}
```

Export the module types from `crates/migration/src/lib.rs`. Do not add a
dependency on a vendor adapter to this crate.

- [ ] **Step 4: Run focused tests and formatting.**

Run:

```powershell
cargo fmt --all -- --check
cargo test -p agentark-migration --test recovery --offline
```

Expected: all three decision tests pass.

- [ ] **Step 5: Commit the self-contained recovery domain.**

```powershell
git add crates/migration/src/recovery.rs crates/migration/src/lib.rs crates/migration/tests/recovery.rs
git commit -m "feat: add provider-independent recovery decisions"
```

### Task 2: Store restore mappings with a forward-only encrypted-index migration

**Files:**
- Create: `crates/index/migrations/0002_restore_mappings.sql`
- Modify: `crates/index/src/database.rs`
- Create: `crates/index/src/recovery.rs`
- Modify: `crates/index/src/lib.rs`
- Test: `crates/index/tests/restore_mappings.rs`

**Interfaces:**

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreMapping {
    pub source_session_id: Uuid,
    pub target_agent: AgentKind,
    pub outcome: agentark_migration::RestoreOutcome,
    pub source_native_id: Option<String>,
    pub target_native_id: Option<String>,
    pub source_provider: Option<String>,
    pub target_provider: Option<String>,
    pub source_hash: Sha256Digest,
    pub target_hash: Option<Sha256Digest>,
    pub reason_code: String,
    pub created_at: String,
}

impl IndexDb {
    pub fn record_restore_mapping(&mut self, mapping: &RestoreMapping) -> Result<(), IndexError>;
    pub fn restore_mappings_for(&self, source_session_id: Uuid) -> Result<Vec<RestoreMapping>, IndexError>;
}
```

- [ ] **Step 1: Write failing persistence tests.**

Create a temporary SQLCipher index in `restore_mappings.rs`; write a
continuation mapping then reopen the database and assert both source and target
native IDs, outcome, target provider, hashes, and reason code survive.

```rust
#[test]
fn records_and_reopens_continuation_mapping() {
    let mut index = open_temp_index();
    let mapping = continuation_mapping();
    index.record_restore_mapping(&mapping).unwrap();
    drop(index);
    let index = reopen_temp_index();
    assert_eq!(index.restore_mappings_for(mapping.source_session_id).unwrap(), vec![mapping]);
}
```

Add a second test that opens a database created at schema version 1 and asserts
the migration reaches version 2 without losing a previously stored session.

- [ ] **Step 2: Run focused tests and verify RED.**

Run:

```powershell
cargo test -p agentark-index --test restore_mappings --offline
```

Expected: compilation failure because the migration runner and mapping APIs do not exist.

- [ ] **Step 3: Implement schema migration version 2.**

Create `0002_restore_mappings.sql`:

```sql
CREATE TABLE session_restore_mappings (
  id TEXT PRIMARY KEY,
  source_session_id TEXT NOT NULL REFERENCES sessions(id),
  target_agent TEXT NOT NULL,
  outcome TEXT NOT NULL CHECK(outcome IN ('nativeIdentity','continuation','archiveOnly')),
  source_native_id TEXT,
  target_native_id TEXT,
  source_provider TEXT,
  target_provider TEXT,
  source_hash TEXT NOT NULL,
  target_hash TEXT,
  reason_code TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(source_session_id, target_agent, outcome, target_native_id)
);
CREATE INDEX idx_restore_mappings_source ON session_restore_mappings(source_session_id, created_at DESC);
UPDATE schema_meta SET value = '2' WHERE key = 'schema_version';
```

Replace the single `schema_version == "1"` branch in `IndexDb::open` with a
monotonic migration dispatcher: new databases run `0001_init.sql` then
`0002_restore_mappings.sql`; existing version-1 databases run only migration
2; any version above 2 or an invalid value returns `UnsupportedStorageBuild`.

Implement the mapping APIs in `recovery.rs`, serializing `AgentKind` and
`RestoreOutcome` with `serde_json`, parsing UUID and hash values strictly, and
using parameterized SQL only.

- [ ] **Step 4: Run focused index tests.**

Run:

```powershell
cargo test -p agentark-index --test restore_mappings --offline
cargo test -p agentark-index --test encrypted_index --offline
```

Expected: mapping persistence and existing encrypted-index tests pass.

- [ ] **Step 5: Commit the index migration.**

```powershell
git add crates/index/migrations/0002_restore_mappings.sql crates/index/src/database.rs crates/index/src/recovery.rs crates/index/src/lib.rs crates/index/tests/restore_mappings.rs crates/index/Cargo.toml Cargo.lock
git commit -m "feat: persist native and continuation restore mappings"
```

### Task 3: Add a verified Codex `thread/fork` continuation primitive

**Files:**
- Modify: `crates/adapters/codex/src/native_import.rs`
- Modify: `crates/adapters/codex/src/lib.rs`
- Test: `crates/adapters/codex/tests/native_import.rs`
- Create: `crates/adapters/codex/tests/provider_continuation_app_server.rs`

**Interfaces:**

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodexContinuationRequest {
    pub source_rollout: PathBuf,
    pub source_thread_id: String,
    pub target_cwd: PathBuf,
    pub target_provider: Option<String>,
    pub target_model: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodexContinuationReport {
    pub source_thread_id: String,
    pub target_thread_id: String,
    pub rollout_path: PathBuf,
    pub model_provider: String,
    pub model: String,
    pub visible_turns: usize,
}

pub fn fork_rollout_with_target_provider(
    executable: &Path,
    codex_home: &Path,
    request: &CodexContinuationRequest,
) -> Result<CodexContinuationReport, NativeImportError>;
```

- [ ] **Step 1: Write a scripted transport test for the fork request.**

Extend `native_import.rs` tests with a `ScriptedTransport` that returns
`initialize`, `thread/fork`, `thread/list`, and `thread/read` replies. Assert
the actual JSON-RPC request has exactly these essential fields:

```rust
assert_eq!(request["method"], "thread/fork");
assert_eq!(request["params"]["path"], source_rollout.to_string_lossy().as_ref());
assert_eq!(request["params"]["modelProvider"], "openai");
assert_eq!(request["params"]["model"], "gpt-5");
assert_eq!(request["params"]["cwd"], target_cwd.to_string_lossy().as_ref());
assert_ne!(fork_response["result"]["thread"]["id"], source_thread_id);
```

The test must also assert neither an API key nor an endpoint field appears in
the serialized request.

- [ ] **Step 2: Run the focused unit test and verify RED.**

Run:

```powershell
cargo test -p agentark-adapter-codex --test native_import fork_rollout --offline
```

Expected: failure because `CodexContinuationRequest` and the fork helper do not exist.

- [ ] **Step 3: Implement fork plus non-mutating visibility verification.**

Use the existing `ProcessTransport` and `NativeAppServerClient`. First query
`modelProvider/capabilities/read` and `model/list`; record only the selected
provider/model labels. The executor receives the selected target defaults from
that probe rather than deriving a default from catalog ordering. After the
initialize handshake, construct the fork request from the typed input:

```rust
let mut params = json!({
    "threadId": request.source_thread_id,
    "path": request.source_rollout.to_string_lossy(),
    "cwd": request.target_cwd.to_string_lossy(),
    "threadSource": "user",
    "ephemeral": false,
});
if let Some(provider) = &request.target_provider {
    params["modelProvider"] = Value::String(provider.clone());
}
if let Some(model) = &request.target_model {
    params["model"] = Value::String(model.clone());
}
let response = client.request("thread/fork", params)?;
```

Require a nonempty target ID different from `source_thread_id`, an absolute
rollout path under `CODEX_HOME/sessions`, and target provider/model values in
the response. Then verify that target ID through `thread/list` (active then
archived fallback) and `thread/read(includeTurns=true)`. Return only hashes,
counts, IDs, labels, and paths; never return message text.

- [ ] **Step 4: Add isolated real-Codex continuation tests.**

Create `provider_continuation_app_server.rs` with two ignored tests that use
temporary `CODEX_HOME` only:

```rust
#[test]
#[ignore = "requires compatible Codex, source rollout, and target provider"]
fn fork_rebases_visible_history_to_target_provider() {
    let report = fork_fixture_with_target_provider("openai", None).unwrap();
    assert_ne!(report.source_thread_id, report.target_thread_id);
    assert!(report.visible_turns > 0);
    assert_eq!(report.model_provider, "openai");
}

#[test]
#[ignore = "starts a billed target-provider turn only when explicitly enabled"]
fn forked_thread_accepts_a_target_provider_turn() {
    if std::env::var_os("AGENTARK_RUN_PROVIDER_CONTINUATION").is_none() {
        return;
    }
    let report = fork_fixture_with_target_provider("openai", None).unwrap();
    start_and_wait_for_turn(&report.target_thread_id, "Reply only: continuation verified.").unwrap();
    assert_target_turn_is_visible(&report.target_thread_id).unwrap();
}
```

The second test must be opt-in because it may consume the target provider's
model quota. Both tests use a copied fixture; neither may write the user's
live `CODEX_HOME`.

- [ ] **Step 5: Run standard tests and the non-billed isolated test.**

Run:

```powershell
cargo test -p agentark-adapter-codex --test native_import --offline
$env:AGENTARK_CODEX_BIN='C:\Users\33384\AppData\Roaming\npm\codex.opencodex-real.cmd'
$fixture = Get-ChildItem -Path "$env:USERPROFILE\.codex\sessions" -Recurse -Filter 'rollout-*.jsonl' -File |
  Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
if (-not $fixture) { throw 'No Codex rollout fixture is available for the isolated test.' }
$env:AGENTARK_CODEX_ROLLOUT_FIXTURE=$fixture
cargo test -p agentark-adapter-codex --test provider_continuation_app_server --offline -- --ignored --nocapture
```

Expected: the visibility test passes. Do not run the billed subsequent-turn
test unless the user separately authorizes it.

- [ ] **Step 6: Commit the Codex continuation primitive.**

```powershell
git add crates/adapters/codex/src/native_import.rs crates/adapters/codex/src/lib.rs crates/adapters/codex/tests/native_import.rs crates/adapters/codex/tests/provider_continuation_app_server.rs
git commit -m "feat: fork Codex history into target provider"
```

### Task 4: Add bundle recovery metadata while retaining old-bundle compatibility

**Files:**
- Modify: `crates/bundle/src/lib.rs`
- Modify: `crates/bundle/tests/agent_project_bundle.rs`
- Create: `crates/bundle/tests/recovery_manifest.rs`

**Interfaces:**

```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleRecoverySession {
    pub canonical_session_id: Uuid,
    pub source_provider: Option<String>,
    pub source_model: Option<String>,
    pub native_payload_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleRecoveryManifest {
    pub version: String,
    pub sessions: Vec<BundleRecoverySession>,
}

impl Bundle {
    pub fn recovery_manifest(&self) -> Result<Option<BundleRecoveryManifest>, BundleError>;
}
```

- [ ] **Step 1: Write failing bundle tests.**

Create a Codex bundle with one canonical session, `model_provider="custom"`,
`model_name="claude"`, and one native rollout entry. Assert that
`recovery/manifest.json` contains no credential-shaped values, records one
payload, and round-trips through `read_bundle`.

Add a v1.1 fixture bundle with no recovery entry and assert
`recovery_manifest()` returns `Ok(None)`.

- [ ] **Step 2: Run tests and verify RED.**

Run:

```powershell
cargo test -p agentark-bundle --test recovery_manifest --offline
```

Expected: compilation failure because recovery manifest APIs are absent.

- [ ] **Step 3: Implement additive manifest entry.**

Keep the framed container format unchanged. Change `FORMAT_VERSION` to `1.2`,
retain read support for `1.0`, `1.1`, and `1.2`, and write
`recovery/manifest.json` only for new selected-session bundles. Build entries
from the already sanitized canonical sessions and native-entry counts; do not
serialize `raw_extra`, source endpoint strings, or credentials.

- [ ] **Step 4: Run bundle verification.**

Run:

```powershell
cargo test -p agentark-bundle --offline
```

Expected: old and new bundle tests pass; entry hashes continue to verify.

- [ ] **Step 5: Commit the compatible bundle update.**

```powershell
git add crates/bundle/src/lib.rs crates/bundle/tests/agent_project_bundle.rs crates/bundle/tests/recovery_manifest.rs
git commit -m "feat: describe provider recovery in bundles"
```

### Task 5: Replace all-or-nothing Codex restore with per-session automatic fallback

**Files:**
- Modify: `apps/desktop/src-tauri/src/state.rs`
- Modify: `apps/desktop/src-tauri/src/commands.rs`
- Modify: `apps/desktop/src/api.ts`
- Create: `apps/desktop/src-tauri/tests/provider_independent_restore.rs`

**Interfaces:**

Extend `BundleReport` and its camelCase API contract:

```rust
pub struct BundleReport {
    // Existing fields remain.
    pub native_identity_count: u64,
    pub continuation_count: u64,
    pub archive_only_count: u64,
    pub restore_mapping_count: u64,
    pub recovery_error: Option<String>,
}
```

Replace `bundle_restore(path, native_target)` with:

```rust
pub fn bundle_restore(&self, path: PathBuf) -> Result<BundleReport, String>;
```

The command/API no longer accepts `nativeTarget`; AgentArk resolves each
selected session automatically.

- [ ] **Step 1: Write failing state integration tests using temporary roots.**

Add a test-only `AppState::for_data_root(data_root: PathBuf)` constructor under
`#[cfg(test)]` so no test uses the user's local AgentArk or Codex directory.
Use an executor trait injected into state tests:

```rust
trait CodexRecoveryExecutor {
    fn try_native_identity(&self, input: &RecoveryInput) -> Result<NativeRestoreReport, RecoveryError>;
    fn create_continuation(&self, input: &RecoveryInput) -> Result<CodexContinuationReport, RecoveryError>;
}
```

Test these exact outcomes:

```rust
#[test]
fn compatible_payload_retains_original_id() {
    let report = restore_with(fake_executor().native_success()).unwrap();
    assert_eq!(report.native_identity_count, 1);
    assert_eq!(report.continuation_count, 0);
}

#[test]
fn missing_source_provider_falls_back_to_target_default_continuation() {
    let report = restore_with(fake_executor().native_missing_provider().continuation_success()).unwrap();
    assert_eq!(report.native_identity_count, 0);
    assert_eq!(report.continuation_count, 1);
}

#[test]
fn unverified_target_stays_archive_only_without_vendor_write() {
    let executor = fake_executor().native_missing_provider().continuation_unavailable();
    let report = restore_with(&executor).unwrap();
    assert_eq!(report.archive_only_count, 1);
    assert_eq!(executor.vendor_write_count(), 0);
}
```

- [ ] **Step 2: Run the state test and verify RED.**

Run:

```powershell
cargo test -p agentark-desktop --test provider_independent_restore --offline
```

Expected: compilation failure because the automatic resolver, executor boundary, and report fields do not exist.

- [ ] **Step 3: Implement per-session transaction flow.**

Perform existing bundle verification, project restore, and AgentArk index restore
first. For a Codex bundle, partition native payloads by canonical session ID.
For each session:

1. Construct `ProviderIdentity` from the bundle recovery manifest, falling
   back to canonical `model_provider`/`model_name` for old bundles.
2. Attempt native identity restore only when a payload exists. Treat a missing
   target provider or native verification failure as an ordinary fallback
   signal, not as a global failure.
3. Invoke `decide_recovery`; for `Continuation`, call the verified Codex fork
   primitive using the target default provider/model discovered from the
   current App Server response.
4. Persist `RestoreMapping` after every verified outcome.
5. On continuation failure, delete only that continuation's newly written
   target data/checkpoint and persist `ArchiveOnly` with a sanitized reason.

Never allow one session's mismatch to roll back native sessions or
continuations already verified in the same bundle.

- [ ] **Step 4: Implement command/API compatibility behavior.**

Change the Tauri command signature and TypeScript client to omit
`nativeTarget`. If a legacy frontend sends the field, Tauri's serde argument
handling ignores it; do not depend on it. Update all unit-test mocks with the
new report fields.

- [ ] **Step 5: Run state, command, and index tests.**

Run:

```powershell
cargo test -p agentark-desktop --test provider_independent_restore --offline
cargo test -p agentark-index --test restore_mappings --offline
cargo check -p agentark-desktop --offline
```

Expected: all temporary-root cases pass and no live vendor directory is touched.

- [ ] **Step 6: Commit the automatic fallback executor.**

```powershell
git add apps/desktop/src-tauri/src/state.rs apps/desktop/src-tauri/src/commands.rs apps/desktop/src/api.ts apps/desktop/src-tauri/tests/provider_independent_restore.rs
git commit -m "feat: automatically continue unavailable Codex sessions"
```

### Task 6: Make transfer UI mode-free and report the actual outcome

**Files:**
- Modify: `apps/desktop/src/views/TransferView.tsx`
- Modify: `apps/desktop/src/i18n.tsx`
- Modify: `apps/desktop/src/App.test.tsx`
- Modify: `apps/desktop/src/api.ts`

**Interfaces:**

The UI calls exactly:

```ts
api.bundleRestore(path)
```

It no longer renders `restoreNativeCodex` or any per-session Provider/mode
control. Add translation keys:

```text
transfer.nativeIdentitySummary
transfer.continuationSummary
transfer.archiveOnlySummary
transfer.recoveryDiagnostics
```

- [ ] **Step 1: Write failing UI tests.**

Update the existing Codex restore test and add these assertions:

```tsx
expect(screen.queryByRole('checkbox', { name: /restore into codex client/i })).not.toBeInTheDocument();
fireEvent.click(screen.getByRole('button', { name: /restore imported history/i }));
await waitFor(() => expect(invoke).toHaveBeenCalledWith('bundle_restore', { path: expect.any(String) }));
expect(await screen.findByText(/2 original sessions retained/i)).toBeInTheDocument();
expect(screen.getByText(/1 continuation created/i)).toBeInTheDocument();
expect(screen.getByText(/1 available in AgentArk archive only/i)).toBeInTheDocument();
```

- [ ] **Step 2: Run the focused frontend test and verify RED.**

Run:

```powershell
pnpm --dir apps/desktop test -- App.test.tsx
```

Expected: the old checkbox/action payload assertions fail.

- [ ] **Step 3: Implement the outcome summary.**

Remove `restoreNativeCodex` state and the corresponding checkbox. Keep the
native Windows file dialogs and existing project-file selection. On restore,
show a localized one-line summary containing all three counts. Render a
details disclosure only when `recoveryError` is present; it may show reason
codes and backup basenames but not provider credentials or message bodies.

- [ ] **Step 4: Run frontend tests and production build.**

Run:

```powershell
pnpm --dir apps/desktop test
pnpm --dir apps/desktop build
```

Expected: all tests pass and the TypeScript production build succeeds.

- [ ] **Step 5: Commit the user-facing automatic restore flow.**

```powershell
git add apps/desktop/src/views/TransferView.tsx apps/desktop/src/i18n.tsx apps/desktop/src/App.test.tsx apps/desktop/src/api.ts
git commit -m "feat: report automatic native and continuation recovery"
```

### Task 7: Document capability states, validate release behavior, and package 0.6.0

**Files:**
- Modify: `docs/implementation-status.md`
- Modify: `AgentArk.md`
- Modify: `apps/desktop/package.json`
- Modify: `apps/desktop/src-tauri/tauri.conf.json`
- Modify: `crates/adapters/codex/tests/native_import_app_server.rs`
- Modify: `crates/adapters/codex/tests/provider_continuation_app_server.rs`

**Interfaces:**

Document exactly these advertised capability labels:

```text
Codex: native identity restore + provider-independent continuation (only after isolated proof)
Claude Code: archive-only pending verified continuation writer
Hermes: archive-only pending verified continuation writer
OpenClaw: archive-only pending verified continuation writer
OpenCode: archive-only pending verified continuation writer
Grok Build: archive-only pending verified continuation writer
```

- [ ] **Step 1: Add a release-gate assertion for no credential propagation.**

Extend the bundle/continuation test fixtures with a provider-token canary.
Assert the native continuation request, recovery manifest, restore mapping, UI
report, and audit event contain the provider label but not the token value.

- [ ] **Step 2: Run focused security and integration tests.**

Run:

```powershell
cargo test -p agentark-security --test secret_projection --offline
cargo test -p agentark-adapter-codex --test provider_continuation_app_server --offline -- --ignored --nocapture
```

Do not set `AGENTARK_RUN_PROVIDER_CONTINUATION` unless the user explicitly
authorizes a live target-provider test that may consume model quota.

- [ ] **Step 3: Update documentation and release versions.**

Change desktop package/Tauri versions from `0.5.0` to `0.6.0`. Describe the
automatic resolver, retained-ID versus continuation outcome, credential
boundary, restart requirement, and archive-only behavior. Do not claim a
continuation capability for a non-Codex Agent until its writer has passed its
own isolated proof.

- [ ] **Step 4: Run the full release gate.**

Run:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --offline -- -D warnings
cargo test --workspace --all-features --offline
pnpm --dir apps/desktop test
pnpm --dir apps/desktop build
pnpm --dir apps/desktop tauri build
```

Expected: every command exits with code 0. Linker PDB warnings are recorded as
toolchain warnings only; no Rust, TypeScript, or test failure is accepted.

- [ ] **Step 5: Install and inspect the release without importing live history.**

Copy the generated MSI and NSIS EXE into `C:\Users\33384\Documents\AgentArk\dist`
under unique `0.6.0` names. Compute SHA-256, install the MSI, verify the
AgentArk uninstall registry version and installed executable version are
`0.6.0`, then launch the client and verify its process responds. Do not run
native restore against the user's live `CODEX_HOME` during packaging
verification.

- [ ] **Step 6: Commit documentation and release metadata.**

```powershell
git add docs/implementation-status.md AgentArk.md apps/desktop/package.json apps/desktop/src-tauri/tauri.conf.json crates/adapters/codex/tests/native_import_app_server.rs crates/adapters/codex/tests/provider_continuation_app_server.rs
git commit -m "feat: release provider-independent Codex recovery"
```

## Follow-on Agent Plans

After Task 3 proves the Codex continuation contract, create one design/spec and
one execution plan per target writer: Claude Code first, then Hermes,
OpenClaw, OpenCode, and Grok Build. Each plan starts with a throwaway isolated
protocol/storage spike. Until that spike demonstrates native visible history
and a target-provider follow-up turn, the corresponding adapter stays
archive-only under the UI introduced in Task 6.
