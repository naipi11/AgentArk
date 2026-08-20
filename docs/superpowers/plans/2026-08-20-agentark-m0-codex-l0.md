# AgentArk M0 Codex L0 Read-Only Vertical Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an encrypted, local-only, read-only Codex archive with deterministic provenance, sanitized search, CLI workflows, and a minimal Tauri desktop viewer.

**Architecture:** Vendor data enters through a read-only `SourceAdapter` boundary, is archived in an encrypted CAS before normalization, and is indexed transactionally in SQLCipher/FTS5. The Rust application layer owns all behavior; CLI and Tauri call application services and never access adapters, vendor files, keys, CAS, or SQL directly.

**Tech Stack:** Rust 1.97.1 (edition 2024), Codex CLI protocol baseline 0.146.0, Tauri 2.11.5, React 19.2.8, TypeScript 7.0.2, Vite 8.2.2, pnpm 11.22.0, SQLCipher through rusqlite 0.40.2, XChaCha20-Poly1305, HKDF-SHA-256, HMAC-SHA-256, RFC 8785 JCS, SQLite FTS5.

**Spec:** `docs/superpowers/specs/2026-08-20-agentark-m0-codex-l0-design.md`

## Global Constraints

- Product and executable name: `AgentArk` / `agentark`. Rust packages use the `agentark-*` prefix.
- Repository remains private. Do not add a public license file or publish an artifact.
- Do not push, open a pull request, publish, or scan real user history without separate explicit authorization.
- Work in the isolated worktree created at execution time by `superpowers:using-git-worktrees`.
- Rust toolchain is exactly `1.97.1` with edition `2024`. Node is `>=24 <25`. pnpm is exactly `11.22.0`.
- Codex fixture baseline is `codex-cli 0.146.0`. Any other version is unsupported until it has its own immutable schema and fixture entry.
- Local-only mode makes no intentional network request. Codex App Server uses local `stdio` only.
- Never read `auth.json`, keychain contents, cookies, `.env` files, or provider credential databases.
- Never modify vendor files, directories, SQLite databases, WAL files, permissions, ACLs, attributes, or modification times.
- Never normalize or index hidden reasoning. Preserve its containing raw source record only in encrypted CAS.
- Unknown fingerprints fail closed: encrypted raw archive plus quarantine; no semantic indexing.
- Every production behavior follows RED -> GREEN -> REFACTOR. Declarative configuration, lockfiles, generated Tauri icons, and generated Codex schemas are configuration/generated-code exceptions; validate them with the exact commands in their task.
- Do not use `unsafe` in AgentArk-owned Rust code. Every crate starts with `#![forbid(unsafe_code)]`.
- Every error, log, CLI JSON document, FTS row, preview, and diagnostic is sanitized.
- Stage only paths listed by each commit step. Never use `git add .`, `git add -A`, or `git add --all`.
- Each task stops for fresh verification and inline diff self-review before the
  next task begins. Independent review occurs at the four Gate checkpoints.

## Dependency Baseline

Pin these exact versions in workspace manifests:

| Dependency | Version | Required features |
|---|---:|---|
| serde | 1.0.229 | `derive` |
| serde_json | 1.0.151 | `preserve_order` |
| schemars | 1.2.2 | `derive` |
| uuid | 1.24.1 | `serde,v4,v5,v7` |
| thiserror | 2.0.20 | default |
| sha2 | 0.11.0 | default |
| hmac | 0.13.0 | default |
| hkdf | 0.13.0 | default |
| hex | 0.4.3 | default |
| getrandom | 0.4.3 | default |
| chacha20poly1305 | 0.11.0 | `zeroize` |
| zeroize | 1.9.0 | `derive` |
| rusqlite | 0.40.2 | `bundled-sqlcipher-vendored-openssl,backup,hooks,limits` |
| keyring | 4.1.6 | default `v1` |
| clap | 4.6.6 | `derive,env` |
| tracing | 0.1.44 | default |
| tracing-subscriber | 0.3.23 | `fmt,env-filter,json` |
| tempfile | 3.27.0 | default |
| proptest | 1.11.0 | default |
| assert_cmd | 2.2.2 | default |
| predicates | 3.1.4 | default |
| url | 2.5.8 | `serde` |
| regex | 1.13.1 | default |
| walkdir | 2.5.0 | default |
| dunce | 1.0.5 | default |
| serde_jcs | 0.2.0 | default |
| time | 0.3.55 | `formatting,parsing,serde,serde-well-known` |
| directories | 6.0.0 | default |
| libfuzzer-sys | 0.4.13 | default |
| tauri | 2.11.5 | `tracing` |
| tauri-build | 2.6.3 | default |

Frontend versions:

| Package | Version |
|---|---:|
| @tauri-apps/api | 2.11.1 |
| @tauri-apps/cli | 2.11.4 |
| react / react-dom | 19.2.8 |
| typescript | 7.0.2 |
| vite | 8.2.2 |
| @vitejs/plugin-react | 6.1.0 |
| vitest | 4.1.11 |
| @testing-library/react | 16.3.2 |
| @testing-library/jest-dom | 7.0.1 |
| @playwright/test | 1.62.1 |

## File Responsibility Map

| Path | Responsibility |
|---|---|
| `Cargo.toml` | Workspace membership and exact dependency pins |
| `rust-toolchain.toml` | Rust 1.97.1 selection |
| `crates/canonical/src/{ids,hash,model}.rs` | Stable identities, hashes, canonical entities |
| `crates/security/src/{path,secrets,keys}.rs` | Trust roots, secret projection, OS-backed keys |
| `crates/cas/src/{format,store}.rs` | Authenticated encrypted raw objects |
| `crates/index/migrations/0001_init.sql` | SQLCipher metadata, message, scan, quarantine, FTS schema |
| `crates/index/src/{database,query,write}.rs` | Encrypted database lifecycle and repositories |
| `crates/adapter-sdk/src/{contract,types,conformance}.rs` | Read-only adapter contract and reusable contract tests |
| `crates/adapters/synthetic/` | Deterministic fixture adapter |
| `crates/adapters/codex/src/{probe,protocol,process,filesystem,normalize}.rs` | Codex-only anti-corruption boundary |
| `crates/app/src/{scan,verify,services}.rs` | Use-case orchestration and completion semantics |
| `cli/src/{args,output,runtime,main}.rs` | CLI parsing, sanitized output, dependency wiring |
| `apps/desktop/src-tauri/src/{commands,state,lib}.rs` | Thin Tauri IPC boundary |
| `apps/desktop/src/{api,App,views,components}.tsx` | Four inert read-only views |
| `fixtures/{synthetic,codex,security}/` | Synthetic, redacted, immutable evidence |
| `schemas/{canonical,codex}/` | Versioned generated schemas and hashes |
| `compat/matrix.toml` | Supported adapter/protocol fingerprints |
| `threat-model/m0.md` | M0 assets, actors, threats, controls, residual risks |
| `docs/adr/0001-*.md` through `0006-*.md` | Approved architecture decisions |
| `.github/workflows/{ci,nightly}.yml` | Cross-platform deterministic and fuzz/security gates |

---

### Task 1: Scaffold the pinned Rust workspace

**Files:**
- Modify: `.gitignore`
- Create: `.gitattributes`
- Create: `rust-toolchain.toml`
- Create: `rustfmt.toml`
- Create: `Cargo.toml`
- Create: `crates/{canonical,security,cas,index,adapter-sdk,app}/Cargo.toml`
- Create: `crates/adapters/{synthetic,codex}/Cargo.toml`
- Create: `cli/Cargo.toml`
- Create: `crates/*/src/lib.rs`
- Create: `crates/adapters/*/src/lib.rs`
- Create: `cli/src/main.rs`
- Create: `Cargo.lock`

**Interfaces:**
- Consumes: Rust 1.97.1 installed with the MSVC host on Windows.
- Produces: A compiling workspace containing packages `agentark-canonical`, `agentark-security`, `agentark-cas`, `agentark-index`, `agentark-adapter-sdk`, `agentark-app`, `agentark-adapter-synthetic`, `agentark-adapter-codex`, and binary `agentark`.

- [ ] **Step 1: Verify the authorized execution environment**

Run:

```powershell
rustc --version
cargo --version
node --version
pnpm --version
git status --short --branch
```

Expected: Rust reports `1.97.1`, Node reports major `24`, pnpm reports `11.22.0`, and the isolated worktree is clean.

- [ ] **Step 2: Create crate skeletons as generated-code exceptions**

Run:

```powershell
cargo new --lib --name agentark-canonical crates/canonical
cargo new --lib --name agentark-security crates/security
cargo new --lib --name agentark-cas crates/cas
cargo new --lib --name agentark-index crates/index
cargo new --lib --name agentark-adapter-sdk crates/adapter-sdk
cargo new --lib --name agentark-app crates/app
cargo new --lib --name agentark-adapter-synthetic crates/adapters/synthetic
cargo new --lib --name agentark-adapter-codex crates/adapters/codex
cargo new --bin --name agentark cli
```

Expected: every command creates one package and no nested `.git` directory.

- [ ] **Step 3: Replace the root workspace manifest**

Write `Cargo.toml`:

```toml
[workspace]
members = [
  "crates/canonical",
  "crates/security",
  "crates/cas",
  "crates/index",
  "crates/adapter-sdk",
  "crates/app",
  "crates/adapters/synthetic",
  "crates/adapters/codex",
  "cli",
]
resolver = "2"

[workspace.package]
version = "0.1.0"
edition = "2024"
rust-version = "1.97.1"
authors = ["naipi11"]
repository = "https://github.com/naipi11/AgentArk"
publish = false

[workspace.dependencies]
serde = { version = "=1.0.229", features = ["derive"] }
serde_json = { version = "=1.0.151", features = ["preserve_order"] }
schemars = { version = "=1.2.2", features = ["derive"] }
uuid = { version = "=1.24.1", features = ["serde", "v4", "v5", "v7"] }
thiserror = "=2.0.20"
sha2 = "=0.11.0"
hmac = "=0.13.0"
hkdf = "=0.13.0"
hex = "=0.4.3"
getrandom = "=0.4.3"
chacha20poly1305 = { version = "=0.11.0", features = ["zeroize"] }
zeroize = { version = "=1.9.0", features = ["derive"] }
rusqlite = { version = "=0.40.2", features = ["bundled-sqlcipher-vendored-openssl", "backup", "hooks", "limits"] }
keyring = "=4.1.6"
clap = { version = "=4.6.6", features = ["derive", "env"] }
tracing = "=0.1.44"
tracing-subscriber = { version = "=0.3.23", features = ["fmt", "env-filter", "json"] }
tempfile = "=3.27.0"
proptest = "=1.11.0"
assert_cmd = "=2.2.2"
predicates = "=3.1.4"
url = { version = "=2.5.8", features = ["serde"] }
regex = "=1.13.1"
walkdir = "=2.5.0"
dunce = "=1.0.5"
serde_jcs = "=0.2.0"
time = { version = "=0.3.55", features = ["formatting", "parsing", "serde", "serde-well-known"] }
directories = "=6.0.0"
tauri = { version = "=2.11.5", features = ["tracing"] }
tauri-build = "=2.6.3"
```

Each package manifest inherits `version.workspace`, `edition.workspace`,
`rust-version.workspace`, and `publish.workspace`, and declares only
dependencies it imports.

- [ ] **Step 4: Pin formatting, toolchain, line endings, and ignored state**

Write `rust-toolchain.toml`:

```toml
[toolchain]
channel = "1.97.1"
profile = "minimal"
components = ["clippy", "rustfmt"]
```

Write `rustfmt.toml`:

```toml
edition = "2024"
max_width = 100
newline_style = "Unix"
use_field_init_shorthand = true
```

Write `.gitattributes`:

```gitattributes
* text=auto
*.rs text eol=lf
*.toml text eol=lf
*.md text eol=lf
*.json text eol=lf
*.yml text eol=lf
*.yaml text eol=lf
*.png binary
*.ico binary
*.icns binary
```

Write `.gitignore`:

```gitignore
/target/
/.worktrees/
/node_modules/
/apps/desktop/node_modules/
/apps/desktop/dist/
/.tmp-*/
*.db
*.db-wal
*.db-shm
```

- [ ] **Step 5: Forbid unsafe code in every generated crate**

Replace every generated library `src/lib.rs` with:

```rust
#![forbid(unsafe_code)]
```

Replace `cli/src/main.rs` with:

```rust
#![forbid(unsafe_code)]

fn main() {
    println!("AgentArk");
}
```

- [ ] **Step 6: Validate the workspace and lock dependencies**

Run:

```powershell
cargo fmt --all -- --check
cargo metadata --no-deps --format-version 1
cargo test --workspace --no-run
cargo generate-lockfile
git diff --check
```

Expected: all commands exit 0, all nine packages appear in metadata, and `Cargo.lock` is created.

- [ ] **Step 7: Commit the workspace skeleton**

```powershell
git add -- .gitignore .gitattributes rust-toolchain.toml rustfmt.toml Cargo.toml Cargo.lock crates cli
git commit -m "chore: scaffold pinned AgentArk workspace"
```

### Task 2: Implement deterministic identities and canonical hashes

**Files:**
- Create: `crates/canonical/src/ids.rs`
- Create: `crates/canonical/src/hash.rs`
- Modify: `crates/canonical/src/lib.rs`
- Modify: `crates/canonical/Cargo.toml`
- Test: `crates/canonical/tests/identity_hash.rs`

**Interfaces:**
- Consumes: `uuid`, `sha2`, `hex`, `serde`, `serde_jcs`.
- Produces:
  - `agent_install_id(machine_id: Uuid, agent_kind: &str, canonical_root: &str) -> Uuid`
  - `session_id(install_id: Uuid, source_session_id: &str) -> Uuid`
  - `message_id(session_id: Uuid, source_record_id: Option<&str>, ordinal: u64, raw_hash: &Sha256Digest) -> Uuid`
  - `Sha256Digest::from_bytes(&[u8]) -> Sha256Digest`
  - `canonical_hash<T: Serialize>(entity_type: &str, value: &T) -> Result<Sha256Digest, CanonicalHashError>`

- [ ] **Step 1: Write failing identity tests**

Create `crates/canonical/tests/identity_hash.rs`:

```rust
use agentark_canonical::{
    Sha256Digest, agent_install_id, canonical_hash, message_id, session_id,
};
use serde::Serialize;
use uuid::Uuid;

#[test]
fn identities_are_stable_and_message_ordinals_are_distinct() {
    let machine = Uuid::parse_str("018f8e42-89e0-7d35-b52a-1c8f7e98c001").unwrap();
    let install = agent_install_id(machine, "codex", "file:///C:/Users/test/.codex");
    assert_eq!(install, agent_install_id(machine, "codex", "file:///C:/Users/test/.codex"));

    let session = session_id(install, "thr_123");
    let raw = Sha256Digest::from_bytes(b"{\"type\":\"message\"}");
    assert_ne!(
        message_id(session, None, 1, &raw),
        message_id(session, None, 2, &raw)
    );
    assert_eq!(
        message_id(session, Some("item_1"), 1, &raw),
        message_id(session, Some("item_1"), 99, &raw)
    );
}

#[derive(Serialize)]
struct HashFixture {
    b: u64,
    a: &'static str,
}

#[test]
fn canonical_hash_is_key_order_independent_and_domain_separated() {
    let value = HashFixture { b: 7, a: "x" };
    let session_hash = canonical_hash("session", &value).unwrap();
    let message_hash = canonical_hash("message", &value).unwrap();
    assert_ne!(session_hash, message_hash);
    assert!(session_hash.as_str().starts_with("sha256:"));
    assert_eq!(session_hash.as_str().len(), 71);
}
```

- [ ] **Step 2: Run the test and verify RED**

Run:

```powershell
cargo test -p agentark-canonical --test identity_hash
```

Expected: compilation fails because the imported identity and hash APIs do not exist.

- [ ] **Step 3: Implement stable UUIDv5 identities**

Create `crates/canonical/src/ids.rs`:

```rust
use uuid::Uuid;

use crate::Sha256Digest;

const AGENTARK_NAMESPACE: Uuid =
    Uuid::from_u128(0xd6ba6862_673d_5f83_9df7_64c15b5138e6);

pub fn agent_install_id(machine_id: Uuid, agent_kind: &str, canonical_root: &str) -> Uuid {
    Uuid::new_v5(
        &AGENTARK_NAMESPACE,
        format!("install\0{machine_id}\0{agent_kind}\0{canonical_root}").as_bytes(),
    )
}

pub fn session_id(install_id: Uuid, source_session_id: &str) -> Uuid {
    Uuid::new_v5(
        &AGENTARK_NAMESPACE,
        format!("session\0{install_id}\0{source_session_id}").as_bytes(),
    )
}

pub fn message_id(
    session_id: Uuid,
    source_record_id: Option<&str>,
    ordinal: u64,
    raw_hash: &Sha256Digest,
) -> Uuid {
    let source_key = source_record_id
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("{ordinal}\0{}", raw_hash.as_str()));
    Uuid::new_v5(
        &AGENTARK_NAMESPACE,
        format!("message\0{session_id}\0{source_key}").as_bytes(),
    )
}
```

- [ ] **Step 4: Implement domain-separated RFC 8785 hashes**

Create `crates/canonical/src/hash.rs`:

```rust
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Error)]
pub enum CanonicalHashError {
    #[error("canonical serialization failed")]
    Serialization(#[from] serde_json::Error),
}

pub fn canonical_hash<T: Serialize>(
    entity_type: &str,
    value: &T,
) -> Result<Sha256Digest, CanonicalHashError> {
    let canonical = serde_jcs::to_vec(value)?;
    let mut input = format!("agentark:v1:{entity_type}:").into_bytes();
    input.extend_from_slice(&canonical);
    Ok(Sha256Digest::from_bytes(&input))
}
```

Export both modules from `crates/canonical/src/lib.rs`. Add workspace
dependencies `serde`, `serde_json`, `schemars`, `uuid`, `thiserror`, `sha2`,
`hex`, and `serde_jcs` to `crates/canonical/Cargo.toml`.

- [ ] **Step 5: Run identity and hash tests and verify GREEN**

```powershell
cargo test -p agentark-canonical --test identity_hash
cargo clippy -p agentark-canonical --all-targets -- -D warnings
```

Expected: 2 tests pass and clippy emits no warning.

- [ ] **Step 6: Commit deterministic identities and hashes**

```powershell
git add -- crates/canonical/Cargo.toml crates/canonical/src/lib.rs crates/canonical/src/ids.rs crates/canonical/src/hash.rs crates/canonical/tests/identity_hash.rs
git commit -m "feat: add canonical identities and hashes"
```

### Task 3: Define the canonical v0.1 model and schema

**Files:**
- Create: `crates/canonical/src/model.rs`
- Create: `crates/canonical/examples/write_schema.rs`
- Modify: `crates/canonical/src/lib.rs`
- Modify: `crates/canonical/Cargo.toml`
- Create: `schemas/canonical/v0.1.0.json`
- Test: `crates/canonical/tests/model_roundtrip.rs`

**Interfaces:**
- Consumes: `Sha256Digest` and stable UUIDs from Task 2.
- Produces: `AgentInstall`, `Workspace`, `CanonicalSession`, `CanonicalMessage`, `ContentPart`, `ToolEvent`, `Attachment`, `SourceRecord`, `Completeness`, and JSON Schema `0.1.0`.

- [ ] **Step 1: Write failing round-trip and ordering tests**

Create `crates/canonical/tests/model_roundtrip.rs`:

```rust
use std::collections::BTreeMap;

use agentark_canonical::{
    CanonicalMessage, CanonicalRole, ContentPart, ContentPartKind, Sha256Digest,
};
use serde_json::json;
use uuid::Uuid;

#[test]
fn raw_role_and_unknown_fields_survive_round_trip() {
    let mut raw_extra = BTreeMap::new();
    raw_extra.insert("futureField".into(), json!({"nested": true}));
    let message = CanonicalMessage {
        id: Uuid::nil(),
        source_record_id: None,
        ordinal: 4,
        role: CanonicalRole::Unknown,
        raw_role: Some("critic".into()),
        created_at_raw: Some("not-a-time".into()),
        content: vec![ContentPart {
            kind: ContentPartKind::Text,
            text: Some("visible".into()),
            attachment_id: None,
            raw_extra,
        }],
        raw_ref: Sha256Digest::from_bytes(b"raw"),
    };
    let encoded = serde_json::to_vec(&message).unwrap();
    let decoded: CanonicalMessage = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded, message);
}

#[test]
fn ordinal_is_not_derived_from_timestamp() {
    let mut messages = vec![
        CanonicalMessage::text_fixture(2, "same", "second"),
        CanonicalMessage::text_fixture(1, "same", "first"),
    ];
    messages.sort_by_key(|message| message.ordinal);
    assert_eq!(messages[0].visible_text(), "first");
    assert_eq!(messages[1].visible_text(), "second");
}
```

- [ ] **Step 2: Run the tests and verify RED**

```powershell
cargo test -p agentark-canonical --test model_roundtrip
```

Expected: compilation fails because canonical model types are absent.

- [ ] **Step 3: Implement the complete v0.1 entity set**

Create `crates/canonical/src/model.rs`. Use these exact enums and required fields:

```rust
use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::Sha256Digest;

pub const CANONICAL_SCHEMA_VERSION: &str = "0.1.0";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum AgentKind { Codex }

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum Completeness { Complete, Partial, Quarantined }

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum CanonicalRole { User, Assistant, System, Tool, Unknown }

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum ContentPartKind { Text, Image, Audio, File, Unknown }

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AgentInstall {
    pub id: Uuid,
    pub kind: AgentKind,
    pub executable_version: String,
    pub authorized_root_uri: String,
    pub adapter_version: String,
    pub schema_fingerprint: String,
    pub capabilities: BTreeSet<String>,
    pub quarantine_reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Workspace {
    pub id: Uuid,
    pub path_native: String,
    pub canonical_uri: String,
    pub git_commit: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalSession {
    pub schema_version: String,
    pub id: Uuid,
    pub install_id: Uuid,
    pub source_session_id: String,
    pub source_kind: String,
    pub workspace: Option<Workspace>,
    pub title: Option<String>,
    pub archived: bool,
    pub created_at_raw: Option<String>,
    pub updated_at_raw: Option<String>,
    pub model_provider: Option<String>,
    pub model_name: Option<String>,
    pub completeness: Completeness,
    pub messages: Vec<CanonicalMessage>,
    pub tool_events: Vec<ToolEvent>,
    pub attachments: Vec<Attachment>,
    pub raw_extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalMessage {
    pub id: Uuid,
    pub source_record_id: Option<String>,
    pub ordinal: u64,
    pub role: CanonicalRole,
    pub raw_role: Option<String>,
    pub created_at_raw: Option<String>,
    pub content: Vec<ContentPart>,
    pub raw_ref: Sha256Digest,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ContentPart {
    pub kind: ContentPartKind,
    pub text: Option<String>,
    pub attachment_id: Option<Uuid>,
    pub raw_extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ToolEvent {
    pub id: String,
    pub ordinal: u64,
    pub tool_name: String,
    pub status: String,
    pub visible_input: Option<String>,
    pub visible_output: Option<String>,
    pub raw_ref: Sha256Digest,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Attachment {
    pub id: Uuid,
    pub source_locator: String,
    pub media_type: Option<String>,
    pub size: u64,
    pub sha256: Sha256Digest,
    pub raw_ref: Sha256Digest,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SourceRecord {
    pub source_locator: String,
    pub source_record_id: Option<String>,
    pub ordinal: u64,
    pub raw_sha256: Sha256Digest,
    pub cas_object_id: String,
    pub adapter_version: String,
    pub snapshot_id: String,
}
```

Add `#[doc(hidden)]` `text_fixture` and `visible_text` fixture helpers. They
remain available to integration tests but are not presented as ingestion
constructors in generated documentation.

Implement `CanonicalSession::searchable_text()` by joining message visible text
and visible tool input/output in ordinal order. It excludes `raw_extra`,
attachments, source locators, and every item not represented by a canonical
visible entity.

- [ ] **Step 4: Verify the model tests GREEN**

```powershell
cargo test -p agentark-canonical --test model_roundtrip
```

Expected: 2 tests pass.

- [ ] **Step 5: Generate and verify the canonical schema**

The example writes `schemars::schema_for!(CanonicalSession)` as pretty JSON to the path supplied as its only argument. Run:

```powershell
cargo run -p agentark-canonical --example write_schema -- schemas/canonical/v0.1.0.json
cargo run -p agentark-canonical --example write_schema -- schemas/canonical/v0.1.0.second.json
Compare-Object (Get-Content schemas/canonical/v0.1.0.json) (Get-Content schemas/canonical/v0.1.0.second.json)
[System.IO.File]::Delete((Resolve-Path schemas/canonical/v0.1.0.second.json))
```

Expected: `Compare-Object` prints nothing, proving deterministic generation.

- [ ] **Step 6: Run crate verification and commit**

```powershell
cargo test -p agentark-canonical
cargo clippy -p agentark-canonical --all-targets -- -D warnings
git diff --check
git add -- crates/canonical schemas/canonical/v0.1.0.json
git commit -m "feat: define canonical session schema"
```

### Task 4: Enforce authorized-root and hostile-path policy

**Files:**
- Create: `crates/security/src/error.rs`
- Create: `crates/security/src/path.rs`
- Modify: `crates/security/src/lib.rs`
- Modify: `crates/security/Cargo.toml`
- Test: `crates/security/tests/path_policy.rs`

**Interfaces:**
- Consumes: `dunce`, `url`, and standard filesystem metadata.
- Produces:
  - `AuthorizedRoot::new(root: PathBuf) -> Result<AuthorizedRoot, SecurityError>`
  - `AuthorizedRoot::resolve_existing(&self, relative: &Path) -> Result<PathBuf, SecurityError>`
  - `AuthorizedRoot::open_regular_file(&self, relative: &Path) -> Result<File, SecurityError>`
  - `validate_relative_lexical(value: &str) -> Result<(), SecurityError>`
  - `PathClass::{Local, Unc, Device, AlternateDataStream, Traversal, ReparsePoint, Symlink}`

- [ ] **Step 1: Write failing lexical and filesystem tests**

Create `crates/security/tests/path_policy.rs`:

```rust
use std::{fs, path::Path};

use agentark_security::{AuthorizedRoot, PathClass, classify_windows_path};
use tempfile::tempdir;

#[test]
fn rejects_windows_unc_device_ads_and_traversal_strings_on_every_platform() {
    assert_eq!(classify_windows_path(r"\\server\share\x"), PathClass::Unc);
    assert_eq!(classify_windows_path(r"\\?\C:\x"), PathClass::Device);
    assert_eq!(classify_windows_path(r"C:\safe\file.txt:secret"), PathClass::AlternateDataStream);
    assert_eq!(classify_windows_path(r"..\outside"), PathClass::Traversal);
}

#[test]
fn opens_only_regular_files_beneath_the_authorized_root() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("ok.jsonl"), b"{}\n").unwrap();
    fs::create_dir(dir.path().join("nested")).unwrap();
    let root = AuthorizedRoot::new(dir.path().to_path_buf()).unwrap();
    assert!(root.open_regular_file(Path::new("ok.jsonl")).is_ok());
    assert!(root.open_regular_file(Path::new("nested")).is_err());
    assert!(root.open_regular_file(Path::new("../escape")).is_err());
}
```

- [ ] **Step 2: Run tests and verify RED**

```powershell
cargo test -p agentark-security --test path_policy
```

Expected: compilation fails because path-policy APIs do not exist.

- [ ] **Step 3: Implement lexical classification and component containment**

Implement `classify_windows_path` as a pure string classifier so Windows forms are tested on all CI systems:

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathClass {
    Local,
    Unc,
    Device,
    AlternateDataStream,
    Traversal,
    ReparsePoint,
    Symlink,
}

pub fn classify_windows_path(value: &str) -> PathClass {
    let normalized = value.replace('/', r"\");
    if normalized.starts_with(r"\\?\") || normalized.starts_with(r"\\.\") {
        return PathClass::Device;
    }
    if normalized.starts_with(r"\\") {
        return PathClass::Unc;
    }
    if normalized.split('\\').any(|part| part == "..") {
        return PathClass::Traversal;
    }
    let bytes = normalized.as_bytes();
    let without_drive = if bytes.len() >= 2
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
    {
        &normalized[2..]
    } else {
        &normalized
    };
    if without_drive.contains(':') {
        return PathClass::AlternateDataStream;
    }
    PathClass::Local
}
```

`AuthorizedRoot::new` requires an existing absolute local directory and stores `dunce::canonicalize(root)`. `resolve_existing` rejects absolute input and every non-`Local` lexical class, walks each component with `symlink_metadata`, rejects symlinks, and on Windows rejects `FILE_ATTRIBUTE_REPARSE_POINT (0x400)`. The final canonical path must start with the canonical root plus a component boundary.

`validate_relative_lexical` rejects empty strings, absolute/prefixed/rooted
paths, `.` and `..` components, and every non-`Local` Windows class. It accepts
only one or more normal relative components.

`open_regular_file` calls `resolve_existing`, checks `metadata.is_file()`, and opens read-only. It never creates a path.

`error.rs` starts with these path-safe variants and sanitized messages:

```rust
#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    #[error("source root is not authorized")]
    RootNotAuthorized,
    #[error("path class is forbidden: {0}")]
    ForbiddenPathClass(&'static str),
    #[error("path escapes the authorized root")]
    PathEscape,
    #[error("source is not a regular file")]
    NotRegularFile,
    #[error("security I/O operation failed")]
    Io(#[from] std::io::Error),
}
```

Tasks 5 and 6 add secret-rule and key-store variants without placing matched
values, paths, or key bytes in an error message.

- [ ] **Step 4: Add platform-specific symlink/reparse tests**

On Unix, create a symlink inside the root pointing outside and assert rejection.
Extract `is_windows_reparse_point(file_attributes: u32) -> bool` and test
`0x400` as true and `0` as false on every platform. The Windows
`resolve_existing` implementation must call this function with real metadata;
the pure test is mandatory and requires no junction-creation privilege.

- [ ] **Step 5: Run security tests and commit**

```powershell
cargo test -p agentark-security --test path_policy
cargo clippy -p agentark-security --all-targets -- -D warnings
git diff --check
git add -- crates/security/Cargo.toml crates/security/src/lib.rs crates/security/src/error.rs crates/security/src/path.rs crates/security/tests/path_policy.rs
git commit -m "feat: enforce authorized source roots"
```

### Task 5: Implement deterministic secret projection and inert text

**Files:**
- Create: `crates/security/src/secrets.rs`
- Modify: `crates/security/src/lib.rs`
- Modify: `crates/security/Cargo.toml`
- Create: `fixtures/security/vendor-token-canaries.json`
- Test: `crates/security/tests/secret_projection.rs`

**Interfaces:**
- Consumes: `regex` and synthetic canary fixtures.
- Produces:
  - `SecretScanner::v1() -> Result<SecretScanner, SecurityError>`
  - `SecretScanner::sanitize(&self, input: &str) -> SanitizedText`
  - `SanitizedText { text: String, findings: Vec<SecretFinding> }`
  - `SecretFinding { class: SecretClass, rule_version: &'static str, start: usize, end: usize }`

- [ ] **Step 1: Write failing redaction and false-positive tests**

Create `crates/security/tests/secret_projection.rs`:

```rust
use agentark_security::{SecretClass, SecretScanner};

#[test]
fn removes_secret_values_but_keeps_classes() {
    let input = concat!(
        "Authorization: Bearer canary_authorization_value\n",
        "api_key = \"sk-proj-CanaryValue123456789012345\"\n",
        "https://canary-user:canary-password@example.invalid/path\n",
        "-----BEGIN PRIVATE KEY-----\ncanary\n-----END PRIVATE KEY-----",
    );
    let sanitized = SecretScanner::v1().unwrap().sanitize(input);
    for secret in [
        "canary_authorization_value",
        "sk-proj-CanaryValue123456789012345",
        "canary-password",
        "-----BEGIN PRIVATE KEY-----",
    ] {
        assert!(!sanitized.text.contains(secret));
    }
    assert!(sanitized.text.contains("[REDACTED:authorization]"));
    assert!(sanitized.findings.iter().any(|f| f.class == SecretClass::PrivateKey));
}

#[test]
fn does_not_redact_high_entropy_text_without_a_rule_match() {
    let visible = "a8f9d4c3b2e190887766554433221100";
    let sanitized = SecretScanner::v1().unwrap().sanitize(visible);
    assert_eq!(sanitized.text, visible);
    assert!(sanitized.findings.is_empty());
}
```

- [ ] **Step 2: Run tests and verify RED**

```powershell
cargo test -p agentark-security --test secret_projection
```

Expected: compilation fails because secret-scanner types do not exist.

- [ ] **Step 3: Define the fixed v1 rule registry**

Implement these ordered rules in `secrets.rs`:

```rust
const RULE_VERSION: &str = "agentark-secret-rules-v1";

const RULES: &[(&str, SecretClass)] = &[
    (r"(?is)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", SecretClass::PrivateKey),
    (r"(?im)^(authorization|cookie)\s*:\s*[^\r\n]+", SecretClass::Authorization),
    (r#"(?i)\b(token|access_token|refresh_token|api_key|secret|password|authorization)\b\s*[:=]\s*["']?[^\s"',}]+"#, SecretClass::StructuredValue),
    (r"(?i)https?://[^/\s:@]+:[^@\s/]+@", SecretClass::UriUserInfo),
    (r"\bsk-[A-Za-z0-9_-]{20,}\b", SecretClass::VendorToken),
    (r"\bghp_[A-Za-z0-9]{20,}\b", SecretClass::VendorToken),
    (r"\bgithub_pat_[A-Za-z0-9_]{20,}\b", SecretClass::VendorToken),
    (r"\bAKIA[0-9A-Z]{16}\b", SecretClass::VendorToken),
];
```

`SecretClass::label()` returns exactly `private-key`, `authorization`, `structured-value`, `uri-user-info`, or `vendor-token`.

- [ ] **Step 4: Implement non-overlapping replacement**

For every regex match, collect `(start, end, class)` against the original string, sort by `start` then longest `end`, discard a match whose bytes overlap an already accepted match, and rebuild the output from original slices plus `[REDACTED:<class>]`. Do not store the matched value in `SecretFinding`.

Use this exact output model:

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretFinding {
    pub class: SecretClass,
    pub rule_version: &'static str,
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SanitizedText {
    pub text: String,
    pub findings: Vec<SecretFinding>,
}
```

Write `fixtures/security/vendor-token-canaries.json` exactly as:

```json
[
  {"class":"openai","value":"sk-proj-AgentArkCanaryValue1234567890"},
  {"class":"github","value":"ghp_AgentArkCanaryValue1234567890"},
  {"class":"aws","value":"AKIAAGENTARKCANARY12"},
  {"class":"uri","value":"https://agentark:AgentArkCanaryValue@example.invalid/"}
]
```

The values are synthetic; `example.invalid` is reserved and no entry is a live
credential.

- [ ] **Step 5: Add sink-canary regression coverage**

Serialize `SanitizedText` to JSON through a test-only DTO and capture a `tracing_subscriber::fmt` writer into memory. Assert none of the four canary values appears in sanitized text, serialized diagnostics, or captured log output.

- [ ] **Step 6: Verify and commit secret projection**

```powershell
cargo test -p agentark-security --test secret_projection
cargo clippy -p agentark-security --all-targets -- -D warnings
git diff --check
git add -- crates/security/Cargo.toml crates/security/src/lib.rs crates/security/src/secrets.rs crates/security/tests/secret_projection.rs fixtures/security/vendor-token-canaries.json
git commit -m "feat: sanitize secret-bearing projections"
```

### Task 6: Create fail-closed dataset keys and OS key storage

**Files:**
- Create: `crates/security/src/keys.rs`
- Modify: `crates/security/src/error.rs`
- Modify: `crates/security/src/lib.rs`
- Modify: `crates/security/Cargo.toml`
- Test: `crates/security/tests/key_management.rs`

**Interfaces:**
- Consumes: `keyring`, `getrandom`, `hkdf`, `sha2`, `chacha20poly1305`, `hex`, `zeroize`.
- Produces:
  - `MasterKeyStore::{load, store}`
  - `OsMasterKeyStore::new(machine_id: Uuid)`
  - `MemoryMasterKeyStore` for tests
  - `DatasetBootstrap::create(dataset_id, &dyn MasterKeyStore)`
  - `DatasetBootstrap::unlock(&dyn MasterKeyStore) -> Result<DatasetKeys, SecurityError>`
  - `DatasetKeys::{dataset_id, sqlcipher_key, cas_aead_key, object_id_key}` with
    the three keys held as zeroizing 32-byte values.

- [ ] **Step 1: Write failing fail-closed and bootstrap tests**

Create `crates/security/tests/key_management.rs`:

```rust
use agentark_security::{DatasetBootstrap, MemoryMasterKeyStore, SecurityError};
use uuid::Uuid;

#[test]
fn creates_and_unlocks_wrapped_dataset_keys_without_plaintext_metadata() {
    let store = MemoryMasterKeyStore::empty();
    let dataset_id = Uuid::parse_str("018f8e42-89e0-7d35-b52a-1c8f7e98c010").unwrap();
    let bootstrap = DatasetBootstrap::create(dataset_id, &store).unwrap();
    let json = serde_json::to_string(&bootstrap).unwrap();
    assert!(!json.contains("source-root"));
    assert!(!json.contains("session-title"));
    let first = bootstrap.unlock(&store).unwrap();
    let second = bootstrap.unlock(&store).unwrap();
    assert_eq!(first.sqlcipher_key(), second.sqlcipher_key());
    assert_ne!(first.sqlcipher_key(), first.cas_aead_key());
}

#[test]
fn missing_master_key_never_falls_back_to_plaintext() {
    let creator = MemoryMasterKeyStore::empty();
    let bootstrap = DatasetBootstrap::create(Uuid::new_v4(), &creator).unwrap();
    let missing = MemoryMasterKeyStore::empty();
    assert!(matches!(
        bootstrap.unlock(&missing),
        Err(SecurityError::MasterKeyUnavailable)
    ));
}
```

- [ ] **Step 2: Run tests and verify RED**

```powershell
cargo test -p agentark-security --test key_management
```

Expected: compilation fails because key-management APIs are absent.

- [ ] **Step 3: Implement master-key stores**

Define:

```rust
pub trait MasterKeyStore: Send + Sync {
    fn load(&self) -> Result<Zeroizing<[u8; 32]>, SecurityError>;
    fn store(&self, key: &[u8; 32]) -> Result<(), SecurityError>;
}
```

`MemoryMasterKeyStore` uses a mutex-protected optional key and exists only for tests and ephemeral fixture runs. `OsMasterKeyStore` uses:

```rust
let entry = keyring::Entry::new("dev.agentark.master-key", &machine_id.to_string())?;
```

Use `Entry::get_secret` and `Entry::set_secret`. Accept exactly 32 bytes; any other length returns `SecurityError::InvalidMasterKeyLength`. Map a missing credential to `MasterKeyUnavailable` and never create a replacement while unlocking an existing bootstrap.

- [ ] **Step 4: Implement wrapping and subkey derivation**

`DatasetBootstrap` contains only:

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DatasetBootstrap {
    pub format_version: u32,
    pub dataset_id: Uuid,
    pub wrap_nonce_hex: String,
    pub wrapped_dataset_key_hex: String,
}
```

Creation generates a device master key only when the store is empty, generates a separate random dataset key with `getrandom::fill`, and wraps the dataset key with XChaCha20-Poly1305. Associated data is `agentark:v1:dataset-key:<dataset-id>`.

Use HKDF-SHA-256 with the dataset UUID bytes as salt and these exact info values:

```text
agentark-v1-sqlcipher
agentark-v1-cas-aead
agentark-v1-object-id
```

Store derived arrays in `Zeroizing<[u8; 32]>`. Retain the non-secret dataset
UUID and expose `dataset_id() -> Uuid`. Do not implement `Clone` or `Debug` for
`DatasetKeys`.

- [ ] **Step 5: Verify key behavior and commit**

```powershell
cargo test -p agentark-security --test key_management
cargo test -p agentark-security
cargo clippy -p agentark-security --all-targets -- -D warnings
git diff --check
git add -- crates/security/Cargo.toml crates/security/src/lib.rs crates/security/src/error.rs crates/security/src/keys.rs crates/security/tests/key_management.rs
git commit -m "feat: protect dataset keys with OS storage"
```

### Task 7: Implement the authenticated encrypted CAS

**Files:**
- Create: `crates/cas/src/error.rs`
- Create: `crates/cas/src/format.rs`
- Create: `crates/cas/src/store.rs`
- Modify: `crates/cas/src/lib.rs`
- Modify: `crates/cas/Cargo.toml`
- Test: `crates/cas/tests/encrypted_store.rs`

**Interfaces:**
- Consumes: `DatasetKeys`, `Sha256Digest`, HMAC-SHA-256, and XChaCha20-Poly1305.
- Produces:
  - `ArtifactStore::put(&self, object_type: ObjectType, plaintext: &[u8]) -> Result<StoredObject, CasError>`
  - `ArtifactStore::get(&self, object: &StoredObject) -> Result<Vec<u8>, CasError>`
  - `StoredObject { object_id: String, plaintext_hash: Sha256Digest, size: u64 }`
  - `EncryptedCas::open(root: PathBuf, keys: &DatasetKeys)`

- [ ] **Step 1: Write failing round-trip, idempotence, and tamper tests**

Create `crates/cas/tests/encrypted_store.rs`:

```rust
use std::fs;

use agentark_cas::{ArtifactStore, EncryptedCas, ObjectType};
use agentark_security::{DatasetBootstrap, MemoryMasterKeyStore};
use tempfile::tempdir;
use uuid::Uuid;

fn store() -> (tempfile::TempDir, EncryptedCas) {
    let dir = tempdir().unwrap();
    let key_store = MemoryMasterKeyStore::empty();
    let bootstrap = DatasetBootstrap::create(Uuid::new_v4(), &key_store).unwrap();
    let keys = bootstrap.unlock(&key_store).unwrap();
    let cas = EncryptedCas::open(dir.path().join("objects"), &keys).unwrap();
    (dir, cas)
}

#[test]
fn encrypts_round_trips_and_deduplicates() {
    let (_dir, cas) = store();
    let first = cas.put(ObjectType::AgentRawRecord, b"canary plaintext").unwrap();
    let second = cas.put(ObjectType::AgentRawRecord, b"canary plaintext").unwrap();
    assert_eq!(first.object_id, second.object_id);
    assert_eq!(cas.get(&first).unwrap(), b"canary plaintext");
    let bytes = fs::read(cas.object_path(&first.object_id)).unwrap();
    assert!(!bytes.windows(b"canary plaintext".len())
        .any(|window| window == b"canary plaintext"));
}

#[test]
fn rejects_tampered_ciphertext() {
    let (_dir, cas) = store();
    let object = cas.put(ObjectType::AgentRawRecord, b"record").unwrap();
    let path = cas.object_path(&object.object_id);
    let mut bytes = fs::read(&path).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(path, bytes).unwrap();
    assert!(cas.get(&object).is_err());
}
```

`DatasetKeys` retains the dataset UUID and exposes `dataset_id() -> Uuid` so
CAS associated data is stable. It does not expose or format secret bytes.

- [ ] **Step 2: Run tests and verify RED**

```powershell
cargo test -p agentark-cas --test encrypted_store
```

Expected: compilation fails because CAS APIs do not exist.

- [ ] **Step 3: Implement the binary object format**

`format.rs` encodes:

```text
8 bytes  magic: AARKCAS1
1 byte   object type
24 bytes XChaCha20 nonce
N bytes  ciphertext plus 16-byte Poly1305 tag
```

Define:

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ObjectType {
    AgentRawRecord = 1,
}
```

Associated data is:

```text
agentark:v1:cas:<dataset-uuid>:<object-type>:<object-id>
```

Compute `plaintext_hash = SHA-256(plaintext)` and `object_id = hex(HMAC-SHA-256(object_id_key, plaintext_hash_bytes))`. Store objects under `objects/v1/<first-two-hex>/<object-id>`.

- [ ] **Step 4: Implement durable idempotent put**

`put` writes to a random same-directory `.tmp-<uuid>` file with `create_new(true)`, calls `sync_all`, and renames atomically. If the final object already exists, decrypt and verify it before deleting the temporary file and returning the existing object. A mismatching existing object returns `CasError::ObjectCollision`.

After rename, attempt to sync the containing directory. Ignore only the platform-specific `Unsupported` result; propagate all other errors. `get` verifies magic, object type, AEAD tag, plaintext SHA-256, HMAC object ID, and expected size.

- [ ] **Step 5: Run tests, inspect on-disk canaries, and commit**

```powershell
cargo test -p agentark-cas --test encrypted_store
cargo test -p agentark-cas
cargo clippy -p agentark-cas --all-targets -- -D warnings
rg -a "canary plaintext" target -g "*.cas"
git diff --check
```

Expected: tests pass and `rg` finds no plaintext CAS canary.

```powershell
git add -- crates/cas/Cargo.toml crates/cas/src crates/cas/tests/encrypted_store.rs
git commit -m "feat: add encrypted content-addressed storage"
```

### Task 8: Build the SQLCipher index and sanitized FTS queries

**Files:**
- Create: `crates/index/migrations/0001_init.sql`
- Create: `crates/index/src/error.rs`
- Create: `crates/index/src/database.rs`
- Create: `crates/index/src/write.rs`
- Create: `crates/index/src/query.rs`
- Modify: `crates/index/src/lib.rs`
- Modify: `crates/index/Cargo.toml`
- Test: `crates/index/tests/encrypted_index.rs`
- Test: `crates/index/tests/transactional_ingest.rs`

**Interfaces:**
- Consumes: canonical entities, `SanitizedText`, and `DatasetKeys::sqlcipher_key()`.
- Produces:
  - `IndexDb::open(path: &Path, sqlcipher_key: &[u8; 32]) -> Result<IndexDb, IndexError>`
  - `SessionIndex::ingest_session(&mut self, input: SessionIngest<'_>)`
  - `SessionIndex::record_quarantine(&mut self, record: QuarantineRecord)`
  - `SessionQuery::{list_sessions, show_session, search, list_quarantines}`
  - `SessionSummary`, `SessionDetail`, `SearchHit`, `ScanManifest`.

- [ ] **Step 1: Write failing encryption and FTS tests**

`crates/index/tests/encrypted_index.rs` creates a temporary DB using fixed test keys, inserts a title and full text containing `CanonicalVisibleCanary`, and inserts sanitized FTS text containing `[REDACTED:vendor-token]`. Assert:

```rust
let file = std::fs::read(db_path).unwrap();
assert!(!file.windows("CanonicalVisibleCanary".len())
    .any(|window| window == b"CanonicalVisibleCanary"));
assert_eq!(db.search("vendor-token", 10).unwrap().len(), 1);
assert_eq!(db.search("CanonicalVisibleCanary", 10).unwrap().len(), 0);
assert!(db.cipher_version().unwrap().starts_with("4."));
assert!(db.fts5_enabled().unwrap());
```

- [ ] **Step 2: Write a failing rollback test**

`transactional_ingest.rs` ingests a valid revision, then attempts a second revision with duplicate `ordinal` values. Assert the second call returns `IndexError::InvariantViolation` and the first revision remains the only visible revision.

- [ ] **Step 3: Run index tests and verify RED**

```powershell
cargo test -p agentark-index --test encrypted_index --test transactional_ingest
```

Expected: compilation fails because database and repository APIs are absent.

- [ ] **Step 4: Create the complete initial migration**

`0001_init.sql` creates:

```sql
CREATE TABLE schema_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
INSERT INTO schema_meta(key, value) VALUES ('schema_version', '1');

CREATE TABLE scan_runs (
  id TEXT PRIMARY KEY,
  adapter_id TEXT NOT NULL,
  snapshot_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('running','complete','partial','failed')),
  started_at TEXT NOT NULL,
  completed_at TEXT,
  indexed_count INTEGER NOT NULL DEFAULT 0,
  quarantined_count INTEGER NOT NULL DEFAULT 0,
  retryable_count INTEGER NOT NULL DEFAULT 0,
  rejected_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE agent_installs (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  executable_version TEXT NOT NULL,
  authorized_root_uri TEXT NOT NULL,
  adapter_version TEXT NOT NULL,
  schema_fingerprint TEXT NOT NULL,
  capabilities_json TEXT NOT NULL,
  quarantine_reason TEXT
);

CREATE TABLE workspaces (
  id TEXT PRIMARY KEY,
  path_native TEXT NOT NULL,
  canonical_uri TEXT NOT NULL,
  git_commit TEXT
);

CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  install_id TEXT NOT NULL REFERENCES agent_installs(id),
  workspace_id TEXT REFERENCES workspaces(id),
  source_session_id TEXT NOT NULL,
  source_kind TEXT NOT NULL,
  title TEXT,
  archived INTEGER NOT NULL CHECK(archived IN (0,1)),
  completeness TEXT NOT NULL,
  canonical_hash TEXT NOT NULL,
  canonical_json TEXT NOT NULL,
  search_title TEXT NOT NULL,
  search_body TEXT NOT NULL,
  model_provider TEXT,
  model_name TEXT,
  revision INTEGER NOT NULL,
  stale INTEGER NOT NULL DEFAULT 0 CHECK(stale IN (0,1)),
  UNIQUE(install_id, source_session_id)
);

CREATE TABLE tool_events (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  tool_name TEXT NOT NULL,
  status TEXT NOT NULL,
  visible_input TEXT,
  visible_output TEXT,
  raw_ref TEXT NOT NULL,
  UNIQUE(session_id, ordinal)
);

CREATE TABLE attachments (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  source_locator TEXT NOT NULL,
  media_type TEXT,
  size INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  raw_ref TEXT NOT NULL
);

CREATE TABLE messages (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  role TEXT NOT NULL,
  raw_role TEXT,
  visible_text TEXT NOT NULL,
  raw_ref TEXT NOT NULL,
  message_json TEXT NOT NULL,
  UNIQUE(session_id, ordinal)
);

CREATE TABLE source_records (
  id TEXT PRIMARY KEY,
  raw_sha256 TEXT NOT NULL,
  session_id TEXT,
  source_locator TEXT NOT NULL,
  source_record_id TEXT,
  ordinal INTEGER NOT NULL,
  cas_object_id TEXT NOT NULL,
  adapter_version TEXT NOT NULL,
  snapshot_id TEXT NOT NULL,
  UNIQUE(source_locator, snapshot_id)
);

CREATE TABLE quarantines (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scan_runs(id),
  source_locator TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  reason_code TEXT NOT NULL,
  raw_sha256 TEXT NOT NULL,
  cas_object_id TEXT NOT NULL
);

CREATE TABLE secret_findings (
  id INTEGER PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  class TEXT NOT NULL,
  rule_version TEXT NOT NULL,
  start_offset INTEGER NOT NULL,
  end_offset INTEGER NOT NULL
);

CREATE VIRTUAL TABLE session_fts USING fts5(
  session_id UNINDEXED,
  title,
  body,
  tokenize = 'unicode61 remove_diacritics 2'
);
```

- [ ] **Step 5: Open SQLCipher safely**

`IndexDb::open` opens the connection, applies the raw 32-byte key as a hex SQLCipher key before every other statement, then verifies `PRAGMA cipher_version`. Apply:

```sql
PRAGMA foreign_keys = ON;
PRAGMA trusted_schema = OFF;
PRAGMA secure_delete = ON;
PRAGMA temp_store = MEMORY;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
```

Check `SELECT sqlite_compileoption_used('ENABLE_FTS5')` returns `1`. A missing cipher version or FTS5 returns `UnsupportedStorageBuild` before migrations run.

- [ ] **Step 6: Implement transactional ingest and explicit queries**

Define the repository boundary before implementing SQL:

```rust
pub struct SessionIngest<'a> {
    pub install: &'a AgentInstall,
    pub session: &'a CanonicalSession,
    pub source_records: &'a [SourceRecord],
    pub sanitized_title: &'a str,
    pub sanitized_body: &'a str,
    pub findings: &'a [SecretFinding],
    pub canonical_hash: &'a Sha256Digest,
}

pub struct QuarantineRecord {
    pub id: Uuid,
    pub scan_id: Uuid,
    pub source_locator: String,
    pub fingerprint: String,
    pub reason_code: String,
    pub raw_sha256: Sha256Digest,
    pub cas_object_id: String,
}

pub enum ScanManifestStatus { Complete, Partial, Failed }

pub struct ScanManifest {
    pub id: Uuid,
    pub status: ScanManifestStatus,
    pub completed_at: String,
    pub indexed_count: u64,
    pub quarantined_count: u64,
    pub retryable_count: u64,
    pub rejected_count: u64,
}

pub trait SessionIndex {
    fn begin_scan(&mut self, scan_id: Uuid, adapter_id: &str, snapshot_id: &str)
        -> Result<(), IndexError>;
    fn ingest_session(&mut self, input: SessionIngest<'_>) -> Result<(), IndexError>;
    fn record_quarantine(&mut self, record: QuarantineRecord) -> Result<(), IndexError>;
    fn finish_scan(&mut self, manifest: &ScanManifest) -> Result<(), IndexError>;
    fn fail_scan(&mut self, scan_id: Uuid) -> Result<(), IndexError>;
}

pub trait SessionQuery {
    fn list_sessions(&self, limit: u32, offset: u32)
        -> Result<Vec<SessionSummary>, IndexError>;
    fn show_session(&self, id: Uuid) -> Result<SessionDetail, IndexError>;
    fn search(&self, query: &str, limit: u32) -> Result<Vec<SearchHit>, IndexError>;
    fn list_quarantines(&self) -> Result<Vec<QuarantineSummary>, IndexError>;
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionSummary {
    pub id: Uuid,
    pub title: Option<String>,
    pub source_kind: String,
    pub archived: bool,
    pub completeness: Completeness,
    pub stale: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionDetail {
    pub session: CanonicalSession,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchHit {
    pub session_id: Uuid,
    pub title: Option<String>,
    pub snippet: String,
    pub score: f64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuarantineSummary {
    pub id: Uuid,
    pub reason_code: String,
    pub fingerprint: String,
    pub sanitized_locator: String,
}
```

`SessionSummary.title` is read from `sessions.search_title`, never from the
full canonical title. `SessionDetail` is an internal Rust value; it cannot cross
CLI/Tauri boundaries until Task 10 maps it to public DTOs.

`ingest_session` validates strictly increasing unique ordinals before opening a
transaction. Inside one transaction it upserts the install/workspace, deletes
the prior FTS, message, tool-event, attachment, and secret-finding rows, upserts
the session with `revision + 1`, inserts all canonical child/source rows,
inserts the sanitized FTS row, and commits. No dynamic column or table name
comes from user input.

`search` uses:

```sql
SELECT s.id, s.title, snippet(session_fts, 2, '[', ']', ' … ', 16), bm25(session_fts)
FROM session_fts
JOIN sessions s ON s.id = session_fts.session_id
WHERE session_fts MATCH ?1
ORDER BY bm25(session_fts)
LIMIT ?2;
```

Escape FTS operator syntax by converting a user query into a quoted phrase per whitespace-delimited token. Reject an empty query and cap `limit` at 100.

- [ ] **Step 7: Verify encrypted storage and commit**

```powershell
cargo test -p agentark-index --test encrypted_index --test transactional_ingest
cargo test -p agentark-index
cargo clippy -p agentark-index --all-targets -- -D warnings
git diff --check
git add -- crates/index/Cargo.toml crates/index/migrations/0001_init.sql crates/index/src crates/index/tests
git commit -m "feat: add encrypted session index"
```

### Task 9: Define the adapter SDK and synthetic conformance fixture

**Files:**
- Create: `crates/adapter-sdk/src/contract.rs`
- Create: `crates/adapter-sdk/src/types.rs`
- Create: `crates/adapter-sdk/src/conformance.rs`
- Modify: `crates/adapter-sdk/src/lib.rs`
- Modify: `crates/adapter-sdk/Cargo.toml`
- Create: `crates/adapters/synthetic/src/adapter.rs`
- Modify: `crates/adapters/synthetic/src/lib.rs`
- Modify: `crates/adapters/synthetic/Cargo.toml`
- Create: `fixtures/synthetic/{text,tool,unknown,truncated}.jsonl`
- Test: `crates/adapters/synthetic/tests/conformance.rs`

**Interfaces:**
- Consumes: canonical entities and `AuthorizedRoot`.
- Produces: the exact `SourceAdapter` contract, capture/probe types, and `assert_source_adapter_contract`.

- [ ] **Step 1: Write a failing synthetic conformance test**

```rust
use agentark_adapter_sdk::assert_source_adapter_contract;
use agentark_adapter_synthetic::SyntheticAdapter;
use tempfile::tempdir;

#[test]
fn synthetic_adapter_meets_read_only_contract() {
    let root = tempdir().unwrap();
    SyntheticAdapter::write_fixture_set(root.path()).unwrap();
    let before = SyntheticAdapter::tree_digest(root.path()).unwrap();
    let report = assert_source_adapter_contract(
        &SyntheticAdapter::new(root.path()).unwrap()
    ).unwrap();
    let after = SyntheticAdapter::tree_digest(root.path()).unwrap();
    assert_eq!(before, after);
    assert_eq!(report.normalized, 2);
    assert_eq!(report.quarantined, 1);
    assert_eq!(report.retryable, 1);
}
```

- [ ] **Step 2: Run the test and verify RED**

```powershell
cargo test -p agentark-adapter-synthetic --test conformance
```

Expected: compilation fails because the adapter contract is absent.

- [ ] **Step 3: Implement exact SDK types**

`types.rs` defines:

```rust
pub struct DetectContext {
    pub explicit_roots: Vec<PathBuf>,
    pub allow_detected_home: bool,
}

pub struct ProbeReport {
    pub adapter_id: String,
    pub executable_version: String,
    pub schema_fingerprint: String,
    pub capabilities: BTreeSet<SourceCapability>,
    pub quarantine_reason: Option<String>,
}

pub struct CaptureRequest {
    pub install: AgentInstall,
    pub snapshot_hint: Option<String>,
}

pub struct CapturedRecord {
    pub source_locator: String,
    pub source_session_id: Option<String>,
    pub source_record_id: Option<String>,
    pub ordinal: u64,
    pub snapshot_id: String,
    pub bytes: Vec<u8>,
}

pub struct CaptureBatch {
    pub snapshot_id: String,
    pub records: Vec<CapturedRecord>,
}

pub enum NormalizeOutcome {
    Normalized(CanonicalSession),
    Quarantined { reason_code: String, fingerprint: String },
    Retryable { reason_code: String },
    Rejected { reason_code: String },
}
```

`SourceCapability` includes `AppServerRead`, `FilesystemRawArchive`, `ArchivedThreads`, `Attachments`, and `KnownSemanticSchema`.

- [ ] **Step 4: Implement the read-only trait**

```rust
pub trait SourceAdapter: Send + Sync {
    fn id(&self) -> &'static str;
    fn detect(&self, ctx: &DetectContext) -> Result<Vec<AgentInstall>, AdapterError>;
    fn probe(&self, install: &AgentInstall) -> Result<ProbeReport, AdapterError>;
    fn capture(&self, request: &CaptureRequest) -> Result<CaptureBatch, AdapterError>;
    fn normalize(&self, record: &CapturedRecord)
        -> Result<NormalizeOutcome, AdapterError>;
    fn capabilities(&self, install: &AgentInstall) -> BTreeSet<SourceCapability>;
}
```

The SDK contains no target, import, resume, archive, delete, metadata-update, shell, or process method.

- [ ] **Step 5: Implement synthetic fixtures and reusable conformance**

`text.jsonl` contains one user and one assistant message with equal timestamps and distinct ordinals. `tool.jsonl` adds a visible tool call/result. `unknown.jsonl` contains an unknown role and field and returns `Quarantined`. `truncated.jsonl` omits the final newline and returns `Retryable`.

`assert_source_adapter_contract` runs detect, probe, capture, repeated capture, normalize, and a before/after tree digest. It asserts deterministic record bytes/order, no source mutation, explicit unknown quarantine, and retryable truncation.

- [ ] **Step 6: Run contract tests and commit**

```powershell
cargo test -p agentark-adapter-synthetic --test conformance
cargo test -p agentark-adapter-sdk -p agentark-adapter-synthetic
cargo clippy -p agentark-adapter-sdk -p agentark-adapter-synthetic --all-targets -- -D warnings
git diff --check
git add -- crates/adapter-sdk crates/adapters/synthetic fixtures/synthetic
git commit -m "feat: define read-only adapter contract"
```

### Task 10: Orchestrate archive-first scans and verification

**Files:**
- Create: `crates/app/src/error.rs`
- Create: `crates/app/src/scan.rs`
- Create: `crates/app/src/verify.rs`
- Create: `crates/app/src/services.rs`
- Modify: `crates/app/src/lib.rs`
- Modify: `crates/app/Cargo.toml`
- Test: `crates/app/tests/scan_pipeline.rs`
- Test: `crates/app/tests/verification.rs`

**Interfaces:**
- Consumes: `SourceAdapter`, `ArtifactStore`, `SessionIndex`, `SecretScanner`, and canonical hashing.
- Produces:
  - `ScanService<A, C, I>::run(request: ScanRequest) -> Result<ScanReport, AppError>`
  - `ScanReport { scan_id, status, indexed, quarantined, retryable, rejected }`
  - `ScanStatus::{Complete, Partial, Failed}`
  - `VerificationService::verify_scan(scan_id) -> VerificationReport`.

- [ ] **Step 1: Write a failing archive-before-index test**

Create `scan_pipeline.rs` with test doubles that append `"capture"`, `"cas.put"`, `"normalize"`, and `"index.ingest"` to a shared vector:

```rust
#[test]
fn archives_raw_bytes_before_normalizing_or_indexing() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut service = fixture_service(events.clone(), FixtureOutcome::Normalized);
    let report = service.run(fixture_request()).unwrap();
    assert_eq!(
        *events.lock().unwrap(),
        ["capture", "cas.put", "normalize", "index.ingest"]
    );
    assert_eq!(report.status, ScanStatus::Complete);
    assert_eq!(report.indexed, 1);
}
```

- [ ] **Step 2: Write failing partial and rollback tests**

Add:

```rust
#[test]
fn quarantine_is_archived_but_never_indexed_and_marks_scan_partial() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut service = fixture_service(events.clone(), FixtureOutcome::Quarantined);
    let report = service.run(fixture_request()).unwrap();
    assert_eq!(*events.lock().unwrap(), ["capture", "cas.put", "normalize", "index.quarantine"]);
    assert_eq!(report.status, ScanStatus::Partial);
    assert_eq!(report.quarantined, 1);
}

#[test]
fn index_failure_does_not_publish_a_complete_manifest() {
    let mut service = fixture_service_with_failing_index();
    let error = service.run(fixture_request()).unwrap_err();
    assert!(matches!(error, AppError::Index(_)));
    assert_eq!(service.index().last_scan_status(), Some("failed"));
}
```

- [ ] **Step 3: Run tests and verify RED**

```powershell
cargo test -p agentark-app --test scan_pipeline
```

Expected: compilation fails because scan service types are absent.

- [ ] **Step 4: Implement the archive-first state machine**

Use these exact public models:

```rust
pub struct ScanRequest {
    pub install: AgentInstall,
    pub snapshot_hint: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ScanStatus { Complete, Partial, Failed }

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanReport {
    pub scan_id: Uuid,
    pub status: ScanStatus,
    pub indexed: u64,
    pub quarantined: u64,
    pub retryable: u64,
    pub rejected: u64,
}
```

`services.rs` defines `AppServices` with sanitized query/status methods used by
both CLI and Tauri:

```rust
pub struct AppServices {
    pub scanner: Box<dyn ScanUseCase>,
    pub verifier: Box<dyn VerifyUseCase>,
    pub queries: Box<dyn QueryUseCase>,
}

pub trait QueryUseCase: Send + Sync {
    fn status(&self) -> Result<StatusDto, AppError>;
    fn list_sessions(&self, limit: u32, offset: u32) -> Result<Vec<SessionSummary>, AppError>;
    fn show_session(&self, id: Uuid) -> Result<PublicSessionDetail, AppError>;
    fn search(&self, query: &str, limit: u32) -> Result<Vec<SearchHit>, AppError>;
    fn list_quarantines(&self) -> Result<Vec<QuarantineDto>, AppError>;
}
```

Define the public boundary:

```rust
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusDto {
    pub dataset_state: String,
    pub adapter_id: Option<String>,
    pub executable_version: Option<String>,
    pub schema_fingerprint: Option<String>,
    pub capabilities: Vec<String>,
    pub quarantine_reason: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicSessionDetail {
    pub id: Uuid,
    pub title: Option<String>,
    pub archived: bool,
    pub completeness: Completeness,
    pub messages: Vec<PublicMessage>,
    pub tool_events: Vec<PublicToolEvent>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicMessage {
    pub ordinal: u64,
    pub role: CanonicalRole,
    pub text: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicToolEvent {
    pub ordinal: u64,
    pub tool_name: String,
    pub status: String,
    pub visible_input: Option<String>,
    pub visible_output: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuarantineDto {
    pub reason_code: String,
    pub fingerprint: String,
    pub sanitized_locator: String,
}
```

`services.rs` maps full canonical text through `SecretScanner` again before
building `PublicSessionDetail`. Public DTOs contain no raw reference, raw extra,
source locator, attachment path, key, CAS ID, or SQL value.

For each `CapturedRecord`:

1. Write `record.bytes` to CAS as `ObjectType::AgentRawRecord`.
2. Build `SourceRecord` using the CAS result and capture metadata.
3. Call `adapter.normalize`.
4. For `Normalized`, verify every message `raw_ref` equals the archived raw hash or a separately archived item hash, sanitize title and visible text, then call `index.ingest_session`.
5. For `Quarantined`, write an index quarantine row containing only sanitized metadata and CAS reference.
6. Count `Retryable` and `Rejected` without indexing canonical content.
7. Publish `Complete` only when all discovered records normalize and every verification check passes; otherwise publish `Partial`.

Start `scan_runs.status = running` before capture. On any infrastructure error, set `failed` in a separate best-effort transaction and return the original typed error. Never convert an infrastructure error into a partial success.

- [ ] **Step 5: Implement sanitized session projection**

`sanitize_session` concatenates only user-visible message text and visible tool input/output in ordinal order. It sanitizes title and body separately. It returns sanitized title/body and findings with session-relative offsets. It never includes `raw_extra`, raw bytes, source locators, reasoning items, or attachment bytes.

- [ ] **Step 6: Implement verification tests RED then GREEN**

`verification.rs` creates a synthetic indexed session, flips one CAS ciphertext byte, and expects:

```rust
let report = verifier.verify_scan(scan_id).unwrap();
assert!(!report.passed);
assert_eq!(report.failures[0].code, "cas-authentication-failed");
```

Implement verification of CAS AEAD, plaintext SHA-256, canonical hash, strictly increasing message ordinals, session/message counts, and FTS sanitized projection. The report contains reason codes and object IDs, never plaintext.

- [ ] **Step 7: Run integration verification and commit**

```powershell
cargo test -p agentark-app --test scan_pipeline --test verification
cargo test -p agentark-app
cargo clippy -p agentark-app --all-targets -- -D warnings
git diff --check
git add -- crates/app/Cargo.toml crates/app/src crates/app/tests
git commit -m "feat: orchestrate archive-first scans"
```

### Task 11: Implement the Codex 0.146.0 probe and read-only App Server client

**Files:**
- Create: `schemas/codex/0.146.0/app-server-v2.schema.json`
- Create: `schemas/codex/0.146.0/SHA256SUMS`
- Create: `compat/matrix.toml`
- Create: `crates/adapters/codex/src/error.rs`
- Create: `crates/adapters/codex/src/probe.rs`
- Create: `crates/adapters/codex/src/protocol.rs`
- Create: `crates/adapters/codex/src/process.rs`
- Modify: `crates/adapters/codex/src/lib.rs`
- Modify: `crates/adapters/codex/Cargo.toml`
- Create: `fixtures/codex/app-server/{initialize,list-active,list-archived,read-thread}.jsonl`
- Test: `crates/adapters/codex/tests/app_server_readonly.rs`
- Test: `crates/adapters/codex/tests/probe.rs`

**Interfaces:**
- Consumes: local `codex` executable and the stable v2 JSON schema.
- Produces:
  - `CodexProbe::run(executable: &Path) -> Result<ProbeReport, CodexError>`
  - `JsonRpcTransport::{send_value, receive_value}`
  - `ReadOnlyAppServerClient::{initialize, list_threads, read_thread}`
  - raw JSON response bytes for CAS-first processing.

- [ ] **Step 1: Generate and pin the stable schema as a generated-code exception**

Run:

```powershell
New-Item -ItemType Directory -Path target/codex-schema-0.146.0 -Force | Out-Null
codex app-server generate-json-schema --out target/codex-schema-0.146.0
$schema = 'target/codex-schema-0.146.0/codex_app_server_protocol.v2.schemas.json'
$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $schema).Hash
if ($hash -ne 'F766C650A2A2EA18BF9DDB8D82A87F74ECB0AB4CEB359A17B2E66D9D604F353F') {
    throw "Codex 0.146.0 schema fingerprint mismatch: $hash"
}
New-Item -ItemType Directory -Path schemas/codex/0.146.0 -Force | Out-Null
Copy-Item -LiteralPath $schema -Destination schemas/codex/0.146.0/app-server-v2.schema.json
Set-Content -LiteralPath schemas/codex/0.146.0/SHA256SUMS -NoNewline -Value 'f766c650a2a2ea18bf9ddb8d82a87f74ecb0ab4ceb359a17b2e66d9d604f353f  app-server-v2.schema.json'
```

Expected: schema hash equals the exact baseline and no `--experimental` flag is used.

- [ ] **Step 2: Write failing probe tests**

Use a fake executable script that returns `codex-cli 0.146.0` for `--version` and App Server help containing `--listen stdio://`. Assert the probe reports `AppServerRead` and fingerprint `sha256:f766c650...f353f`. A fake `0.147.0` executable must return a quarantine reason `unsupported-codex-version` and no `KnownSemanticSchema` capability.

- [ ] **Step 3: Implement exact version and capability probing**

`CodexProbe` runs only:

```text
codex --version
codex app-server --help
```

It applies a 5-second timeout, captures at most 64 KiB from each stream, parses `codex-cli <semver>`, and never invokes login, account, thread, shell, or network functionality. Version `0.146.0` plus the pinned schema yields `KnownSemanticSchema`. All other versions remain detectable but quarantined.

- [ ] **Step 4: Write a failing read-only protocol transcript test**

Create a `ScriptedTransport` containing fixture responses. Assert sent methods are exactly:

```rust
assert_eq!(
    transport.sent_methods(),
    ["initialize", "initialized", "thread/list", "thread/list", "thread/read"]
);
assert!(transport.sent_json().iter().all(|json| !json.contains("experimentalApi")));
assert!(transport.sent_json().iter().all(|json| {
    !["thread/start", "thread/resume", "thread/archive", "thread/delete",
      "thread/metadata/update", "turn/start", "command/exec"]
        .iter().any(|method| json.contains(method))
}));
```

- [ ] **Step 5: Implement the strict JSON-RPC client**

`initialize` sends:

```json
{"method":"initialize","id":1,"params":{"clientInfo":{"name":"agentark","title":"AgentArk","version":"0.1.0"}}}
{"method":"initialized","params":{}}
```

`list_threads` sends two paginated sequences, one with `archived:false` and one with `archived:true`. Every request sets:

```json
{
  "sourceKinds":["cli","vscode","exec","appServer","subAgent","subAgentReview","subAgentCompact","subAgentThreadSpawn","subAgentOther","unknown"],
  "useStateDbOnly":true,
  "limit":100,
  "sortKey":"created_at",
  "sortDirection":"asc"
}
```

Continue until `nextCursor` is null. `read_thread` sends `{"threadId":"<id>","includeTurns":true}`. Preserve each complete response line as raw bytes before deserializing a typed summary.

`ProcessTransport` spawns:

```text
codex app-server -c analytics.enabled=false --listen stdio://
```

It pipes stdin/stdout, caps each JSONL line at 16 MiB, ignores notifications while waiting for a matching response ID, treats malformed/oversized lines as typed errors, and terminates the child on drop. It never passes `--analytics-default-enabled`.

- [ ] **Step 6: Pin compatibility metadata**

Write `compat/matrix.toml`:

```toml
schema_version = 1

[[adapter]]
agent = "codex"
adapter_version = "0.1.0"
codex_cli_version = "0.146.0"
protocol = "app-server-v2"
schema_sha256 = "f766c650a2a2ea18bf9ddb8d82a87f74ecb0ab4ceb359a17b2e66d9d604f353f"
semantic_source = "app-server"
filesystem_source = "raw-only"
experimental_api = false
```

- [ ] **Step 7: Verify probe/protocol and commit**

```powershell
cargo test -p agentark-adapter-codex --test probe --test app_server_readonly
cargo clippy -p agentark-adapter-codex --all-targets -- -D warnings
git diff --check
git add -- schemas/codex/0.146.0 compat/matrix.toml crates/adapters/codex fixtures/codex/app-server
git commit -m "feat: probe Codex read-only app server"
```

### Task 12: Capture Codex files safely and normalize visible App Server history

**Files:**
- Create: `crates/adapters/codex/src/filesystem.rs`
- Create: `crates/adapters/codex/src/normalize.rs`
- Create: `crates/adapters/codex/src/adapter.rs`
- Modify: `crates/adapters/codex/src/lib.rs`
- Create: `fixtures/codex/filesystem/known-home/{sessions,archived_sessions}/`
- Create: `fixtures/codex/app-server/thread-read-visible.json`
- Create: `fixtures/codex/app-server/thread-read-reasoning.json`
- Test: `crates/adapters/codex/tests/filesystem_capture.rs`
- Test: `crates/adapters/codex/tests/normalization.rs`
- Test: `crates/adapters/codex/tests/conformance.rs`

**Interfaces:**
- Consumes: `AuthorizedRoot`, `ReadOnlyAppServerClient`, canonical IDs/models, and `SourceAdapter`.
- Produces: `CodexAdapter` implementing the complete read-only contract,
  `split_complete_jsonl_prefix(&[u8])`,
  `normalize_thread_read_bytes(&[u8])`, and linkage between App Server semantic
  records and filesystem raw evidence.

- [ ] **Step 1: Write failing stable-prefix tests**

Create fixture tests that:

- capture a complete JSONL file ending in `\n`;
- append another complete record after the initial file length and accept the earlier prefix;
- capture a length ending in the middle of a JSON value and return `Retryable("incomplete-final-record")`;
- replace the captured prefix and return `Retryable("source-changed")`;
- verify bytes, length, modification time, attributes, and fixture ACL are unchanged.

The test records access time separately and does not treat an OS read-induced access-time change as mutation.

- [ ] **Step 2: Implement stable read-only filesystem capture**

Detection recognizes an explicit root, `CODEX_HOME`, or the platform default only when `allow_detected_home` is true. Scanning considers only:

```text
<CODEX_HOME>/sessions/**/*.jsonl
<CODEX_HOME>/archived_sessions/**/*.jsonl
```

It never opens `auth.json`, `config.toml`, history files, databases, logs, keyrings, or any other root entry.

For every file, capture identity, length, modification time, attributes, and ACL evidence; read no byte beyond captured length; require a final newline; recheck identity and prefix hash. The source locator is relative to the authorized root. The thread ID is the filename stem only when it is a valid non-empty UTF-8 identifier; otherwise it is absent.

- [ ] **Step 3: Write failing visible-content and reasoning tests**

`normalization.rs` tests assert:

```rust
let visible = normalize_thread_read(include_str!(
    "../../../../fixtures/codex/app-server/thread-read-visible.json"
)).unwrap();
assert_eq!(visible.messages[0].role, CanonicalRole::User);
assert_eq!(visible.messages[1].role, CanonicalRole::Assistant);
assert!(visible.tool_events.iter().any(|event| event.tool_name == "commandExecution"));

let reasoning = normalize_thread_read(include_str!(
    "../../../../fixtures/codex/app-server/thread-read-reasoning.json"
)).unwrap();
assert!(!reasoning.messages.iter().any(|message| {
    message.visible_text().contains("HiddenReasoningCanary")
}));
assert!(!reasoning.searchable_text().contains("HiddenReasoningCanary"));
assert_eq!(reasoning.completeness, Completeness::Partial);
```

- [ ] **Step 4: Implement explicit item mapping**

Flatten turns in response order and items in each turn's array order. Increment one `u64` ordinal per visible message or tool event. Map:

| App Server item type | Canonical output |
|---|---|
| `userMessage` | `CanonicalMessage(User)`; text inputs only |
| `agentMessage` | `CanonicalMessage(Assistant)` |
| `commandExecution` | `ToolEvent` with visible command/output/status |
| `fileChange` | `ToolEvent` with visible paths/diff/status |
| `mcpToolCall` | `ToolEvent` with server/tool/status and sanitized visible result |
| `dynamicToolCall` | `ToolEvent` with name/status and visible content |
| `collabAgentToolCall` | `ToolEvent` with tool/status/agent IDs; never map its `prompt` field |
| `webSearch` | `ToolEvent` with query and visible result metadata |
| `imageView` / `imageGeneration` | attachment metadata only; never fetch a URL |
| `reasoning` | no canonical message/tool event; raw preserved and session marked partial |
| unknown type | no guessed entity; raw preserved and session marked partial |

Local image/audio paths become attachments only after authorized-root validation and local hashing. Remote URLs are not fetched; retain them only in encrypted raw data and mark the session partial.

Populate the `tool_events` and `attachments` fields already defined on
`CanonicalSession`, regenerate `schemas/canonical/v0.1.0.json`, and update its
round-trip tests in the same RED/GREEN cycle.

- [ ] **Step 5: Link semantic and raw sources without guessing**

`CodexAdapter::capture` obtains App Server thread responses and filesystem files. A filesystem record links to an App Server thread only when its validated filename stem exactly equals `thread.id`. Linked raw evidence does not make the session partial. Unlinked files return `Quarantined("raw-only-private-schema")`. Duplicate App Server/file content is stored once by CAS object ID but retains both source locators.

- [ ] **Step 6: Run full adapter conformance and commit**

```powershell
cargo test -p agentark-adapter-codex --test filesystem_capture --test normalization --test conformance
cargo test -p agentark-adapter-codex
cargo clippy -p agentark-adapter-codex --all-targets -- -D warnings
cargo run -p agentark-canonical --example write_schema -- schemas/canonical/v0.1.0.json
git diff --check
git add -- crates/canonical schemas/canonical/v0.1.0.json crates/adapters/codex fixtures/codex
git commit -m "feat: archive and normalize Codex sessions"
```

### Task 13: Expose the complete sanitized CLI workflow

**Files:**
- Create: `cli/src/args.rs`
- Create: `cli/src/output.rs`
- Create: `cli/src/runtime.rs`
- Modify: `cli/src/main.rs`
- Modify: `cli/Cargo.toml`
- Test: `cli/tests/cli_json.rs`
- Test: `cli/tests/cli_scan.rs`

**Interfaces:**
- Consumes: app services, Codex adapter, OS key store, SQLCipher index, and encrypted CAS.
- Produces commands `doctor`, `probe codex`, `scan codex`, `sessions list`, `sessions show`, `search`, and `verify` with versioned JSON envelopes.

- [ ] **Step 1: Write failing command-shape tests**

```rust
use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn help_lists_only_approved_read_only_commands() {
    Command::cargo_bin("agentark").unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("doctor"))
        .stdout(predicate::str::contains("probe"))
        .stdout(predicate::str::contains("scan"))
        .stdout(predicate::str::contains("sessions"))
        .stdout(predicate::str::contains("search"))
        .stdout(predicate::str::contains("verify"))
        .stdout(predicate::str::contains("delete").not())
        .stdout(predicate::str::contains("import").not());
}
```

- [ ] **Step 2: Write failing JSON and canary tests**

Run `doctor --json --data-dir <temp>` and assert:

```json
{
  "schemaVersion": 1,
  "ok": true,
  "command": "doctor",
  "data": {
    "datasetState": "notInitialized"
  },
  "warnings": []
}
```

Inject a synthetic error containing `CliSecretCanary` and assert stdout/stderr and serialized JSON contain neither the canary nor a backtrace.

- [ ] **Step 3: Run CLI tests and verify RED**

```powershell
cargo test -p agentark --test cli_json --test cli_scan
```

Expected: tests fail because clap commands and JSON output are absent.

- [ ] **Step 4: Implement exact clap arguments**

```rust
#[derive(Parser)]
#[command(name = "agentark", version, about = "Local read-only agent history archive")]
pub struct Cli {
    #[arg(long, global = true)]
    pub json: bool,
    #[arg(long, global = true, env = "AGENTARK_DATA_DIR")]
    pub data_dir: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    Doctor,
    Probe { #[command(subcommand)] agent: ProbeAgent },
    Scan(ScanArgs),
    Sessions { #[command(subcommand)] command: SessionsCommand },
    Search { query: String, #[arg(long, default_value_t = 50)] limit: u32 },
    Verify { #[arg(long)] scan_id: Option<Uuid> },
}

#[derive(Subcommand)]
pub enum ProbeAgent { Codex }

#[derive(Clone, Copy, ValueEnum)]
pub enum AgentArg { Codex }

#[derive(Subcommand)]
pub enum SessionsCommand {
    List {
        #[arg(long, default_value_t = 50)]
        limit: u32,
        #[arg(long, default_value_t = 0)]
        offset: u32,
    },
    Show { session_id: Uuid },
}

#[derive(Args)]
pub struct ScanArgs {
    #[arg(value_enum)]
    pub agent: AgentArg,
    #[arg(long, conflicts_with = "allow_detected_codex_home")]
    pub source_root: Option<PathBuf>,
    #[arg(long)]
    pub allow_detected_codex_home: bool,
}
```

Only `AgentArg::Codex` is public. Tests can select the synthetic adapter through a test-only runtime constructor, not a CLI flag.

- [ ] **Step 5: Wire runtime paths and dataset creation**

Default data root is `ProjectDirs::from("dev", "AgentArk", "AgentArk").data_local_dir()`. `--data-dir` overrides it for tests and explicit operation. `doctor` and `probe` do not create a dataset. The first authorized `scan` creates the bootstrap, OS master key, CAS root, and SQLCipher DB if absent. If creation fails, return a sanitized error and leave no plaintext fallback.

`scan codex` requires exactly one authorization mechanism: `--source-root` or `--allow-detected-codex-home`. Missing both returns exit code `2`.

- [ ] **Step 6: Implement output and exit contracts**

Every JSON response is:

```rust
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonEnvelope<T> {
    pub schema_version: u32,
    pub ok: bool,
    pub command: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<PublicError>,
    pub warnings: Vec<PublicWarning>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicError {
    pub code: &'static str,
    pub message: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicWarning {
    pub code: &'static str,
    pub message: &'static str,
}
```

Exit codes: `0` success, `2` invalid arguments or missing explicit authorization, `3` compatibility quarantine/partial result, `4` integrity verification failure, `5` storage/key failure. Human output uses the same sanitized DTOs.

Map typed internal errors to a fixed code/message table. Never place
`Error::source()`, a path, raw vendor text, SQL text, or keyring backend text in
`PublicError.message`.

- [ ] **Step 7: Run end-to-end CLI tests and commit**

`cli_scan.rs` runs an isolated synthetic-home scan twice and asserts one session revision, no duplicate message/object, successful list/show/search/verify, and zero canary leakage.

```powershell
cargo test -p agentark --test cli_json --test cli_scan
cargo test -p agentark
cargo clippy -p agentark --all-targets -- -D warnings
git diff --check
git add -- cli/Cargo.toml cli/src cli/tests
git commit -m "feat: expose read-only AgentArk CLI"
```

### Task 14: Add the minimal inert Tauri desktop viewer

**Files:**
- Create: `package.json`
- Create: `pnpm-workspace.yaml`
- Create: `pnpm-lock.yaml`
- Create: `apps/desktop/package.json`
- Create: `apps/desktop/index.html`
- Create: `apps/desktop/tsconfig.json`
- Create: `apps/desktop/vite.config.ts`
- Create: `apps/desktop/src/main.tsx`
- Create: `apps/desktop/src/api.ts`
- Create: `apps/desktop/src/App.tsx`
- Create: `apps/desktop/src/styles.css`
- Create: `apps/desktop/src/views/{StatusView,SessionsView,TimelineView,QuarantineView}.tsx`
- Create: `apps/desktop/src/components/VirtualTimeline.tsx`
- Create: `apps/desktop/src/test/setup.ts`
- Create: `apps/desktop/src/**/*.test.tsx`
- Create: `apps/desktop/tests/timeline-performance.spec.ts`
- Create: `apps/desktop/src-tauri/Cargo.toml`
- Create: `apps/desktop/src-tauri/build.rs`
- Create: `apps/desktop/src-tauri/tauri.conf.json`
- Create: `apps/desktop/src-tauri/capabilities/default.json`
- Create: `apps/desktop/src-tauri/src/{commands,state,lib,main}.rs`
- Create: `apps/desktop/src-tauri/icons/*`
- Modify: `Cargo.toml`

**Interfaces:**
- Consumes: read-only `AppServices` query/status functions.
- Produces Tauri commands `status`, `sessions_list`, `sessions_show`, `search`, and `quarantines_list` plus four React views.

- [ ] **Step 1: Add exact frontend and Tauri manifests as configuration exceptions**

Root `package.json`:

```json
{
  "name": "agentark-workspace",
  "private": true,
  "packageManager": "pnpm@11.22.0",
  "engines": { "node": ">=24 <25", "pnpm": "11.22.0" },
  "scripts": {
    "desktop:dev": "pnpm --dir apps/desktop tauri dev",
    "desktop:build": "pnpm --dir apps/desktop tauri build",
    "desktop:test": "pnpm --dir apps/desktop test"
  }
}
```

`pnpm-workspace.yaml`:

```yaml
packages:
  - apps/desktop
```

`apps/desktop/package.json` pins:

```json
{
  "name": "@agentark/desktop",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc -b && vite build",
    "test": "vitest run",
    "tauri": "tauri"
  },
  "dependencies": {
    "@tauri-apps/api": "2.11.1",
    "react": "19.2.8",
    "react-dom": "19.2.8"
  },
  "devDependencies": {
    "@playwright/test": "1.62.1",
    "@tauri-apps/cli": "2.11.4",
    "@testing-library/jest-dom": "7.0.1",
    "@testing-library/react": "16.3.2",
    "@types/react": "19.2.18",
    "@types/react-dom": "19.2.4",
    "@vitejs/plugin-react": "6.1.0",
    "jsdom": "30.0.1",
    "typescript": "7.0.2",
    "vite": "8.2.2",
    "vitest": "4.1.11"
  }
}
```

These exact package versions were verified against the npm registry on
2026-08-20. `pnpm install` must resolve them without substitution; a resolution
failure blocks Task 14 and requires a reviewed plan amendment.

Add `apps/desktop/src-tauri` as a workspace member. Its Rust package is `agentark-desktop` and depends on `agentark-app`, `agentark-index`, `agentark-security`, `serde`, `tracing`, and `tauri` through workspace dependencies.

- [ ] **Step 2: Generate platform icons from the supplied asset**

Run from `apps/desktop`:

```powershell
pnpm install --no-frozen-lockfile
pnpm tauri icon ../../AgentArk.png
```

Expected: Tauri generates PNG sizes, `icon.ico`, and `icon.icns` beneath `src-tauri/icons`. Visually inspect the 32x32 and 128x128 PNG files for recognizable shape and transparent background before committing.

- [ ] **Step 3: Write failing Rust command-boundary tests**

In `commands.rs` tests, build a fake `AppServices` and assert:

```rust
#[test]
fn commands_expose_only_sanitized_query_dtos() {
    let state = fixture_state_with_secret("DesktopSecretCanary");
    let sessions = sessions_list_inner(&state, 50, 0).unwrap();
    let json = serde_json::to_string(&sessions).unwrap();
    assert!(!json.contains("DesktopSecretCanary"));
}

#[test]
fn no_mutating_command_is_registered() {
    assert_eq!(
        REGISTERED_COMMANDS,
        ["status", "sessions_list", "sessions_show", "search", "quarantines_list"]
    );
}
```

- [ ] **Step 4: Implement thin Tauri state and commands**

`AppState` contains an `Arc<Mutex<AppServices>>`. Each `#[tauri::command]` delegates immediately to an `*_inner` function returning a sanitized serializable DTO. Do not expose `PathBuf` source locators, SQLCipher handles, CAS paths, raw JSON, or key types.

`lib.rs` registers only:

```rust
tauri::generate_handler![
    commands::status,
    commands::sessions_list,
    commands::sessions_show,
    commands::search,
    commands::quarantines_list,
]
```

- [ ] **Step 5: Lock down Tauri configuration**

Use identifier `dev.agentark.desktop`, a single 1200x760 window, no updater, no shell plugin, no HTTP plugin, and no external binary. `capabilities/default.json` grants only `core:default` to window `main`.

Set CSP:

```text
default-src 'self'; connect-src ipc: http://ipc.localhost; img-src 'self' asset: data:; style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; frame-src 'none'
```

Do not add `dangerousRemoteDomainIpcAccess`, remote URLs, navigation allowlists, or filesystem permissions.

- [ ] **Step 6: Write failing React view tests**

Mock `@tauri-apps/api/core.invoke`. Tests must prove:

- Status view renders dataset lock state and adapter capability/fingerprint.
- Sessions view searches and selects a session.
- Timeline renders user/assistant/tool rows as text.
- Quarantine view renders reason code, fingerprint, and sanitized locator.
- A message containing `<img src=x onerror=DesktopXssCanary>` appears as literal text and creates no `img` element.
- No component uses `dangerouslySetInnerHTML`.

Run:

```powershell
pnpm --dir apps/desktop test
```

Expected: tests fail before the views exist.

- [ ] **Step 7: Implement API DTOs and four views**

`api.ts` exports one typed function per registered command. `App.tsx` has four navigation tabs and keeps the selected session ID in component state. It never stores raw record bytes.

`VirtualTimeline` uses a fixed 72-pixel estimated row height, a 10-row overscan, scrollTop/clientHeight calculations, and absolutely positioned visible rows. It receives already sanitized DTOs and renders all content through ordinary React text nodes.

- [ ] **Step 8: Add the 10,000-message first-viewport benchmark test**

Create 10,000 fixed-size fixture messages, render `VirtualTimeline` at a 720-pixel viewport, and assert fewer than 40 rows are mounted. A Playwright benchmark records from navigation to first non-empty timeline paint and writes JSON evidence. On the 8-core/16-GB/NVMe baseline, p95 across 20 warm runs must be at most 500 ms.

`timeline-performance.spec.ts` runs 20 page reloads against a Vite fixture route,
collects `performance.now()` from navigation start to the first
`[data-timeline-row]`, sorts the samples, writes only timings/counts to
`target/agentark-bench/timeline.json`, and fails when sample index 18 exceeds
500 ms.

- [ ] **Step 9: Build, test, and commit desktop**

```powershell
pnpm --dir apps/desktop test
pnpm --dir apps/desktop build
cargo test -p agentark-desktop
cargo clippy -p agentark-desktop --all-targets -- -D warnings
pnpm --dir apps/desktop tauri build --debug --no-bundle
git diff --check
git add -- package.json pnpm-workspace.yaml pnpm-lock.yaml Cargo.toml Cargo.lock apps/desktop
git commit -m "feat: add read-only AgentArk desktop"
```

### Task 15: Enforce threat-model, fuzz, CI, performance, and final M0 gates

**Files:**
- Create: `docs/adr/0001-read-only-source-boundary.md`
- Create: `docs/adr/0002-exact-raw-sanitized-search.md`
- Create: `docs/adr/0003-dataset-key-hierarchy.md`
- Create: `docs/adr/0004-canonical-hashing.md`
- Create: `docs/adr/0005-source-snapshot-semantics.md`
- Create: `docs/adr/0006-tauri-ipc-boundary.md`
- Create: `threat-model/m0.md`
- Create: `deny.toml`
- Create: `fuzz/Cargo.toml`
- Create: `fuzz/fuzz_targets/codex_jsonl.rs`
- Create: `fuzz/fuzz_targets/path_policy.rs`
- Create: `crates/index/benches/search.rs`
- Create: `ci/check-no-secret-canaries.ps1`
- Create: `ci/check-no-forbidden-codex-methods.ps1`
- Create: `ci/check-security-crate-majors.ps1`
- Create: `ci/enforce-search-benchmark.ps1`
- Create: `ci/network-silence.sh`
- Create: `.github/workflows/ci.yml`
- Create: `.github/workflows/nightly.yml`
- Modify: `crates/index/Cargo.toml`
- Test: `crates/app/tests/m0_end_to_end.rs`

**Interfaces:**
- Consumes: every prior task.
- Produces: repeatable evidence for all four specification gates and a clean final-review package.

- [ ] **Step 1: Write the six accepted ADRs**

Each ADR contains `Status: Accepted`, context, decision, consequences, and rejected alternatives. Record these exact decisions:

1. Source and target adapter traits are separated; M0 compiles no target trait.
2. Exact encrypted raw data coexists with sanitized search/preview projections.
3. OS master key wraps per-dataset keys; no plaintext fallback.
4. RFC 8785 plus domain-separated SHA-256 defines canonical hashes.
5. Stable-prefix capture accepts append-only growth but rejects prefix changes/incomplete records.
6. Tauri exposes only five sanitized query commands and inert text rendering.

- [ ] **Step 2: Write the M0 threat model**

`threat-model/m0.md` lists assets, trust boundaries, attacker capabilities, controls, evidence tests, and residual risk for:

- malicious transcript/JSON/Markdown/HTML;
- JSONL concurrent append and replacement;
- path traversal, UNC, device path, ADS, symlink, junction, and reparse points;
- source database/WAL mutation;
- credential files and transcript-embedded secrets;
- stolen local dataset;
- tampered CAS/index/bootstrap;
- App Server schema drift and hostile JSON-RPC lines;
- Tauri IPC/XSS/navigation;
- retry duplication and partial scan publication;
- unintended network egress.

Every threat references at least one concrete test file and one typed failure/outcome.

- [ ] **Step 3: Add dependency and license policy**

`deny.toml` denies known vulnerabilities, unmaintained/yanked crates, unknown registries, git dependencies, copyleft licenses not explicitly approved, and duplicate major versions of security-critical crates (`chacha20poly1305`, `sha2`, `rusqlite`, `zeroize`). Allow Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC, Unicode-3.0, OpenSSL, and Zlib.

Write:

```toml
[graph]
all-features = true
targets = [
  "x86_64-pc-windows-msvc",
  "x86_64-unknown-linux-gnu",
  "aarch64-unknown-linux-gnu",
  "x86_64-apple-darwin",
  "aarch64-apple-darwin",
]

[advisories]
yanked = "deny"
unmaintained = "workspace"

[bans]
multiple-versions = "warn"
wildcards = "deny"
highlight = "all"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = [
  "https://github.com/rust-lang/crates.io-index",
  "sparse+https://index.crates.io/",
]

[licenses]
confidence-threshold = 0.93
unused-allowed-license = "allow"
allow = [
  "Apache-2.0",
  "Apache-2.0 WITH LLVM-exception",
  "MIT",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "ISC",
  "Unicode-3.0",
  "OpenSSL",
  "Zlib",
]

[licenses.private]
ignore = true
```

Because Tauri's graph can legitimately contain duplicate utility crates,
`multiple-versions` is a warning globally. `check-security-crate-majors.ps1`
hard-fails when `cargo metadata --locked` contains more than one major version
for `chacha20poly1305`, `sha2`, `rusqlite`, or `zeroize`:

```powershell
$critical = @('chacha20poly1305', 'sha2', 'rusqlite', 'zeroize')
$metadata = cargo metadata --locked --format-version 1 | ConvertFrom-Json
foreach ($name in $critical) {
    $majors = @(
        $metadata.packages |
            Where-Object name -eq $name |
            ForEach-Object { ([version]$_.version).Major } |
            Sort-Object -Unique
    )
    if ($majors.Count -gt 1) {
        throw "$name has multiple major versions: $($majors -join ',')"
    }
}
```

Install exact tools:

```powershell
cargo install --locked cargo-deny --version 0.20.2
cargo install --locked cargo-audit --version 0.22.2
cargo install --locked cargo-nextest --version 0.9.143
cargo install --locked cargo-fuzz --version 0.13.2
```

- [ ] **Step 4: Write fuzz targets**

`codex_jsonl.rs` calls the stable-prefix record splitter and App Server item decoder inside `std::panic::catch_unwind`; any panic fails the target. It asserts normalization never emits a canonical message for an item whose type is `reasoning`.

`path_policy.rs` interprets arbitrary bytes as lossy UTF-8 and feeds both `classify_windows_path` and lexical relative-path validation. It asserts no classified UNC/device/ADS/traversal path returns `Local`.

Seed corpora include truncated JSONL, incomplete UTF-8, equal timestamps, unknown roles/items, giant tool output boundary cases, CRLF/LF, UNC/device/ADS strings, and credential canaries.

`fuzz/Cargo.toml` is:

```toml
[package]
name = "agentark-fuzz"
version = "0.0.0"
publish = false
edition = "2024"

[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "=0.4.13"
agentark-security = { path = "../crates/security" }
agentark-adapter-codex = { path = "../crates/adapters/codex" }

[[bin]]
name = "codex_jsonl"
path = "fuzz_targets/codex_jsonl.rs"
test = false
doc = false
bench = false

[[bin]]
name = "path_policy"
path = "fuzz_targets/path_policy.rs"
test = false
doc = false
bench = false
```

`codex_jsonl.rs`:

```rust
#![no_main]

use std::panic::{AssertUnwindSafe, catch_unwind};

use agentark_adapter_codex::{normalize_thread_read_bytes, split_complete_jsonl_prefix};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    assert!(catch_unwind(AssertUnwindSafe(|| {
        let _ = split_complete_jsonl_prefix(data);
        if let Ok(session) = normalize_thread_read_bytes(data) {
            assert!(!session.searchable_text().contains("HiddenReasoningCanary"));
        }
    }))
    .is_ok());
});
```

`path_policy.rs`:

```rust
#![no_main]

use agentark_security::{PathClass, classify_windows_path, validate_relative_lexical};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let value = String::from_utf8_lossy(data);
    let class = classify_windows_path(&value);
    let accepted = validate_relative_lexical(value.as_ref()).is_ok();
    if matches!(
        class,
        PathClass::Unc | PathClass::Device | PathClass::AlternateDataStream | PathClass::Traversal
    ) {
        assert!(!accepted);
    }
});
```

- [ ] **Step 5: Add the search performance benchmark**

`crates/index/benches/search.rs` is a harness-free benchmark. It creates
100,000 sessions and 1,000,000 message parts with deterministic synthetic text
through the public ingest API, warms the query five times, and measures 100
top-50 FTS searches:

```rust
fn main() {
    let (_temp, mut db) = seeded_db(100_000, 10);
    for _ in 0..5 {
        db.search("deterministic needle", 50).unwrap();
    }
    let mut samples_ms = (0..100)
        .map(|_| {
            let started = std::time::Instant::now();
            let hits = db.search("deterministic needle", 50).unwrap();
            assert_eq!(hits.len(), 50);
            started.elapsed().as_secs_f64() * 1_000.0
        })
        .collect::<Vec<_>>();
    samples_ms.sort_by(f64::total_cmp);
    let result = BenchResult {
        sessions: 100_000,
        message_parts: 1_000_000,
        p50_ms: samples_ms[49],
        p95_ms: samples_ms[94],
    };
    write_sanitized_result("target/agentark-bench/search.json", &result);
    if std::env::var_os("AGENTARK_ENFORCE_BENCH").is_some() && result.p95_ms > 150.0 {
        std::process::exit(1);
    }
}
```

`seeded_db` uses fixed UUIDv5 identities, fixed text, an in-memory test master
key, a temporary SQLCipher file, and batches of 1,000 session transactions.
`BenchResult` contains only counts and timings. Add:

```toml
[[bench]]
name = "search"
harness = false
```

to `crates/index/Cargo.toml`. `enforce-search-benchmark.ps1` sets
`AGENTARK_ENFORCE_BENCH=1`, runs `cargo bench -p agentark-index --bench search`,
and checks the JSON p95 is at most `150.0`.

- [ ] **Step 6: Write the full failing M0 end-to-end test**

`m0_end_to_end.rs` performs:

```text
synthetic authorized root
  -> probe
  -> exact raw archive
  -> normalize
  -> sanitized index
  -> list/show/search
  -> second identical scan
  -> verify
  -> tamper one copied dataset
  -> verify failure on the copy
```

Assert source bytes/length/mtime/attributes are unchanged, second scan has no duplicate entities/objects, secret and reasoning canaries are absent from every non-secret sink, and the untampered verification report passes.

- [ ] **Step 7: Implement CI canary and forbidden-method scripts**

`check-no-secret-canaries.ps1` recursively searches test outputs, logs, UI dist files, SQLite fixture dumps, and JSON reports for every value in `fixtures/security/vendor-token-canaries.json` and exits 1 on a match outside the encrypted test-object directory.

`check-no-forbidden-codex-methods.ps1` searches AgentArk production Rust code for these string literals and exits 1 if found:

```text
thread/start
thread/resume
thread/archive
thread/unarchive
thread/delete
thread/metadata/update
turn/start
command/exec
process/spawn
```

The script excludes test fixtures that intentionally assert absence.

Implement `check-no-secret-canaries.ps1` as:

```powershell
$canaries = Get-Content -LiteralPath 'fixtures/security/vendor-token-canaries.json' -Raw |
    ConvertFrom-Json
$roots = @(
    'target/agentark-test-artifacts',
    'target/agentark-bench',
    'apps/desktop/dist'
) | Where-Object { Test-Path -LiteralPath $_ }
foreach ($root in $roots) {
    foreach ($entry in $canaries) {
        $matches = @(& rg -a -l -F --glob '!encrypted-objects/**' -- $entry.value $root)
        if ($LASTEXITCODE -eq 0 -and $matches.Count -gt 0) {
            throw "Secret canary $($entry.class) found in $($matches -join ', ')"
        }
        if ($LASTEXITCODE -notin @(0, 1)) {
            throw "rg failed while scanning $root"
        }
    }
}
```

Implement `check-no-forbidden-codex-methods.ps1` as:

```powershell
$forbidden = @(
    'thread/start', 'thread/resume', 'thread/archive', 'thread/unarchive',
    'thread/delete', 'thread/metadata/update', 'turn/start', 'command/exec',
    'process/spawn'
)
$files = @(& rg --files crates/adapters/codex/src)
foreach ($method in $forbidden) {
    $hits = @(Select-String -LiteralPath $files -SimpleMatch -Pattern $method)
    if ($hits.Count -gt 0) {
        throw "Forbidden Codex method $method found at $($hits.Path -join ', ')"
    }
}
```

Run `check-security-crate-majors.ps1` from Step 3 beside both scripts.

- [ ] **Step 8: Add the Linux network-silence harness**

`ci/network-silence.sh` runs the synthetic end-to-end CLI inside:

```bash
unshare --user --map-root-user --net \
  env HTTP_PROXY= HTTPS_PROXY= ALL_PROXY= NO_PROXY= \
  cargo test -p agentark-app --test m0_end_to_end -- --exact local_only_has_zero_egress
```

The test binds no socket and uses the synthetic adapter. CI treats an unavailable user/network namespace as a failed prerequisite, not a skipped gate. The real Codex live probe remains separately authorized and is not run in public CI.

- [ ] **Step 9: Create deterministic cross-platform CI**

`ci.yml` runs on `pull_request` and `push` with `windows-latest`, `ubuntu-latest`, and `macos-latest`. It pins Rust `1.97.1`, Node `24`, pnpm `11.22.0`, and runs:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo nextest run --workspace --all-features
cargo test --workspace --doc
cargo deny check
cargo audit
pnpm install --frozen-lockfile
pnpm --dir apps/desktop test
pnpm --dir apps/desktop build
cargo test -p agentark-desktop
ci/check-no-secret-canaries.ps1
ci/check-no-forbidden-codex-methods.ps1
```

Ubuntu installs Tauri's documented WebKitGTK, appindicator, SSL, SVG, patchelf, and build dependencies before desktop compilation. A separate Ubuntu job runs `ci/network-silence.sh`.

`nightly.yml` runs the two fuzz targets for 15 minutes each, the large FTS benchmark, the 10,000-message UI benchmark, and the dependency audits. It uploads only sanitized benchmark and failure reports.

Use this CI structure:

```yaml
name: ci
on:
  pull_request:
  push:
permissions:
  contents: read

jobs:
  test:
    strategy:
      fail-fast: false
      matrix:
        os: [windows-latest, ubuntu-latest, macos-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - if: runner.os == 'Linux'
        run: |
          sudo apt-get update
          sudo apt-get install -y libwebkit2gtk-4.1-dev build-essential curl wget file \
            libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev patchelf
      - uses: dtolnay/rust-toolchain@stable
        with:
          toolchain: 1.97.1
          components: rustfmt, clippy
      - uses: actions/setup-node@v4
        with:
          node-version: 24
          cache: pnpm
      - uses: pnpm/action-setup@v4
        with:
          version: 11.22.0
          run_install: false
      - run: cargo install --locked cargo-nextest --version 0.9.143
      - run: cargo install --locked cargo-deny --version 0.20.2
      - run: cargo install --locked cargo-audit --version 0.22.2
      - run: pnpm install --frozen-lockfile
      - run: cargo fmt --all -- --check
      - run: cargo clippy --workspace --all-targets --all-features -- -D warnings
      - run: cargo nextest run --workspace --all-features
      - run: cargo test --workspace --doc
      - run: cargo deny check
      - run: cargo audit
      - run: pwsh -File ci/check-security-crate-majors.ps1
      - run: pnpm --dir apps/desktop test
      - run: pnpm --dir apps/desktop build
      - run: cargo test -p agentark-desktop
      - run: pwsh -File ci/check-no-secret-canaries.ps1
      - run: pwsh -File ci/check-no-forbidden-codex-methods.ps1

  network-silence:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          toolchain: 1.97.1
      - run: cargo fetch --locked
      - run: bash ci/network-silence.sh
```

`nightly.yml` uses `nightly-2026-08-20` only for cargo-fuzz and Rust `1.97.1`
for benchmarks:

```yaml
name: nightly
on:
  schedule:
    - cron: "17 3 * * *"
  workflow_dispatch:
permissions:
  contents: read
jobs:
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
        with:
          toolchain: nightly-2026-08-20
      - run: cargo install --locked cargo-fuzz --version 0.13.2
      - run: cargo fuzz run codex_jsonl -- -max_total_time=900
      - run: cargo fuzz run path_policy -- -max_total_time=900
  performance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          toolchain: 1.97.1
      - uses: actions/setup-node@v4
        with:
          node-version: 24
      - uses: pnpm/action-setup@v4
        with:
          version: 11.22.0
      - run: pnpm install --frozen-lockfile
      - run: pwsh -File ci/enforce-search-benchmark.ps1
      - run: pnpm --dir apps/desktop exec playwright install --with-deps chromium
      - run: pnpm --dir apps/desktop exec playwright test tests/timeline-performance.spec.ts
```

- [ ] **Step 10: Run the complete local verification gate**

Run fresh:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo test --workspace --doc
cargo deny check
cargo audit
pwsh -File ci/check-security-crate-majors.ps1
pnpm install --frozen-lockfile
pnpm --dir apps/desktop test
pnpm --dir apps/desktop build
cargo test -p agentark-desktop
pnpm --dir apps/desktop tauri build --debug --no-bundle
pwsh -File ci/enforce-search-benchmark.ps1
pnpm --dir apps/desktop exec playwright install chromium
pnpm --dir apps/desktop exec playwright test tests/timeline-performance.spec.ts
pwsh -File ci/check-no-secret-canaries.ps1
pwsh -File ci/check-no-forbidden-codex-methods.ps1
git diff --check
git status --short
```

Expected: every command exits 0. `git status --short` lists only Task 15 paths before the commit.

- [ ] **Step 11: Commit release gates**

```powershell
git add -- docs/adr threat-model deny.toml fuzz crates/index/Cargo.toml crates/index/benches ci .github/workflows crates/app/tests/m0_end_to_end.rs Cargo.lock
git commit -m "test: enforce AgentArk M0 release gates"
```

- [ ] **Step 12: Request final whole-branch review**

Generate the final review package from the implementation branch base through
`HEAD`. The reviewer checks the complete spec, this plan, deferred-minor
ledger, source-nonmutation evidence, secret/reasoning canaries, dependency
policy, and every verification command. Fix all Critical and Important
findings inline, rerun their covering tests, and obtain one scoped re-review
before branch completion.

## Plan Coverage Matrix

| Specification requirement | Implemented by |
|---|---|
| Read-only architecture and split adapter traits | Tasks 1, 9, 11, 12 |
| Stable IDs, order, unknown/raw preservation | Tasks 2, 3, 9, 12 |
| Authorized roots and hostile paths | Tasks 4, 12, 15 |
| Exact encrypted raw CAS | Tasks 6, 7, 10 |
| SQLCipher and sanitized FTS | Tasks 5, 6, 8 |
| Archive-before-normalize scan semantics | Task 10 |
| Codex 0.146.0 capability/fingerprint gate | Tasks 11, 12 |
| No hidden reasoning | Tasks 3, 10, 12, 15 |
| CLI workflows and JSON contract | Task 13 |
| Four inert desktop views and supplied icon | Task 14 |
| Source nonmutation, idempotence, quarantine | Tasks 9, 10, 12, 15 |
| Cross-platform/security/fuzz/performance gates | Tasks 14, 15 |

## Execution Notes

- The controller creates the isolated worktree and progress ledger before Task 1.
- Implementation runs inline in the current session; no implementation task is
  delegated to a subagent.
- Independent read-only review agents may be used only after Tasks 6, 10, 13,
  and 15, corresponding to Gates 1 through 4.
- A Gate with a Critical or Important finding does not advance until the inline
  fix passes its covering tests and a scoped re-review is clean.
- The first real Codex live probe is a separate side effect requiring explicit user authorization; all default implementation and CI work uses synthetic/redacted fixtures.
- Local commits are required by the task boundaries. Pushing remains separately authorized and is not part of this plan.
