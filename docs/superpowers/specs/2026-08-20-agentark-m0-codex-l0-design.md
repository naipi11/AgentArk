# AgentArk M0 Codex L0 Read-Only Vertical Design

**Status:** Approved design
**Date:** 2026-08-20
**Product:** AgentArk
**Source plan:** `AgentArk.md`
**Target milestone:** M0 plus the first Codex L0 read-only vertical

## 1. Purpose

AgentArk is a local-first control plane for discovering, preserving, indexing,
and eventually migrating histories produced by coding agents. This design
covers the smallest safe product slice: an encrypted, searchable, read-only
archive of Codex history with explicit provenance and fail-closed compatibility
handling.

This slice proves the principles that every later adapter, bundle, migration,
and synchronization feature depends on:

- Vendor persistence is an external source and is never modified.
- Vendor-specific types stop at the adapter boundary.
- Raw evidence is preserved before normalization.
- Unknown schemas are archived and quarantined rather than guessed.
- Supported visible content, ordering, and hashes are verified.
- Credentials never become AgentArk data.
- Local-only mode produces no intentional network traffic.

The product name is `AgentArk`. Code packages use the `agentark-*` prefix. The
`.ahbundle` format described by the source plan is reserved for a later
milestone and is not implemented here.

## 2. Scope

### 2.1 Included

- A Rust workspace with a canonical model and read-only adapter SDK.
- Security primitives for authorized roots, path containment, secret
  classification, and safe rendering.
- An encrypted content-addressed store for immutable raw records.
- A SQLCipher database with FTS5 for metadata, canonical content, and search.
- A synthetic adapter and fixture harness.
- A Codex adapter with version and schema fingerprint probing.
- Exact raw archival of authorized Codex session logs.
- Semantic indexing only for known, verified Codex schemas or stable App
  Server responses.
- CLI commands for diagnosis, probing, scanning, querying, and verification.
- A minimal Tauri 2 and React read-only desktop surface after the CLI gates
  pass.
- Windows, Linux, and macOS fixture-based CI.

### 2.2 Excluded

- Any write to Codex or another vendor's state.
- Target adapters, native resume, or L1/L2/L3 migration execution.
- `.ahbundle` export or restore.
- Watchers, background daemons, reconciliation scheduling, LAN synchronization,
  cloud relay, and multi-user server mode.
- Import rollback, cross-device conflicts, update channels, installers, and
  release signing.
- Collection or transfer of OAuth tokens, API keys, cookies, keychain entries,
  or other credential values.
- Hidden reasoning or other non-user-visible model internals.

No excluded capability may be added under a feature flag in this milestone.
Write-capable adapter traits are intentionally absent from the build.

## 3. Architecture

```text
Codex App Server / authorized read-only files
                    |
             adapter-codex
                    |
          canonical + adapter-sdk
                    |
       security / encrypted CAS / index
                    |
           application services
               /           \
             CLI        Tauri/React
```

The Rust core is the only source of product behavior. CLI and Tauri are thin
clients over application services. UI commands do not access SQLite, CAS,
vendor files, or adapters directly.

### 3.1 Repository layout

```text
crates/
  canonical/
  adapter-sdk/
  security/
  cas/
  index/
  app/
  adapters/
    synthetic/
    codex/
cli/
apps/
  desktop/
fixtures/
  synthetic/
  codex/
schemas/
  canonical/
  codex/
compat/
  matrix.toml
docs/
  adr/
  superpowers/specs/
threat-model/
ci/
```

### 3.2 Module responsibilities

| Module | Responsibility | Must not do |
|---|---|---|
| `canonical` | Versioned vendor-neutral entities, stable IDs, canonical hashes, invariants | Read files, call vendors, store data |
| `adapter-sdk` | Read-only source contract, capabilities, fingerprints, fixture conformance | Define target writes |
| `security` | Authorized roots, path policy, redaction projection, safe rendering | Persist plaintext secrets |
| `cas` | Encrypt, address, retrieve, and verify immutable raw objects | Interpret vendor records |
| `index` | SQLCipher schema, FTS5 projection, transactions, queries | Know vendor schemas |
| `app` | Orchestrate probe, scan, verify, and query use cases | Expose storage handles |
| `adapter-synthetic` | Deterministic contract fixtures | Access user data |
| `adapter-codex` | Codex detection, probing, raw capture, normalization | Modify Codex state or read credential stores |
| `cli` | Stable human and JSON command output | Contain business logic |
| `desktop` | Read-only product views through Tauri commands | Execute arbitrary SQL or adapter code |

## 4. Read-only adapter contract

The first milestone exposes only a `SourceAdapter` contract:

```rust
pub trait SourceAdapter: Send + Sync {
    fn id(&self) -> &'static str;
    fn detect(&self, ctx: &DetectContext) -> Result<Vec<AgentInstall>>;
    fn probe(&self, install: &AgentInstall) -> Result<ProbeReport>;
    fn capture(&self, request: &CaptureRequest) -> Result<CaptureBatch>;
    fn normalize(&self, record: &CapturedRecord) -> Result<NormalizeOutcome>;
    fn capabilities(&self, install: &AgentInstall) -> SourceCapabilitySet;
}
```

`NormalizeOutcome` is one of:

- `Normalized`: a verified canonical entity plus its raw reference.
- `Quarantined`: raw evidence was archived but semantic interpretation is
  blocked.
- `Retryable`: a stable source snapshot was not available.
- `Rejected`: the record violated an authorization, path, or integrity rule.

`TargetAdapter`, import planning, and import execution do not exist in this
workspace until a later approved design introduces them.

## 5. Canonical model

### 5.1 Required entities

- `Machine`: a locally generated device UUID and platform family.
- `AgentInstall`: agent kind, executable version, authorized root identity,
  adapter version, schema fingerprint, and source capabilities.
- `Workspace`: native path, canonical file URI, and optional Git provenance.
- `Session`: canonical ID, vendor session ID, workspace, timestamps, title,
  archived state, source kind, completeness, and model provenance.
- `Message`: stable ID, immutable ordinal, canonical role, raw role, visible
  content parts, timestamps, and raw record reference.
- `ToolCall` and `ToolResult`: visible lifecycle data without replay semantics.
- `Attachment`: authorized locator, media metadata, size, and content hash.
- `SourceRecord`: source locator, source record ID when present, raw SHA-256,
  CAS object ID, adapter version, and capture snapshot.
- `ScanRun`: source snapshot, counts by outcome, warnings, start/end time, and
  completion state.
- `Quarantine`: reason code, fingerprint, source reference, and diagnostics
  without raw secret values.
- `SecretFinding`: secret class, confidence, and sanitized location only.

### 5.2 Stable identity

- `machine_id` is a random UUID created once per AgentArk installation.
- `agent_install_id` is UUIDv5 over the AgentArk install namespace, agent kind,
  machine ID, and authorized canonical root.
- `session_id` is UUIDv5 over `agent_install_id` and the unmodified vendor
  session ID.
- A message uses the vendor record ID when available. Otherwise its identity is
  UUIDv5 over session ID, ordinal, and raw record SHA-256.
- Equal timestamps never participate in ordering. `ordinal` is authoritative.
- Duplicate visible text remains distinct when ordinals or source IDs differ.

### 5.3 Canonical hashing

Canonical hashes use RFC 8785 JSON Canonicalization Scheme bytes and SHA-256.
Hash inputs are domain separated:

```text
agentark:v1:<entity-type>:<canonical-json-bytes>
```

Canonical values do not contain floating-point numbers. Timestamps are either
the untouched raw value or a normalized RFC 3339 value with an explicit parse
status. A schema version change that changes hashing semantics requires a new
hash domain.

Unknown roles and fields are stored in `raw_role` and `raw_extra`. The complete
source bytes remain in the encrypted CAS even when normalization succeeds.

## 6. Storage and key design

### 6.1 Dataset keys

Each local dataset receives a random 256-bit data key. HKDF-SHA-256 derives
independent keys using fixed context labels:

- `agentark-v1-sqlcipher`
- `agentark-v1-cas-aead`
- `agentark-v1-object-id`
- `agentark-v1-key-wrap`

A random 256-bit device master key is stored by the operating-system credential
facility selected for each platform:

- Windows: Windows Credential Manager.
- macOS: Keychain.
- Linux: Secret Service.

The dataset key is wrapped with the device master key. If the required
credential facility is unavailable, persistent storage fails closed. There is
no plaintext key file or plaintext database fallback.

Key material uses secret-memory wrappers and is zeroized when released.
Locking a dataset closes SQLCipher connections, clears caches, and releases
keys. The plaintext bootstrap contains only format version, dataset UUID, and
wrapped-key metadata; it contains no source path, session title, message,
account identifier, or count.

### 6.2 SQLCipher index

The index is SQLCipher Community Edition with FTS5 enabled. It stores canonical
entities, provenance, scan manifests, compatibility results, and a sanitized
search projection. SQLCipher also protects its journal and WAL state.

FTS5 never receives a high-confidence secret value. Secret spans are replaced
with `[REDACTED:<class>]` in search text and previews. Full visible text remains
available only inside encrypted canonical tables.

### 6.3 Encrypted CAS

CAS objects use XChaCha20-Poly1305 with a random 192-bit nonce. Associated data
contains the format version, dataset UUID, object type, and keyed object ID.
The object ID is HMAC-SHA-256 over the plaintext SHA-256 using the derived
object-ID key. This prevents local filenames from exposing a bare known-content
digest.

Write order is:

1. Write the encrypted object to a same-volume temporary file.
2. Flush the file and containing directory where the platform permits it.
3. Atomically rename the object to its final keyed path.
4. Commit canonical references in one SQLCipher transaction.

A crash can leave an unreferenced encrypted object but cannot commit a reference
to a missing object. Garbage collection deletes an orphan only after a complete
reference scan and a retention interval in a later maintenance run.

## 7. Secret policy

Known credential sources such as `auth.json`, OS keychains, cookie stores,
`.env` files, and provider credential databases are excluded before file
opening. Their paths may be reported as excluded categories without exposing
values.

User-visible transcripts and tool output can themselves contain credentials.
To preserve the L0 exact-archive contract:

- Exact source bytes are retained only in encrypted CAS.
- Full visible canonical text is retained only in SQLCipher.
- A deterministic secret scanner produces a separately sanitized FTS and
  preview projection.
- Logs, errors, metrics, audit data, CLI JSON diagnostics, and UI previews use
  sanitized values.
- Secret tests use canary values and assert absence from every non-secret sink.

The first scanner version has a fixed, versioned rule registry. It redacts PEM
private-key blocks, URI user-info credentials, authorization and cookie header
values, values under case-insensitive structured keys named `token`,
`access_token`, `refresh_token`, `api_key`, `secret`, `password`, or
`authorization`, and high-confidence vendor token formats represented by
synthetic fixtures. It does not redact on entropy alone. Every rule records a
class and rule version without retaining the matched value.

The later portable-export design must offer a sanitized default and require
explicit confirmation plus encryption for exact L0 export. This milestone does
not export data.

## 8. Codex integration

### 8.1 Supported source surfaces

The adapter uses two independent read-only surfaces:

1. Codex App Server over its default local `stdio` JSON-RPC transport.
2. Explicitly authorized Codex session and archived-session filesystem roots.

AgentArk does not read actual user sessions during development or testing
unless a user explicitly authorizes a live probe. Synthetic and redacted golden
fixtures are the default test sources.

### 8.2 App Server behavior

- Launch `codex app-server --listen stdio://` as a child process.
- Set client name to `agentark` and disable AgentArk analytics.
- Do not opt into `experimentalApi`.
- Call `thread/list` for active and archived threads with
  `useStateDbOnly=true` so App Server does not perform its default JSONL
  metadata repair scan.
- Call `thread/read` with `includeTurns=true` for each listed thread.
- Do not call resume, start, archive, unarchive, metadata update, delete,
  compact, shell, process, or other mutating/executing methods.
- Do not use WebSocket transport.

The currently observed local Codex CLI, version 0.146.0, labels App Server and
schema generation as experimental. Therefore App Server availability is a
capability, not a product assumption. The adapter records the exact CLI version
and protocol fingerprint.

### 8.3 Filesystem capture

The scan command requires either an explicit `--source-root` or an explicit
`--allow-detected-codex-home` authorization. Detection alone never authorizes a
scan.

For each JSONL file:

1. Resolve it beneath an authorized root. The first milestone rejects every
   UNC path, device path, alternate data stream, reparse point, junction,
   symlink, and traversal escape; it has no override for these path classes.
2. Capture file identity and length.
3. Read no bytes beyond the captured length.
4. Accept the captured prefix only when it ends at a complete record boundary.
5. Recheck file identity and the captured prefix.
6. Return `Retryable` if the prefix changed, the boundary is incomplete, or the
   file was replaced.

A file that grows after the captured length may yield a valid prior prefix. A
file whose captured prefix changes never yields a successful archive.

Private JSONL is normalized only when its fingerprint matches an immutable
compatibility fixture. Otherwise the exact bytes are encrypted and the source
is quarantined. AgentArk performs no metadata write. Tests require source bytes,
length, modification time, attributes, ACL, database schema, and fixture WAL to
remain unchanged. Access time is reported separately because an operating
system may update it as a side effect of a read.

### 8.4 Completeness

App Server supplies the supported semantic view. Filesystem capture supplies
raw completeness. The scan manifest explicitly reports:

- App Server-visible and normalized threads.
- Raw-only filesystem threads.
- Quarantined records.
- Retryable records.
- Excluded credential sources.
- Unsupported or omitted fields.

A scan with any raw-only, quarantined, retryable, or rejected record is marked
`partial` and may not claim complete semantic coverage.

## 9. Scan and query flow

```text
doctor
  -> probe executable/version/protocol/fingerprint
  -> authorize source root
  -> capture stable source snapshot
  -> write and verify encrypted raw objects
  -> normalize known records
  -> validate identity/order/path/secret invariants
  -> commit canonical entities and sanitized FTS projection
  -> verify counts, hashes, order, and completeness
  -> publish scan manifest
  -> query through CLI or Tauri
```

Each session is an independent transaction. A failed session keeps the last
successfully indexed revision and is marked stale. A `ScanRun` is `complete`
only when all discovered records reach a terminal non-retryable outcome and
all expected verification checks pass. Partial progress is visible and never
reported as complete.

## 10. Failure semantics

Typed failures include:

- `NotDetected`
- `PermissionDenied`
- `RootNotAuthorized`
- `PathEscape`
- `UnknownFingerprint`
- `UnsupportedCapability`
- `SourceChanged`
- `IncompleteRecord`
- `MalformedRecord`
- `SecretPolicyViolation`
- `StorageLocked`
- `IntegrityMismatch`
- `StorageFailure`

Errors carry sanitized context and stable reason codes. Raw vendor content is
never formatted into an error. Panics across the adapter boundary are treated
as defects; malformed input returns a typed outcome.

## 11. Product surfaces

### 11.1 CLI

- `agentark doctor [--json]`
- `agentark probe codex [--json]`
- `agentark scan codex --source-root <path> [--json]`
- `agentark scan codex --allow-detected-codex-home [--json]`
- `agentark sessions list [--json]`
- `agentark sessions show <session-id> [--json]`
- `agentark search <query> [--json]`
- `agentark verify [--scan-id <id>] [--json]`

Human output is concise. JSON output is versioned and never contains raw secret
values or unsanitized errors.

### 11.2 Desktop

The first desktop surface contains four read-only views:

1. Status and probe results.
2. Session list and search.
3. Session timeline with visible messages and tool events.
4. Quarantine and compatibility diagnostics.

The UI renders transcript content as inert text. Markdown HTML, links, images,
and tool output do not execute automatically. There is no shell command or
vendor-write action.

## 12. Test strategy

Production behavior is implemented test-first.

### 12.1 Unit and property tests

- Stable identities and domain-separated hashes.
- Ordinal ordering with equal or missing timestamps.
- Unknown roles and fields.
- Duplicate IDs and duplicate visible text.
- Secret projection and canary absence.
- Authorized-root and containment policy.
- SQLCipher key failure and lock behavior.
- CAS encryption, authentication failure, and idempotent put.
- SQL transaction rollback and stale-revision retention.

### 12.2 Golden and compatibility tests

- Synthetic empty, text, tool, attachment, error, archived, and forked sessions.
- Codex version and protocol fingerprint fixtures.
- Complete, truncated, concurrently appended, malformed, and unknown JSONL.
- Generated stable App Server schemas are stored with their exact Codex version
  and hash; experimental schema fields are excluded.

Fixtures contain no real credential or unredacted personal data.

### 12.3 Fuzz and security tests

- JSONL parser and canonical decoder.
- Unicode normalization, CRLF/LF, giant fields, and incomplete UTF-8.
- Windows drive, UNC, extended path, alternate data stream, reparse point, and
  junction cases.
- Unix symlink and special-file cases.
- Malicious Markdown/HTML, archive-like paths, and credential-like values.
- Source-nonmutation checks covering file bytes, metadata, and any fixture WAL.

### 12.4 Integration and end-to-end tests

- Synthetic capture through CAS, SQLCipher, query, and verification.
- Local App Server protocol contract against an isolated synthetic Codex home.
- Repeated scans produce no duplicate sessions, messages, or objects.
- A network-deny harness observes zero intended egress.
- CLI JSON schemas remain backward compatible within schema major version.
- Tauri reads only through application services.

## 13. Acceptance gates

### Gate 1: Foundation

- Canonical and adapter contracts compile on Windows, Linux, and macOS.
- Threat model and ADRs cover trust roots, key handling, hashing, secret/L0
  policy, snapshot semantics, and UI rendering.
- Synthetic red-green tests establish identity, order, raw preservation,
  quarantine, and fail-closed behavior.

### Gate 2: Local archive and CLI

- SQLCipher and FTS5 operate with encrypted on-disk data.
- CAS tampering is detected.
- Synthetic end-to-end scan, list, show, search, and verify pass offline.
- Canary secrets are absent from FTS, previews, logs, errors, and JSON output.
- Repeated scans are idempotent.

### Gate 3: Codex read-only adapter

- A controlled live probe produces a redacted immutable fixture and capability
  report for the installed Codex version.
- App Server and filesystem sources leave controlled source bytes, length,
  modification time, attributes, ACL, database schema, and fixture WAL
  identical; access-time differences do not constitute a source mutation.
- Active and archived sessions are distinguished.
- Known records preserve visible text, order, provenance, and raw hashes.
- Unknown fingerprints quarantine without semantic indexing.
- Partial, raw-only, and retryable outcomes are explicitly reported.

### Gate 4: Desktop and performance

- The four read-only views pass desktop end-to-end tests.
- FTS top-50 latency is p95 at most 150 ms on the project benchmark machine.
- A 10,000-message session renders its first viewport within 500 ms.
- Idle RSS is at most 350 MB.
- Windows, Linux, and macOS CI, dependency review, license checks, and
  adversarial code review have no blocking finding.

The benchmark machine baseline is 8 CPU cores, 16 GB RAM, and NVMe storage, as
specified by `AgentArk.md`.

## 14. Delivery order

1. Canonical model, threat model, security boundaries, CI, and synthetic
   fixtures.
2. SQLCipher, encrypted CAS, index queries, synthetic adapter, and complete CLI
   flow.
3. Codex probe, stable protocol fixtures, filesystem fixtures, read-only
   adapter, and compatibility matrix.
4. Tauri views, cross-platform hardening, performance work, and final
   verification.

No later gate starts while a prior gate has an unresolved critical or important
review finding.

## 15. Decisions and consequences

- **Codex first:** validates the official integration boundary and local raw
  archive path before expanding to four more adapters.
- **Read and write traits split:** prevents accidental vendor mutation in the
  first binary.
- **App Server capability-gated:** the local CLI currently marks it
  experimental, so filesystem raw capture remains necessary for L0.
- **SQLCipher rather than plaintext SQLite:** search data receives the same
  at-rest confidentiality as canonical text.
- **Raw exact plus sanitized search:** satisfies L0 without turning search,
  previews, logs, or diagnostics into credential exfiltration paths.
- **Explicit scan authorization:** detection does not silently grant access to
  an agent home.
- **Per-session transactions:** one corrupt session does not erase verified
  progress, while the scan manifest prevents partial work from appearing
  complete.
- **CLI before desktop:** the core contract is testable without UI coupling.

If the Codex live probe cannot satisfy Gate 3, Gate 3 is blocked and its
capability report becomes the evidence for revising this design. AgentArk does
not silently switch to another adapter or weaken source-safety requirements.

## 16. Primary references

- Project plan and specification: `AgentArk.md`
- OpenAI Codex App Server documentation:
  <https://learn.chatgpt.com/docs/app-server>
- Tauri prerequisites:
  <https://v2.tauri.app/start/prerequisites/>
- SQLite WAL:
  <https://www.sqlite.org/wal.html>
- SQLite Online Backup API:
  <https://www.sqlite.org/backup.html>
- SQLite FTS5:
  <https://www.sqlite.org/fts5.html>
- SQLCipher:
  <https://github.com/sqlcipher/sqlcipher>
