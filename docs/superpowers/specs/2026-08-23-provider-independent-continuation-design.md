# Provider-Independent Agent Session Recovery Design

## Product Contract

AgentArk recovery must not permanently bind a developer to the model provider
that generated an earlier turn. A restored session has one of three internal
outcomes, selected automatically and reported in user language:

| Internal outcome | When it is used | Result in the target client |
| --- | --- | --- |
| Native identity restore | The source Agent format, source provider identity, target Agent version, and target provider configuration are compatible and verified. | The original native thread/session ID is retained. |
| Provider-independent continuation | The original provider is unavailable, changed, or no longer desired, while the target Agent has a verified continuation writer. | A new native thread is created using the target Agent's current default provider/model and is linked to the original session. |
| Archive-only restore | Neither native restoration path can be verified for the target Agent. | The complete sanitized history remains available in AgentArk; no broken vendor record is written. |

Users operate one "Restore imported history" action. They do not choose a
restore mode. The result summarizes native restores, continuations, and any
archive-only items in the selected Agent's terms.

This specification first covers recovery into the matching installed Agent on
the new device: Codex sessions restore into Codex, Claude Code sessions into
Claude Code, and so on. A later explicit cross-Agent transfer may reuse the
same continuation contract, but merely having multiple Agents installed never
silently moves a session between them.

## Definitions

- **Source provider identity:** the provider/model reference recorded by the
  source Agent, without a credential, token, account identifier, endpoint
  secret, or raw configuration body.
- **Target provider capability:** a target Agent probe result stating that its
  currently installed configuration can open/resume a source identity, or can
  create a new conversation using the target Agent's active default model.
- **Continuation:** a new target-native conversation that preserves the
  sanitized visible history, project association, title, source ID and
  provenance while using the target Agent's current provider/model for future
  turns.
- **Identity mapping:** the persistent AgentArk mapping from canonical source
  session ID to either the retained native ID or the new continuation ID.

## Automatic Resolver

For every session in a verified `.ahbundle`, AgentArk evaluates this ordered
decision tree before writing anything to a vendor directory:

1. Verify the selected target Agent is installed, supported, closed, and has a
   compatible version/schema.
2. Probe the target's provider capabilities without exporting or reading
   credentials into the bundle.
3. If the target can resume the source provider identity and validation of the
   copied native payload succeeds, select **Native identity restore**.
4. Otherwise, if the target has a verified provider-independent continuation
   writer, select **Provider-independent continuation**. The writer receives
   sanitized visible messages and restored project context, then creates a new
   native thread under the target Agent's existing default provider/model.
5. Otherwise select **Archive-only restore** and present a precise, sanitized
   reason. The AgentArk archive is already restored and remains searchable.

The resolver never silently changes a user's configured provider. When a
developer has configured Codex to use GPT on the new device, an old Codex
session created through a Claude/custom provider becomes a new Codex
continuation whose future turns use that GPT configuration.

## History Representation and Continuity

The continuation contains a target-native, visible recovery record rather than
an opaque reference to AgentArk. It includes:

- original title and a clear "continued from" provenance label;
- chronological sanitized user and assistant messages;
- restored project/workspace location and file recovery status;
- a compact machine-readable migration manifest containing source Agent,
  source session ID, source provider identity class, and content hashes;
- a final target-native turn initialized for the target Agent's active model.

The exact rendering of imported history is adapter-specific. An adapter is not
considered a continuation writer until an isolated integration test proves the
target client lists the new session, opens it, exposes its visible history, and
accepts a subsequent turn using the target provider. If an Agent cannot meet
that proof, it stays archive-only rather than pretending that a transcript is a
resumable vendor session.

## Adapter Capability Contract

Extend the adapter migration boundary with these independently testable
capabilities:

```text
probe_target_provider(source_provider_identity) -> ProviderCompatibility
restore_native_identity(payload, target) -> NativeRestoreReport
create_provider_independent_continuation(canonical_session, target) -> ContinuationReport
verify_target_session(target_session_id, expected_visible_history) -> VerificationReport
```

`ProviderCompatibility` has `same_provider`, `target_default_available`, and
`reason_code` fields only. It must never include a credential value.

`ContinuationReport` includes original and target IDs, target provider/model
labels, visible/history hashes, loss records, and rollback paths. It does not
include message bodies in audit events.

## Agent Rollout

1. **Codex:** retain the existing validated raw-rollout identity path when the
   provider is available. Add a continuation spike that proves a new Codex
   thread can show migrated visible history and accept a turn under the target
   default provider. Current `thread/inject_items` alone is explicitly not a
   sufficient continuation writer because it does not create visible turns.
2. **Claude Code:** add a target configuration probe and a continuation writer
   only after an isolated Claude fixture demonstrates visible history and a
   subsequent turn. Do not write a guessed transcript format.
3. **Hermes, OpenClaw, OpenCode, Grok Build:** implement the same capability
   contract one adapter at a time. Existing read-only adapters remain
   archive-only until each writer/verifier passes its fixture and real-runtime
   gate.

The user-facing UI remains uniform throughout this rollout. A non-ready Agent
reports archive-only recovery rather than exposing experimental controls.

## Bundle and Storage Changes

- Upgrade the bundle manifest compatibly to carry provider identity metadata,
  per-session native payload availability, and migration provenance. Existing
  v1/v1.1 bundles continue to restore to AgentArk.
- Continue storing source raw rollout payloads only for native identity
  restoration. Continuations are generated from the canonical sanitized
  archive, not from old provider credentials.
- Add an immutable `session_restore_mapping` record in AgentArk storage:
  `source_canonical_id`, `target_agent`, `outcome`, `source_native_id`,
  `target_native_id`, `source_provider_class`, `target_provider_class`,
  hashes, timestamps, and sanitized reason code.

## Safety, Conflict Handling, and Rollback

- No provider credential, custom endpoint secret, or account state crosses
  devices in a bundle.
- Native identity writes retain existing process guards, backups, atomic
  writes, conflict detection, and App Server verification.
- Continuation writes use their own target-agent transaction/checkpoint. A
  failed visible-history or subsequent-turn verification deletes only the new
  continuation and records archive-only recovery.
- Existing target thread IDs are never overwritten. Matching payloads are
  idempotently skipped; mismatches are conflicts.
- A successful AgentArk archive restore is never rolled back due solely to a
  vendor-native recovery failure.

## UI and Reporting

The current two transfer buttons remain unchanged. The import preview shows
only an estimated outcome count when it can be determined safely. Completion
shows, per selected Agent:

```text
Restored 14 sessions: 9 original sessions retained, 4 continuations created,
1 available in AgentArk archive only.
```

The UI may offer a normal target-model/default setting at Agent setup time, but
it must never ask the user to choose the recovery mode for individual sessions.
Detailed provider mismatch reasons are available in an expandable diagnostics
view without message bodies or secrets.

## Acceptance Criteria

- A same-provider Codex session restores with the original native ID and opens
  successfully after target client restart.
- A source session using an unavailable/custom/Claude provider creates a new
  Codex continuation that displays the sanitized visible history and accepts a
  next turn using the target GPT default configuration.
- Repeating either restore is idempotent; conflicts do not overwrite target
  sessions.
- Every continuation is traceable from the original AgentArk session and
  target-native ID without exposing credentials.
- Each supported Agent has fixture plus isolated real-runtime proof before its
  continuation capability is advertised.
- Unverified Agents preserve complete archive history and accurately report
  archive-only recovery.
