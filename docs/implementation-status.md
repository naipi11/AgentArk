# AgentArk implementation status

This document records the current implementation boundary against `AgentArk.md`.

## Read-only source adapters

The desktop Scan page, CLI `probe`, and CLI `scan` now share the same read-only
adapter contract for:

- Codex App Server/filesystem
- Claude Code `~/.claude/projects/**/*.jsonl`
- Hermes `~/.hermes/state.db`
- OpenClaw global/per-agent SQLite stores
- OpenCode `opencode.db` (`session`/`message`/`part` tables)
- Grok Build `~/.grok/sessions/**/summary.json` and `updates.jsonl`

Each adapter preserves raw captured records, normalizes visible messages/tool
events, records source provenance, and quarantines malformed semantic records.
Vendor databases/files are never opened writable.

## Archive, migration, and reconciliation

- `.ahbundle` is a framed, path-safe container with entry and total-size limits,
  per-entry SHA-256 verification, deterministic session entries, and recursive
  secret redaction.
- CLI commands: `bundle export`, `bundle verify`, `bundle restore`, and
  `migration plan <bundle> <target> [--handoff]`.
- `migration export <bundle> <target> <output>` writes an L1 structured JSON
  handoff and human-readable Markdown handoff per session.
- Restoring always writes AgentArk-owned SQLCipher index rows in one transaction.
  Codex bundles additionally carry sanitized, source-generated native rollout
  payloads for automatic recovery.
- `agentark-watch` provides root fingerprints, change diffing, debounce, and a
  desktop background rescan loop serialized behind the scan lock.
- `agentark-audit` provides append-only hash-chain events and checkpoint file
  manifests. CLI `audit verify` validates the local chain.
- `agentark-sync` provides an append-only operation log, HLC metadata merge,
  immutable message/tool-event union, and explicit conflict records; message
  content is never silently overwritten by last-write-wins.

## Capability states

- **Codex:** automatic same-provider native identity restore and
  provider-independent continuation, subject to version, process, and App
  Server verification. Compatible same-provider sessions retain their original
  native ID. When the provider is unavailable or changes, AgentArk creates a
  new Codex continuation using the target Codex installation's configured
  default provider and model.
- **Claude Code:** AgentArk archive-only while the native continuation writer
  remains unverified.
- **Hermes:** AgentArk archive-only while the native continuation writer
  remains unverified.
- **OpenClaw:** AgentArk archive-only while the native continuation writer
  remains unverified.
- **OpenCode:** AgentArk archive-only while the native continuation writer
  remains unverified.
- **Grok Build:** AgentArk archive-only while the native continuation writer
  remains unverified.

Users never choose the internal restore mode. Credentials, endpoints, and
hidden reasoning are never portable. Rollback or manual-intervention outcomes
are reported separately and are never presented as archive-only success. Live
subsequent-turn validation is opt-in and is not part of normal packaging.

## Release gate

The 0.6.0 Windows release gate requires workspace tests, clippy, front-end
tests, MSI/NSIS build, and SHA-256 capture. Installation, launch, and live
subsequent-turn validation are separate opt-in operations and are not normal
packaging steps. Codex recovery is version-gated to the tested Codex App Server
contract, requires Codex to be closed while writing, and verifies the recovered
thread after a fresh App Server start. Unknown versions or verification failures
fall back to the verified AgentArk archive. Cloud relay, multi-user server mode,
and L3 credential migration remain deliberately disabled for the local-first
release.

The transfer UI now exposes Agent-scoped project selection, an optional project
file checkbox, bundle verification/preview, conflict blocking, and restore into
`restored-workspaces` on the destination device.

The transfer actions no longer depend on manually entered paths. During an
active operation the button label reports whether AgentArk is exporting,
checking, or restoring the bundle, and a cancelled dialog leaves the archive
unchanged.

The transfer actions now open native Windows dialogs: export opens a save dialog
with the `.ahbundle` filter, import opens a file picker for an existing bundle,
and cancelling either dialog performs no operation.

For Codex, the transfer bundle includes redacted native rollout payloads.
Compatible recovery retains the source native ID; provider-independent recovery
creates a new target-Codex continuation. Restore writes atomically under the
target `CODEX_HOME`, rewrites only workspace path fields, creates an
`agentark-backups` manifest, and reports original-ID, continuation, archive-only,
and manual-intervention outcomes separately. Restart Codex after a successful
native recovery to refresh its session list.
