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
  payloads and can restore them into the target Codex client when the native
  option is enabled.
- `agentark-watch` provides root fingerprints, change diffing, debounce, and a
  desktop background rescan loop serialized behind the scan lock.
- `agentark-audit` provides append-only hash-chain events and checkpoint file
  manifests. CLI `audit verify` validates the local chain.
- `agentark-sync` provides an append-only operation log, HLC metadata merge,
  immutable message/tool-event union, and explicit conflict records; message
  content is never silently overwritten by last-write-wins.

## Release gate result

The 0.5.0 Windows gate is in progress: workspace tests, clippy, front-end tests,
MSI/NSIS build, SHA-256 capture, administrator upgrade, and responsive desktop
launch are retained as release gates. Codex native restore is version-gated to
the tested Codex App Server contract, requires Codex to be closed while writing,
and verifies the imported rollout after a fresh App Server start. Unknown
versions or verification failures fall back to the verified AgentArk archive.
Cloud relay, multi-user server mode, and L3 credential migration remain
deliberately disabled for the local-first release.

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

For Codex, the transfer bundle now includes redacted native rollout payloads.
Restore writes them atomically under the target `CODEX_HOME`, rewrites only
workspace path fields, creates an `agentark-backups` manifest, and reports the
number of Codex threads imported or skipped. Restart Codex after a successful
native restore to refresh its session list.
