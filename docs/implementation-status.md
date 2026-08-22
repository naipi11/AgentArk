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
- Restoring writes only AgentArk-owned SQLCipher index rows in one transaction;
  it does not inject records into a vendor client.
- `agentark-watch` provides root fingerprints, change diffing, debounce, and a
  desktop background rescan loop serialized behind the scan lock.
- `agentark-audit` provides append-only hash-chain events and checkpoint file
  manifests. CLI `audit verify` validates the local chain.
- `agentark-sync` provides an append-only operation log, HLC metadata merge,
  immutable message/tool-event union, and explicit conflict records; message
  content is never silently overwritten by last-write-wins.

## Remaining release gates

The remaining work before the first user test build is release hardening rather
than source coverage: final cross-platform full-workspace test/clippy/audit,
installer build and hash verification, migration/backup end-to-end fixtures,
and a clean Windows install/upgrade smoke test. No vendor-native writer is
enabled by default; cross-agent migration remains an explicit L1 handoff until
an official target import contract is available.
