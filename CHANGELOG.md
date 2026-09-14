# Changelog

## [0.6.6] - 2026-09-14

### Fixed

- Report raw source provenance explicitly as `none`, `available`, `unresolved`, or `unknown` without copying source CAS identifiers or bytes across devices.
- Validate message, tool-event, and attachment raw references before indexing or importing bundles.
- Serialize audit-chain appends and reject corrupted chains or lock contention instead of risking concurrent writes.
- Validate destination storage before materializing restored workspace files during CLI bundle restore.
- Filter archive search by Agent before applying the result limit while preserving legacy unfiltered search payloads.

### Release

- Bump the desktop package and Tauri bundle version to `0.6.6`.

[0.6.6]: https://github.com/naipi11/AgentArk/releases/tag/v0.6.6


## [0.6.5] - 2026-09-13

### Fixed

- Make bundle framing and manifest validation strict, including trailing data, unlisted entries, workspace file hashes, and native payload ownership.
- Prevent duplicate workspace entries when multiple sessions belong to one project.
- Exclude environment credential variants and unscannable binary files from project-file exports.
- Sanitize imported session data before persisting it to the encrypted index.
- Make CAS object path handling reject malformed identifiers without panicking or escaping the CAS root.
- Make first-run bootstrap creation atomic and serialized across processes.
- Keep empty scan verification valid and persist the real source snapshot identifier.
- Run desktop bundle operations off the Tauri command thread and prevent stale Transfer requests.
- Add a full-text Search view and a working Playwright timeline fixture.
- Require explicit CLI workspace selection, with `--all-projects` for intentional full exports.
- Normalize local file URIs across adapters and keep restored workspace metadata under `.agentark/`.

[0.6.5]: https://github.com/naipi11/AgentArk/releases/tag/v0.6.5


## [0.6.4] - 2026-09-10

### Fixed

- Align CLI `.ahbundle` diagnostics with the desktop importer.
- Report unreadable bundles, integrity failures, and invalid formats with stable sanitized error codes.
- Validate recovery metadata and session records during CLI bundle verification, migration planning, and restore.
- Add CLI regression coverage for corrupted, missing, malformed, and invalid bundles.
- Fix the nightly fuzz workflow so `cargo-fuzz` uses the pinned nightly toolchain.

### Release

- Bump the desktop package, Tauri bundle, and Codex App Server client version to `0.6.4`.

[0.6.4]: https://github.com/naipi11/AgentArk/releases/tag/v0.6.4
