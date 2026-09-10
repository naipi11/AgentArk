# Changelog

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
