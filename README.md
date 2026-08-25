<div align="center">
  <img src="AgentArk.png" alt="AgentArk icon" width="144" height="144">
  <h1>AgentArk</h1>
  <p><strong>Local-first archive, search, backup, and safe recovery for coding-agent session history.</strong></p>
  <p><a href="./README.zh-CN.md">中文</a> · English</p>
</div>

<p align="center">
  <a href="https://github.com/naipi11/AgentArk/releases/latest"><img src="https://img.shields.io/github/v/release/naipi11/AgentArk?display_name=tag&sort=semver&style=flat-square&label=release&color=2563eb" alt="Latest release"></a>
  <a href="https://github.com/naipi11/AgentArk/releases"><img src="https://img.shields.io/github/downloads/naipi11/AgentArk/total?style=flat-square&label=downloads&color=7c3aed" alt="Total downloads"></a>
  <a href="https://github.com/naipi11/AgentArk/stargazers"><img src="https://img.shields.io/github/stars/naipi11/AgentArk?style=flat-square&label=stars&color=f59e0b" alt="GitHub stars"></a>
  <a href="https://github.com/naipi11/AgentArk/pulls"><img src="https://img.shields.io/github/issues-pr/naipi11/AgentArk?style=flat-square&label=pull%20requests&color=0ea5e9" alt="Pull requests"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Windows-10%2F11%20x64-0078D4?style=flat-square&logo=windows&logoColor=white" alt="Windows 10 and 11 x64">
  <img src="https://img.shields.io/badge/macOS-Apple%20silicon-000000?style=flat-square&logo=apple&logoColor=white" alt="macOS Apple silicon">
  <img src="https://img.shields.io/badge/Linux-x64-FCC624?style=flat-square&logo=linux&logoColor=111827" alt="Linux x64">
  <img src="https://img.shields.io/badge/Tauri-2-24C8DB?style=flat-square&logo=tauri&logoColor=white" alt="Tauri 2">
  <img src="https://img.shields.io/badge/Rust-2024-000000?style=flat-square&logo=rust&logoColor=white" alt="Rust 2024">
  <img src="https://img.shields.io/badge/React-19-61DAFB?style=flat-square&logo=react&logoColor=111827" alt="React 19">
  <img src="https://img.shields.io/badge/Storage-Encrypted%20local-16a34a?style=flat-square&logo=sqlite&logoColor=white" alt="Encrypted local storage">
</p>

AgentArk consolidates local coding-agent conversations and workspaces into a searchable encrypted archive. It helps you export selected projects, move history to another device, inspect restoration outcomes, and keep an audit trail without uploading your session contents.

## Why AgentArk

- Local-first encrypted archive and full-text search
- Project-aware session browsing, timeline, quarantine, and recovery reports
- Portable `.ahbundle` export/import with project-file selection
- Audit chain, conflict detection, rollback, and safe diagnostic reporting
- Chinese / English desktop interface
- Native Windows, macOS, and Linux desktop installers; no terminal required for normal use

## What's included in v0.6.3

- Agent-scoped project and session browsing for Codex, Claude Code, Hermes, OpenClaw, OpenCode, and Grok Build
- Chinese / English desktop interface and portable `.ahbundle` export/import workflow
- Verified provider-independent Codex continuation when the original native identity cannot be retained
- Published desktop packages for Windows, macOS Apple silicon, and Linux
- Long-running scans execute away from the desktop window thread, keeping AgentArk responsive while indexing
- Project-file exports exclude dependency/build directories and skip individual files over 64 MiB instead of failing the complete history backup
- Import validation now clearly distinguishes unreadable files, integrity failures, and incompatible bundle formats

## Recovery capability

| Agent | Current recovery behavior |
| --- | --- |
| Codex | Verified same-provider native identity restore; provider-independent continuation under the target device's configured provider/model when native identity cannot be retained |
| Claude Code | Complete archive restore; native continuation writer pending its own verified protocol gate |
| Hermes | Complete archive restore; native continuation writer pending verification |
| OpenClaw | Complete archive restore; native continuation writer pending verification |
| OpenCode | Complete archive restore; native continuation writer pending verification |
| Grok Build | Complete archive restore; native continuation writer pending verification |

AgentArk never exports provider credentials, endpoint secrets, account identifiers, or hidden reasoning. Native recovery is attempted only after compatibility, process, schema, visible-history, and durable-rollout validation. If an operation cannot be verified, the complete archive remains available and the result is reported honestly rather than presented as a usable native session.

## Install

1. Open [Releases](https://github.com/naipi11/AgentArk/releases/latest).
2. Choose the package for your platform:
   - **Windows:** AgentArk_0.6.3_x64-setup.exe (recommended) or AgentArk_0.6.3_x64_en-US.msi
   - **macOS Apple silicon:** AgentArk_0.6.3_aarch64.dmg
   - **Linux x64:** AgentArk_0.6.3_amd64.AppImage, `.deb`, or `.rpm`
3. Verify the published SHA-256 checksum if you need a reproducible installation record.
4. Run the installer and open **AgentArk** from the Start menu or your system application launcher.
5. Open **Scan**, choose an Agent, then scan and browse its projects/sessions.

No administrator rights are required for a typical per-user installation.

## Move history to another device

1. In **Projects**, choose the Agent and projects you want to transfer.
2. Choose **Export session history** and select a destination in File Explorer.
3. Copy the generated `.ahbundle` to the new device.
4. Install AgentArk on the new device, then choose **Import session history**.
5. Review the detected archive and choose **Restore imported history**.

AgentArk restores its searchable archive first. For Codex, it then automatically keeps a compatible native session ID or creates a verified continuation. You do not choose an internal recovery mode.

> [!IMPORTANT]
> Close Codex before a native recovery write. AgentArk never terminates Codex automatically. Restart Codex after a native recovery so its client refreshes the restored session list.

## Data and safety

- Session archive and index data are encrypted locally.
- Export bundles are sanitized before creation.
- Provider labels may be retained when safe; tokens, endpoints, account IDs, and hidden reasoning are excluded.
- Every recovery records a hash-chain audit event.
- A failed vendor-native recovery never removes the successfully restored AgentArk archive.

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=naipi11/AgentArk&type=Date)](https://star-history.com/#naipi11/AgentArk&Date)

## Development

Run the desktop release build with `pnpm --dir apps/desktop tauri build`. It produces MSI and NSIS installers under `target/release/bundle/`.

For implementation decisions, capability contracts, and the longer-term roadmap, see [AgentArk.md](AgentArk.md).
