$ErrorActionPreference = 'Stop'

$workflow = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot '..\.github\workflows\ci.yml')
$setupPnpm = $workflow.IndexOf('uses: pnpm/action-setup@v4')
$setupNode = $workflow.IndexOf('uses: actions/setup-node@v4')
if ($setupPnpm -lt 0 -or $setupNode -lt 0 -or $setupPnpm -gt $setupNode) {
  throw 'pnpm/action-setup must run before actions/setup-node uses cache: pnpm'
}

$release = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot '..\.github\workflows\release.yml')
$releasePnpm = $release.IndexOf('uses: pnpm/action-setup@v4')
$releaseNode = $release.IndexOf('uses: actions/setup-node@v4')
if ($releasePnpm -lt 0 -or $releaseNode -lt 0 -or $releasePnpm -gt $releaseNode) {
  throw 'release workflow must install pnpm before actions/setup-node uses cache: pnpm'
}
if ($release -notmatch '(?m)^\s+target/release/bundle/\*\*$') {
  throw 'release workflow must upload Tauri bundles from the workspace target directory'
}
if ($release -match 'apps/desktop/src-tauri/target/release/bundle') {
  throw 'release workflow must not upload the obsolete per-package Tauri target directory'
}

$networkScript = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'network-silence.sh')
if ($networkScript -notmatch 'sudo\s+unshare\s+--net') {
  throw 'network-silence must use the privileged network namespace path on hosted runners'
}
if ($networkScript -notmatch 'CARGO_NET_OFFLINE=true') {
  throw 'network-silence must execute Cargo with offline mode enabled'
}
if ($networkScript -match 'unshare\s+--user\s+--map-root-user') {
  throw 'network-silence must not depend on unprivileged user namespaces on hosted runners'
}

$networkFetch = $workflow.IndexOf('cargo fetch --locked')
$networkRun = $workflow.IndexOf('bash ci/network-silence.sh')
if ($networkFetch -lt 0 -or $networkRun -lt 0 -or $networkFetch -gt $networkRun) {
  throw 'network-silence must prefetch locked dependencies before entering its offline network namespace'
}

foreach ($fragment in @(
  'CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"',
  'RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"',
  'RUSTUP_BIN="$CARGO_HOME/bin/rustup"',
  'CARGO_BIN="$("$RUSTUP_BIN" which cargo)"',
  'TOOLCHAIN_BIN="$(dirname "$CARGO_BIN")"',
  'PATH="$TOOLCHAIN_BIN:$CARGO_HOME/bin:$PATH"',
  '"$CARGO_BIN" test'
)) {
  if (-not $networkScript.Contains($fragment)) {
    throw "network-silence must carry the Rust runtime into the privileged namespace (missing: $fragment)"
  }
}

$processSource = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot '..\crates\adapters\codex\src\process.rs')
if ($processSource -notmatch '(?ms)#\[cfg\(windows\)\]\s*const OWNED_TREE_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs\(2\);') {
  throw 'the owned Windows process-tree timeout must be compiled only on Windows'
}

Write-Output 'CI bootstrap and network-silence configuration is valid.'
