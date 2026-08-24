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
foreach ($pattern in @(
  'target/release/bundle/**/*.msi',
  'target/release/bundle/**/*.exe'
)) {
  if ($release -notmatch [regex]::Escape($pattern)) {
    throw "release workflow must stage installer assets matching $pattern"
  }
}
if ($release -match 'apps/desktop/src-tauri/target/release/bundle') {
  throw 'release workflow must not upload the obsolete per-package Tauri target directory'
}
if ($release -notmatch 'if-no-files-found:\s*error') {
  throw 'release workflow must fail if a platform does not produce publishable artifacts'
}
if ($release -notmatch "! -name 'SHA256SUMS'") {
  throw 'release checksum generation must exclude the manifest itself'
}
if ($release -notmatch 'Stage uniquely named release assets' -or $release -notmatch 'duplicate release asset name') {
  throw 'release workflow must reject colliding published asset names before checksumming'
}
if ($release -notmatch 'files: release-publish/\*') {
  throw 'release workflow must publish the flattened uniquely named release assets'
}
if ($release -match '(?m)^\s+target/release/agentark(?:\.exe)?\s*$') {
  throw 'release workflow must not upload same-named cross-platform CLI binaries'
}
if ($workflow -match 'ci/enforce-search-benchmark\.ps1') {
  throw 'the full 100k search benchmark must not run in every PR matrix job'
}
if ($release -notmatch "(?ms)- name: Enforce search benchmark\s+if: runner\.os == 'Linux'\s+run: pwsh -File ci/enforce-search-benchmark\.ps1") {
  throw 'release workflow must run the full search benchmark once on Linux before publishing'
}

foreach ($scannerName in @(
  'check-no-secret-canaries.ps1',
  'check-workspace-metadata.ps1'
)) {
  $scanner = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot $scannerName)
  if ($scanner -notmatch 'Get-Command\s+rg') {
    throw "$scannerName must have a PowerShell fallback when ripgrep is unavailable"
  }
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
