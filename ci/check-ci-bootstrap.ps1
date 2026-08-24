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

Write-Output 'CI bootstrap and network-silence configuration is valid.'
