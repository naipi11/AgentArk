$ErrorActionPreference = 'Stop'

$root = Join-Path $PSScriptRoot '..'
$workspaceManifest = Join-Path $root 'Cargo.toml'
$workspace = Get-Content -Raw -LiteralPath $workspaceManifest
if ($workspace -notmatch '(?m)^publish\s*=\s*false\s*$') {
  throw 'workspace packages must default to publish = false'
}

$missingPublishMetadata = @()
& rg --files -g Cargo.toml $root |
  Where-Object { $_ -ne $workspaceManifest } |
  ForEach-Object {
    $manifest = Get-Content -Raw -LiteralPath $_
    if ($manifest -match '(?m)^\[package\]\s*$' -and $manifest -notmatch '(?m)^publish(?:\.workspace)?\s*=') {
      $missingPublishMetadata += $_
    }
  }

if ($missingPublishMetadata.Count -gt 0) {
  throw "workspace package manifests must explicitly inherit or disable publishing: $($missingPublishMetadata -join ', ')"
}

Write-Output 'Workspace package publishing metadata is valid.'
