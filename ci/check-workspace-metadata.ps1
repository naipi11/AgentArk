$ErrorActionPreference = 'Stop'

$root = Join-Path $PSScriptRoot '..'
$workspaceManifest = Join-Path $root 'Cargo.toml'
$workspace = Get-Content -Raw -LiteralPath $workspaceManifest
if ($workspace -notmatch '(?m)^publish\s*=\s*false\s*$') {
  throw 'workspace packages must default to publish = false'
}

$manifestPaths = if (Get-Command rg -ErrorAction SilentlyContinue) {
  $paths = @(& rg --files -g Cargo.toml $root)
  if ($LASTEXITCODE -ne 0) { throw 'rg failed while enumerating workspace package manifests' }
  $paths
} else {
  @(Get-ChildItem -LiteralPath $root -Filter Cargo.toml -Recurse -File | ForEach-Object FullName)
}

$missingPublishMetadata = @()
$manifestPaths |
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
