$ErrorActionPreference = 'Stop'

$forbidden = @('thread/start', 'thread/resume', 'thread/archive', 'thread/unarchive', 'thread/delete', 'thread/metadata/update', 'turn/start', 'command/exec', 'process/spawn')
$files = @('crates/adapters/codex/src/protocol.rs')
if (-not (Test-Path -LiteralPath $files[0])) { throw 'Codex read-only protocol source is unavailable for forbidden-method scanning' }
foreach ($method in $forbidden) {
    $hits = @(Select-String -LiteralPath $files -SimpleMatch -Pattern $method)
    if ($hits.Count -gt 0) { throw "Forbidden Codex method $method found at $($hits.Path -join ', ')" }
}

$nativeWriter = Get-Content -Raw -LiteralPath 'crates/adapters/codex/src/native_import.rs'
if ($nativeWriter -notmatch 'struct NativeAppServerClient') {
    throw 'Codex native recovery writes must remain separated from the read-only protocol client'
}
