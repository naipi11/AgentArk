$forbidden = @('thread/start', 'thread/resume', 'thread/archive', 'thread/unarchive', 'thread/delete', 'thread/metadata/update', 'turn/start', 'command/exec', 'process/spawn')
$files = @(& rg --files crates/adapters/codex/src)
foreach ($method in $forbidden) {
    $hits = @(Select-String -LiteralPath $files -SimpleMatch -Pattern $method)
    if ($hits.Count -gt 0) { throw "Forbidden Codex method $method found at $($hits.Path -join ', ')" }
}
