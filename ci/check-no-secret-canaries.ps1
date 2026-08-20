$canaries = Get-Content -LiteralPath 'fixtures/security/vendor-token-canaries.json' -Raw | ConvertFrom-Json
$roots = @('target/agentark-test-artifacts', 'target/agentark-bench', 'apps/desktop/dist') | Where-Object { Test-Path -LiteralPath $_ }
foreach ($root in $roots) {
    foreach ($entry in $canaries) {
        $matches = @(& rg -a -l -F --glob '!encrypted-objects/**' -- $entry.value $root)
        if ($LASTEXITCODE -eq 0 -and $matches.Count -gt 0) { throw "Secret canary $($entry.class) found in $($matches -join ', ')" }
        if ($LASTEXITCODE -notin @(0, 1)) { throw "rg failed while scanning $root" }
    }
}
