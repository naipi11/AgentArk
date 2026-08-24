$ErrorActionPreference = 'Stop'

function Find-CanaryMatches {
    param(
        [Parameter(Mandatory)] [string] $Root,
        [Parameter(Mandatory)] [string] $Needle
    )

    if (Get-Command rg -ErrorAction SilentlyContinue) {
        $matches = @(& rg -a -l -F --glob '!encrypted-objects/**' -- $Needle $Root)
        if ($LASTEXITCODE -eq 0) { return $matches }
        if ($LASTEXITCODE -eq 1) { return @() }
        throw "rg failed while scanning $Root"
    }

    $matches = @()
    Get-ChildItem -LiteralPath $Root -Recurse -File -Force |
        Where-Object { $_.FullName -notmatch '[\\/]+encrypted-objects([\\/]|$)' } |
        ForEach-Object {
            $contents = [System.Text.Encoding]::UTF8.GetString([System.IO.File]::ReadAllBytes($_.FullName))
            if ($contents.IndexOf($Needle, [StringComparison]::Ordinal) -ge 0) {
                $matches += $_.FullName
            }
        }
    return $matches
}

$canaries = Get-Content -LiteralPath 'fixtures/security/vendor-token-canaries.json' -Raw | ConvertFrom-Json
$roots = @('target/agentark-test-artifacts', 'target/agentark-bench', 'apps/desktop/dist') | Where-Object { Test-Path -LiteralPath $_ }
foreach ($root in $roots) {
    foreach ($entry in $canaries) {
        $matches = @(Find-CanaryMatches -Root $root -Needle $entry.value)
        if ($matches.Count -gt 0) { throw "Secret canary $($entry.class) found in $($matches -join ', ')" }
    }
}
