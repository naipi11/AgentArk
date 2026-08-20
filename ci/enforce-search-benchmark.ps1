$env:AGENTARK_ENFORCE_BENCH = '1'
cargo bench -p agentark-index --bench search
$result = Get-Content -LiteralPath 'target/agentark-bench/search.json' -Raw | ConvertFrom-Json
if ($result.p95Ms -gt 150.0) { throw "search p95 exceeds 150 ms" }
