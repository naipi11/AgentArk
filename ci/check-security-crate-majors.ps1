$critical = @('chacha20poly1305', 'sha2', 'rusqlite', 'zeroize')
$metadata = cargo metadata --locked --format-version 1 | ConvertFrom-Json
foreach ($name in $critical) {
    $majors = @($metadata.packages | Where-Object name -eq $name | ForEach-Object { ([version]$_.version).Major } | Sort-Object -Unique)
    if ($majors.Count -gt 1) { throw "$name has multiple major versions: $($majors -join ',')" }
}
