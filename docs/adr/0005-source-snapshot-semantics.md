# ADR 0005: Stable-prefix source snapshots

Status: Accepted

Context: JSONL files can grow while a scan is reading them.

Decision: Capture a stable prefix bounded by the observed length, require a
complete final newline/record, and recheck identity and metadata. Append-only
growth after the captured prefix is retryable for the next snapshot; prefix
replacement is source-changed.

Consequences: A scan never reads beyond its captured boundary and never
publishes an incomplete record.

Rejected alternatives: Reading a live file until EOF races concurrent writers;
blindly accepting a changed prefix corrupts provenance.
