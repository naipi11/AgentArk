# ADR 0002: Exact raw data and sanitized projections

Status: Accepted

Context: Forensic recovery needs exact encrypted source bytes, while search and
preview must not expose secrets or hidden reasoning.

Decision: Archive raw records in encrypted CAS before normalization. Store only
sanitized title/body projections in FTS and map public DTOs through the secret
scanner again.

Consequences: Search is safe to index and raw recovery remains possible after a
successful integrity check.

Rejected alternatives: Indexing raw JSON or hidden reasoning would leak data;
discarding raw bytes would make provenance unverifiable.
