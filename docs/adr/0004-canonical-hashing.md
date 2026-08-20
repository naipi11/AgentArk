# ADR 0004: Canonical hashing

Status: Accepted

Context: Repeated scans must identify the same entities deterministically.

Decision: RFC 8785 JCS serialization plus domain-separated SHA-256 defines
canonical hashes. UUIDv5 identities use stable namespace inputs.

Consequences: Key order and process order do not change identity or revision
comparison.

Rejected alternatives: Debug serialization and random UUIDs cannot support
idempotence or cross-adapter provenance.
