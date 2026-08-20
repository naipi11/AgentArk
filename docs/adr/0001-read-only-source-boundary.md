# ADR 0001: Read-only source boundary

Status: Accepted

Context: Vendor histories are untrusted and must never be mutated by AgentArk.

Decision: Separate `SourceAdapter` from any future target/import adapter. M0
compiles only the source trait and exposes detection, probing, capture, and
normalization. No write, resume, archive, delete, shell, or process operation
is part of the boundary.

Consequences: Every source is testable with a before/after tree digest; target
work remains a separately authorized design.

Rejected alternatives: Reusing a bidirectional vendor SDK would make write
methods reachable and would weaken the read-only guarantee.
