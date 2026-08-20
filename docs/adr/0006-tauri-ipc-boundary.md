# ADR 0006: Tauri IPC boundary

Status: Accepted

Context: The desktop viewer must not become a second storage or key boundary.

Decision: Tauri registers only `status`, `sessions_list`, `sessions_show`,
`search`, and `quarantines_list`. Commands delegate to sanitized app DTOs;
React renders ordinary text nodes under a restrictive CSP.

Consequences: No raw JSON, CAS path, SQL handle, key, navigation, shell, or
mutating command is reachable from the UI.

Rejected alternatives: Filesystem permissions or generic invoke passthroughs
would expose implementation state and enlarge the attack surface.
