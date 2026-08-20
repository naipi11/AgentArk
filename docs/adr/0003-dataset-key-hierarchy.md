# ADR 0003: Dataset key hierarchy

Status: Accepted

Context: A local dataset needs independent encryption domains without a
plaintext fallback.

Decision: An OS-backed master key wraps a random per-dataset key. HKDF derives
separate SQLCipher, CAS AEAD, and object-ID keys. Missing and unavailable OS
stores remain distinct failures.

Consequences: Dataset keys are scoped, buffers are zeroized, and stolen files
alone are insufficient for decryption.

Rejected alternatives: A file plaintext key or password fallback would create a
second uncontrolled secret path.
