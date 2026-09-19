# @sealedrun/core

TypeScript verification library for the SealedRun Record format. Runs in Node and in
the browser; it is what the web inspector uses to verify a bundle without any server.

- RFC 8785 canonicalization, SHA-256/384 hash chain
- Hybrid signature verification: Ed25519, ES256, ML-DSA-65, ML-DSA-87 (via `@noble/*`)
- Delegation, run and bundle verification with the failing check and seq
- Passes every vector in `spec/vectors/`

Signing keys never enter this package; it verifies only.
