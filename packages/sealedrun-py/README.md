# sealedrun

Reference Python implementation of the SealedRun Record specification.
See the repository root `SPEC.md` for the format.

Writes runs, delegations and evidence bundles and verifies them, including the offline check of
anchor receipts (RFC 3161 time-stamps, Sigstore Rekor v1 entries) against the witness trust list
in `sealedrun/trust/witnesses.json`. `python -m sealedrun bundle.zip` prints the verification
summary.
