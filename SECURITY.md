# Security policy

## Reporting a vulnerability

Email **security@sealedrun.com**, or use GitHub private vulnerability reporting
("Report a vulnerability" on the Security tab of this repository). Please do not open a public
issue, pull request or discussion for a suspected vulnerability.

Include what you can: affected component and version, how to reproduce, the impact you expect, and
a proof of concept if you have one. A bundle or record that triggers the problem is ideal.

## What to expect

- Acknowledgement within 3 working days.
- A first assessment within 10 working days.
- Coordinated disclosure: we agree a publication date with you, normally within 90 days, sooner
  when a fix ships earlier. You are credited in the advisory unless you prefer otherwise.

We do not run a bug bounty. Good-faith research that follows this policy will not be met with
legal action from us.

## Scope

In scope: the SealedRun specification (`SPEC.md`, schemas, test vectors), the `sealedrun` Python
library, `@sealedrun/core`, the recorder service, the web inspector, the Docker image and the CI
configuration of this repository.

Of particular interest: any way to make a verifier accept a record, run, delegation or bundle that
was altered, truncated, reordered or signed by the wrong party; disagreement between the Python and
TypeScript verifiers on the same input; resource exhaustion through crafted bundles; anything that
lets stored payloads execute in a browser.

Out of scope: findings that require a compromised Agent or Principal private key (see `TRUST.md`
for what the format does and does not claim), and deployments that expose a recorder without
`SEALEDRUN_API_TOKEN` and TLS against the advice in the README.

## Supported versions

Until 1.0.0 only the latest released version receives security fixes.
