# Security Policy

## Responsible use

RED-AI is an **authorized** adversarial security-testing framework. It is built to
be run **only** against systems you own or have explicit, written permission to
test. Unauthorized use against third-party systems is illegal in most
jurisdictions (e.g. the U.S. Computer Fraud and Abuse Act, the UK Computer
Misuse Act, and equivalents) and is not a use this project supports.

Every engagement is gated by a signed scope with an operator attestation, and
all evidence is recorded — the design makes authorization explicit on purpose.
Keep it that way.

## The deliberately-vulnerable apps

`redai_range/` ships intentionally-vulnerable targets (`site.py`, `showcase.py`,
`boxes.py`) for practice. They bind to `127.0.0.1` by default and hold only
fabricated data, with sandboxed primitives (virtual filesystem, in-memory DB,
simulated shell — no real file reads or command execution). **Do not expose them
to any network**, and do not modify them to touch the real filesystem or shell.

## Reporting a vulnerability

If you find a security issue in RED-AI itself (not in a target you are testing),
please open a private report via GitHub Security Advisories on this repository,
or email the maintainer. Please do not open a public issue for a security bug
until it has been addressed. We aim to acknowledge within a few days.

## No warranty

This software is provided "as is", without warranty of any kind. You are
responsible for how you use it and for ensuring you have authorization.
