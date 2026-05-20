# Contributing to seraph-iris-mods

Thanks for your interest. This repo is the AGPL-3.0-public companion to a
private Seraph IT deployment. We accept external contributions under the
constraints below.

## Scope

This repo holds **only** code modifications and plugins against IRIS-DFIR,
Cortex, and MISP. Configuration, deployment scripts, and customer-specific
data are explicitly out of scope (those live in a private repo).

## Pull Request Requirements

1. **License**: All contributions must be AGPL-3.0-or-later compatible.
2. **No customer data**: No real IPs, hostnames, hashes, or domains in code or
   tests. Use RFC 5737 (`192.0.2.x`), `attacker.example`, and dummy hashes
   (`aaaa...`).
3. **Tests**: New modules require unit tests with ≥80% coverage of the module.
4. **Documentation**: README + docstrings + ADR for non-trivial design choices.
5. **Review**: At least one Seraph-IT maintainer approval before merge.
6. **DCO**: All commits must be signed-off (`git commit -s`).

## Code Style

- Python 3.11+.
- `ruff` for linting and formatting (config in `pyproject.toml`).
- `mypy --strict` for type-checking new code.
- No print statements — use `logging` module.

## Issues

GitHub Issues are open for bug reports related to the code in this repo.
For customer support, contact your Seraph-IT account manager.

For Seraph-IT internal discussions, use the appropriate Discord channel —
not this repo's Issues.

## Reporting Security Issues

Do **not** open public issues for security vulnerabilities. Email
`security@seraph-it.example` with details. We acknowledge within 48h.

## Maintainers

See `CODEOWNERS`. Maintainer status is granted by the Seraph-IT engineering
lead.
