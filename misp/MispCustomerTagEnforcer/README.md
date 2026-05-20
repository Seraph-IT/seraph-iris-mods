# MispCustomerTagEnforcer

V1-Blocker module for the Seraph-IT SOC-Enrichment-Stack. Enforces that every
MISP event carries a `customer:<slug>` tag at creation and after every update,
preventing cross-tenant IoC contamination in the shared threat-intel store.

## Why

MISP is operated as a shared threat-intel hub serving multiple customers. An
IoC introduced for Customer A must not auto-match Customer B without explicit
analyst review (GDPR data sovereignty). Tag enforcement is the foundation that
makes the manual cross-customer review workflow safe.

## Behavior

1. **Hook**: MISP event create/update via the Custom-Modules plugin spec.
2. **Validation**: Event must have exactly one tag matching `^customer:[a-z0-9-]+$`.
3. **On violation**:
   - Block the operation (event creation refused; update rolled back).
   - Emit a structured log line for Wazuh ingestion (rule ID assigned in private deployment repo).
   - Auto-repair job tags legacy events as `customer:UNKNOWN-NEEDS-REVIEW`.

## Cross-Customer Matching (V1 manual)

Even with tags enforced, MISP would by default surface cross-customer matches
in its UI. The deployment configuration disables auto-matching across customer
tags. Engineers requesting cross-customer IoC visibility must explicitly open
a pull request against the deployment-repo IoC-Catalog (Phase-2 will allow
automatic matching where the customer's DPA grants consent).

## Installation

Loaded as a MISP Custom-Module. Engineering team installs via Ansible role
`misp_customer_tag_enforcer` in the private deployment repo.

## License

AGPL-3.0-or-later (inherited from repo root).

## Status

🚧 **Implementation pending** — this README documents the design contract.
Engineer-Chat for `16-soc-enrichment` will deliver the module in Sub-Block 19.
