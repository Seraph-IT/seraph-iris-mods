# IrisCustomerTagEnforcer

V1-Blocker module for the Seraph-IT SOC-Enrichment-Stack. Enforces that every
IRIS-DFIR case carries a `customer:<slug>` tag at creation and after every
update, blocking accidental cross-tenant data leaks.

## Why

IRIS is operated as a multi-tenant DFIR hub. Cases without a customer tag risk
landing in the "untagged" bucket and being acted on by SOC analysts in the
wrong customer context — a GDPR Art.5(1)(c) (data minimization) and Art.32
(security of processing) violation.

This module is **defense-in-depth**: SOC procedures already require analysts
to tag cases. This module programmatically enforces it.

## Behavior

1. **Hook**: IRIS `case.create` and `case.update` events.
2. **Validation**: Case must have exactly one tag matching `^customer:[a-z0-9-]+$`.
3. **On violation**:
   - Block the operation with a 4xx HTTP response (`case.create` denied; `case.update` rejected, prior state retained).
   - Emit a structured log line consumable by Wazuh (rule ID assigned in private deployment repo, range `102400-102499`).
   - Auto-repair job runs every 5 minutes against legacy cases lacking the tag and either:
     - Heuristically infers the customer from case observables (configurable allow/deny logic)
     - Tags the case as `customer:UNKNOWN-NEEDS-REVIEW` and queues an analyst review

## Installation

Loaded by IRIS plugin loader. Engineering team installs via Ansible role
`iris_customer_tag_enforcer` in the private deployment repo.

## Configuration

Pure-config lives outside this repo (`16-soc-enrichment/ansible/roles/.../vars/*.yml`).
This module reads its config from the IRIS-standard plugin-config interface;
no environment-specific values are hardcoded here.

## License

AGPL-3.0-or-later (inherited from repo root).

## Status

🚧 **Implementation pending** — this README documents the design contract.
Engineer-Chat for `16-soc-enrichment` will deliver the module in Sub-Block 10.
