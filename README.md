# seraph-iris-mods

Public AGPL-3.0 modifications and custom modules for [IRIS-DFIR](https://dfir-iris.org/),
[Cortex](https://github.com/TheHive-Project/Cortex), and [MISP](https://www.misp-project.org/)
as deployed in the Seraph IT GmbH SOC-Enrichment-Stack.

## Why this repo exists

IRIS-DFIR, Cortex, and MISP are licensed under AGPL-3.0. Section 13 of the AGPL
("Remote Network Interaction") requires that modifications offered as a network
service to users be made available in source form to those users.

Seraph IT operates these tools as a managed SOC-Enrichment service for
customers. This repository contains all Seraph-IT custom modules, patches, and
plugins applied against the upstream projects, so that AGPL §13 obligations are
satisfied transparently.

Pure configuration (YAML files, Ansible variables, Grafana dashboard JSON) is
**not** AGPL-affected and lives in our private deployment repository.

## Layout

```
seraph-iris-mods/
├── iris/                              # IRIS-DFIR custom modules
│   └── IrisCustomerTagEnforcer/       # V1-Blocker: enforces customer:<slug> tag on every case
├── cortex/                            # Cortex custom analyzers/responders
│   └── (V1: none — Phase-2 roadmap)
└── misp/                              # MISP custom modules
    └── MispCustomerTagEnforcer/       # V1-Blocker: enforces customer:<slug> tag on every event
```

## Consumption

The private deployment repo embeds this repo as a git submodule under `mods/`:

```bash
git clone --recurse-submodules <private-repo-url>
```

A monthly drift-check workflow in the deployment repo verifies that the
deployed module hashes match this repo's `main` branch and opens a high-severity
ticket on mismatch.

## Contributing

External pull requests are welcome under the following constraints:

- Code must be AGPL-3.0-compatible.
- No customer data, secrets, or environment-specific configuration.
- At least one Seraph-IT maintainer approval before merge.

Bug reports via GitHub Issues. Customer support is **not** provided through
this repository.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).

## Disclaimer

This repository contains Seraph-IT operational code intended for use within the
Seraph IT SOC-Enrichment platform. The code is provided as-is, with no warranty
of fitness for any particular purpose. Customers receive these modifications
transparently as part of their service agreement; no separate customer-facing
APIs are exposed here.
