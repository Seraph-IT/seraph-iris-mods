"""IrisCustomerTagEnforcer — defense-in-depth customer-tag enforcement.

Public AGPL-3.0 module. Source-of-truth: Seraph-IT/seraph-iris-mods.

Hooks into IRIS case create/update events and refuses any case lacking a
single `customer:<slug>` tag matching ^customer:[a-z0-9-]+$.

V1-Blocker #4 for 16-soc-enrichment (Sub-Block 10).
"""

from .enforcer import (
    CustomerTagEnforcer,
    InvalidCustomerTagError,
    MissingCustomerTagError,
    MultipleCustomerTagsError,
)

__all__ = [
    "CustomerTagEnforcer",
    "InvalidCustomerTagError",
    "MissingCustomerTagError",
    "MultipleCustomerTagsError",
]

__version__ = "0.1.0"
