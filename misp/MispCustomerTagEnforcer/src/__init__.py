"""MispCustomerTagEnforcer — defense-in-depth customer-tag enforcement for MISP.

Mirror to IrisCustomerTagEnforcer; same regex contract. Public AGPL-3.0.
V1-Blocker #3 for 16-soc-enrichment (Sub-Block 19).
"""

from .enforcer import (
    UNKNOWN_TAG,
    InvalidCustomerTagError,
    MispCustomerTagEnforcer,
    MissingCustomerTagError,
    MultipleCustomerTagsError,
    ValidationResult,
)

__all__ = [
    "MispCustomerTagEnforcer",
    "ValidationResult",
    "MissingCustomerTagError",
    "MultipleCustomerTagsError",
    "InvalidCustomerTagError",
    "UNKNOWN_TAG",
]

__version__ = "0.1.0"
