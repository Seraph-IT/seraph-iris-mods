"""Customer-tag validation logic.

The Iris pipeline calls into `CustomerTagEnforcer.validate(tags)` on each
case create/update. Violations raise; the hook layer translates them into
4xx HTTP responses with a structured log line that Wazuh ingests via the
self-monitoring decoder (rule-range 102400-102499).
"""
from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass

logger = logging.getLogger(__name__)

CUSTOMER_TAG_PATTERN: re.Pattern[str] = re.compile(r"^customer:[a-z0-9-]+$")
UNKNOWN_TAG: str = "customer:unknown-needs-review"


class CustomerTagViolation(Exception):
    """Base class for tag-enforcement violations."""


class MissingCustomerTagError(CustomerTagViolation):
    """No `customer:<slug>` tag found on the case."""


class MultipleCustomerTagsError(CustomerTagViolation):
    """More than one `customer:<slug>` tag — ambiguous tenancy."""

    def __init__(self, found: list[str]) -> None:
        super().__init__(f"Multiple customer tags found: {found!r}")
        self.found = found


class InvalidCustomerTagError(CustomerTagViolation):
    """Tag does not match `customer:[a-z0-9-]+`."""

    def __init__(self, raw: str) -> None:
        super().__init__(f"Invalid customer tag format: {raw!r}")
        self.raw = raw


@dataclass(frozen=True, slots=True)
class ValidationResult:
    customer_slug: str
    matched_tag: str


class CustomerTagEnforcer:
    """Stateless validator. Auto-repair handled by a separate job."""

    def validate(self, tags: Iterable[str]) -> ValidationResult:
        """Return the resolved customer-slug, or raise a CustomerTagViolation."""
        tags_list = list(tags)
        customer_tags = [t for t in tags_list if t.startswith("customer:")]

        if not customer_tags:
            logger.warning(
                "iris-customer-tag-enforcer.missing",
                extra={"tags_seen": tags_list},
            )
            raise MissingCustomerTagError("Case has no customer:<slug> tag.")

        if len(customer_tags) > 1:
            logger.error(
                "iris-customer-tag-enforcer.multiple",
                extra={"tags_seen": customer_tags},
            )
            raise MultipleCustomerTagsError(customer_tags)

        tag = customer_tags[0]
        if not CUSTOMER_TAG_PATTERN.match(tag):
            logger.error(
                "iris-customer-tag-enforcer.invalid",
                extra={"tag_seen": tag},
            )
            raise InvalidCustomerTagError(tag)

        slug = tag.removeprefix("customer:")
        logger.info(
            "iris-customer-tag-enforcer.ok",
            extra={"customer_slug": slug},
        )
        return ValidationResult(customer_slug=slug, matched_tag=tag)

    def needs_review(self, tags: Iterable[str]) -> bool:
        """True if tags contain the auto-repair placeholder."""
        return UNKNOWN_TAG in list(tags)
