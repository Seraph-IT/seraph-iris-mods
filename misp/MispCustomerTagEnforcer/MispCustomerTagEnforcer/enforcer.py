"""Customer-tag validation for MISP events.

Same contract as IrisCustomerTagEnforcer — see iris/IrisCustomerTagEnforcer/.
Differences:
- Operates on MISP Event.Tag relationships rather than IRIS case tags
- Used by both create + edit hooks, plus an attribute-level enforcer (an
  attribute may not be added to an untagged event)
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
    """Base class for MISP tag-enforcement violations."""


class MissingCustomerTagError(CustomerTagViolation):
    pass


class MultipleCustomerTagsError(CustomerTagViolation):
    def __init__(self, found: list[str]) -> None:
        super().__init__(f"Multiple customer tags: {found!r}")
        self.found = found


class InvalidCustomerTagError(CustomerTagViolation):
    def __init__(self, raw: str) -> None:
        super().__init__(f"Invalid customer tag: {raw!r}")
        self.raw = raw


@dataclass(frozen=True, slots=True)
class ValidationResult:
    customer_slug: str
    matched_tag: str


class MispCustomerTagEnforcer:
    """Stateless validator. Auto-repair handled by a separate misp-shell job."""

    def validate(self, tags: Iterable[str]) -> ValidationResult:
        tags_list = list(tags)
        customer_tags = [t for t in tags_list if t.startswith("customer:")]

        if not customer_tags:
            logger.warning(
                "misp-customer-tag-enforcer.missing",
                extra={"tags_seen": tags_list},
            )
            raise MissingCustomerTagError("MISP event has no customer:<slug> tag.")

        if len(customer_tags) > 1:
            logger.error(
                "misp-customer-tag-enforcer.multiple",
                extra={"tags_seen": customer_tags},
            )
            raise MultipleCustomerTagsError(customer_tags)

        tag = customer_tags[0]
        if not CUSTOMER_TAG_PATTERN.match(tag):
            logger.error(
                "misp-customer-tag-enforcer.invalid",
                extra={"tag_seen": tag},
            )
            raise InvalidCustomerTagError(tag)

        slug = tag.removeprefix("customer:")
        return ValidationResult(customer_slug=slug, matched_tag=tag)

    def is_cross_customer_query(
        self,
        requester_slug: str,
        event_tags: Iterable[str],
    ) -> bool:
        """True if a requester tagged for customer A queries an event tagged
        for customer B. Used by the manual-review workflow (V1: blocks,
        Phase-2: gates by DPA-Consent)."""
        try:
            event = self.validate(event_tags)
        except CustomerTagViolation:
            # Untagged events are blocked upstream; treat as cross to be safe.
            return True
        return event.customer_slug != requester_slug
