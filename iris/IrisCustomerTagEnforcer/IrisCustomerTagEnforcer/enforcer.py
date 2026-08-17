"""Customer-tag validation logic.

The Iris pipeline calls into `CustomerTagEnforcer.validate(tags)` on each
case create/update. Violations raise; the hook layer translates them into
4xx HTTP responses and writes a JSONL line that Wazuh matches
(rule-range **102600-102699**, see `audit.py`).

The range in this docstring used to read 102400-102499. That block was handed to
`18-active-directory` on 2026-05-26, so a rule written against this text would
have collided with someone else's detections.
"""
from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass

from . import audit

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
            audit.emit(audit.EVENT_MISSING, tags_seen=tags_list)
            raise MissingCustomerTagError("Case has no customer:<slug> tag.")

        if len(customer_tags) > 1:
            audit.emit(audit.EVENT_MULTIPLE, tags_seen=customer_tags)
            raise MultipleCustomerTagsError(customer_tags)

        tag = customer_tags[0]
        if not CUSTOMER_TAG_PATTERN.match(tag):
            audit.emit(audit.EVENT_INVALID, tag_seen=tag)
            raise InvalidCustomerTagError(tag)

        slug = tag.removeprefix("customer:")
        if tag == UNKNOWN_TAG:
            # Rule 102623 watches for the placeholder: a case carrying it was
            # repaired rather than tagged by whoever opened it, and still needs
            # a human to say which customer it belongs to.
            audit.emit(audit.EVENT_AUTO_REPAIR, customer_slug=slug)
        # The clean case is deliberately not an event. It happens on every valid
        # request; a stream that carries it would drown the four that matter and
        # no rule watches it.
        logger.debug("customer tag accepted: %s", slug)
        return ValidationResult(customer_slug=slug, matched_tag=tag)

    def needs_review(self, tags: Iterable[str]) -> bool:
        """True if tags contain the auto-repair placeholder."""
        return UNKNOWN_TAG in list(tags)
