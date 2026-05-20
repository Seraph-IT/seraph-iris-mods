"""Unit tests for IrisCustomerTagEnforcer."""
from __future__ import annotations

import pytest

from src.enforcer import (
    UNKNOWN_TAG,
    CustomerTagEnforcer,
    InvalidCustomerTagError,
    MissingCustomerTagError,
    MultipleCustomerTagsError,
)


@pytest.fixture
def enforcer() -> CustomerTagEnforcer:
    return CustomerTagEnforcer()


def test_valid_single_tag(enforcer: CustomerTagEnforcer):
    r = enforcer.validate(["customer:musterag-koeln", "tlp:amber"])
    assert r.customer_slug == "musterag-koeln"
    assert r.matched_tag == "customer:musterag-koeln"


def test_missing(enforcer: CustomerTagEnforcer):
    with pytest.raises(MissingCustomerTagError):
        enforcer.validate(["tlp:amber", "kill-chain:lateral-movement"])


def test_empty(enforcer: CustomerTagEnforcer):
    with pytest.raises(MissingCustomerTagError):
        enforcer.validate([])


def test_multiple_tags_rejected(enforcer: CustomerTagEnforcer):
    with pytest.raises(MultipleCustomerTagsError) as exc:
        enforcer.validate(["customer:a-corp", "customer:b-corp"])
    assert exc.value.found == ["customer:a-corp", "customer:b-corp"]


def test_invalid_uppercase(enforcer: CustomerTagEnforcer):
    with pytest.raises(InvalidCustomerTagError):
        enforcer.validate(["customer:MusterAG"])


def test_invalid_underscore(enforcer: CustomerTagEnforcer):
    with pytest.raises(InvalidCustomerTagError):
        enforcer.validate(["customer:muster_ag"])


def test_invalid_dot(enforcer: CustomerTagEnforcer):
    with pytest.raises(InvalidCustomerTagError):
        enforcer.validate(["customer:muster.ag"])


def test_unknown_placeholder_passes_validation(enforcer: CustomerTagEnforcer):
    # Auto-repair job writes the placeholder; it must validate so the case
    # can be reopened/edited by an analyst without re-tag-then-save dance.
    r = enforcer.validate([UNKNOWN_TAG])
    assert r.customer_slug == "unknown-needs-review"


def test_needs_review_helper(enforcer: CustomerTagEnforcer):
    assert enforcer.needs_review([UNKNOWN_TAG, "tlp:red"]) is True
    assert enforcer.needs_review(["customer:musterag"]) is False


def test_slug_with_digits_and_dashes(enforcer: CustomerTagEnforcer):
    r = enforcer.validate(["customer:acme-001-de"])
    assert r.customer_slug == "acme-001-de"


def test_slug_too_short_acceptable(enforcer: CustomerTagEnforcer):
    # Single-char slug is grammatically valid; if business wants min-length
    # that's a separate rule and lives elsewhere.
    r = enforcer.validate(["customer:a"])
    assert r.customer_slug == "a"
