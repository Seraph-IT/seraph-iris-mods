"""Tests for MispCustomerTagEnforcer (mirror of Iris variant)."""
from __future__ import annotations

import pytest

from src.enforcer import (
    UNKNOWN_TAG,
    InvalidCustomerTagError,
    MispCustomerTagEnforcer,
    MissingCustomerTagError,
    MultipleCustomerTagsError,
)


@pytest.fixture
def enforcer() -> MispCustomerTagEnforcer:
    return MispCustomerTagEnforcer()


def test_valid(enforcer):
    r = enforcer.validate(["customer:musterag", "tlp:amber"])
    assert r.customer_slug == "musterag"


def test_missing(enforcer):
    with pytest.raises(MissingCustomerTagError):
        enforcer.validate(["tlp:amber"])


def test_multiple(enforcer):
    with pytest.raises(MultipleCustomerTagsError):
        enforcer.validate(["customer:a", "customer:b"])


def test_invalid_uppercase(enforcer):
    with pytest.raises(InvalidCustomerTagError):
        enforcer.validate(["customer:MusterAG"])


def test_placeholder_passes(enforcer):
    r = enforcer.validate([UNKNOWN_TAG])
    assert r.customer_slug == "unknown-needs-review"


def test_cross_customer_query_same_slug(enforcer):
    assert enforcer.is_cross_customer_query(
        requester_slug="acme",
        event_tags=["customer:acme", "tlp:red"],
    ) is False


def test_cross_customer_query_different_slug(enforcer):
    assert enforcer.is_cross_customer_query(
        requester_slug="acme",
        event_tags=["customer:other-corp", "tlp:red"],
    ) is True


def test_cross_customer_query_untagged_treated_as_cross(enforcer):
    # Defense-in-depth: untagged events are blocked, but if one slipped
    # through the create-hook, treat queries as cross-customer.
    assert enforcer.is_cross_customer_query(
        requester_slug="acme",
        event_tags=["tlp:white"],
    ) is True
