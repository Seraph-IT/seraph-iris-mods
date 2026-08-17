"""IRIS plugin hook entry-points.

This module is loaded by IRIS via its plugin loader. The hook functions
receive the same kwargs IRIS's internal event dispatcher provides.

Hook lifecycle:
    case.before_create  -> enforce_create(case_payload)
    case.before_update  -> enforce_update(case_id, updated_fields)

On violation: raise HTTPException(403) so IRIS surfaces the error to the API
caller. Frontend should display the error verbatim — analysts learn the
constraint by hitting it.
"""
from __future__ import annotations

import logging
from typing import Any

from .enforcer import (
    CustomerTagEnforcer,
    CustomerTagViolation,
)

logger = logging.getLogger(__name__)
_enforcer = CustomerTagEnforcer()


def enforce_create(case_payload: dict[str, Any]) -> None:
    """Refuse case creation without exactly one customer:<slug> tag."""
    tags = case_payload.get("tags", []) or []
    try:
        result = _enforcer.validate(tags)
    except CustomerTagViolation as exc:
        logger.error(
            "iris-customer-tag-enforcer.create-refused",
            extra={"reason": exc.__class__.__name__, "tags": tags},
        )
        raise _to_http_403(exc) from exc
    case_payload["_seraph_customer_slug"] = result.customer_slug


def enforce_update(case_id: int, updated_fields: dict[str, Any]) -> None:
    """Refuse case update that would remove or break the customer:<slug> tag."""
    if "tags" not in updated_fields:
        # Tag-untouched updates pass through.
        return
    try:
        _enforcer.validate(updated_fields["tags"])
    except CustomerTagViolation as exc:
        logger.error(
            "iris-customer-tag-enforcer.update-refused",
            extra={"case_id": case_id, "reason": exc.__class__.__name__},
        )
        raise _to_http_403(exc) from exc


def _to_http_403(exc: CustomerTagViolation) -> Exception:
    """Adapter to IRIS' HTTP exception. Plugin loader injects the type at
    import time; we lazy-import to keep tests independent of IRIS."""
    try:
        from iris.app.exceptions import HTTPForbiddenError  # type: ignore[import-not-found]
    except ImportError:
        # Fallback when run outside IRIS (e.g. unit tests).
        return PermissionError(str(exc))
    return HTTPForbiddenError(str(exc))
