"""Audit stream for tag-enforcement decisions (Wazuh rules 102620-102623).

The enforcer used to log its violations as plain-text messages with the context
in ``extra=``::

    logger.warning("iris-customer-tag-enforcer.missing", extra={"tags_seen": ...})

A ``"%(message)s"`` formatter drops ``extra`` on the floor, and the rules match
``event`` as an anchored regex on a JSON line. So nothing a rule could match was
ever written, and ``/var/log/iris/customer-tag-enforcer.json`` sat at 0 bytes
from 2026-07-29 until this module existed — while the Wazuh agent was wired to
tail it, which reads as coverage.

Two conventions, both load-bearing and both learned the expensive way:

* the event name carries **no component prefix** — the rule already scopes on
  ``seraph_16_component``, and a prefix can only break the match;
* both fields go **in the line**, flat. Wazuh's analysisd flattens the record
  root for matching, so a flat JSON object is addressed by bare field names.
  Nesting the payload under a key would move it to ``data.<field>`` and the
  rules would stop matching. Verified on a live manager (4.14.6) against real
  lines from this stack.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)

COMPONENT = "iris-tag-enforcer"

EVENT_MISSING = "customer-tag-missing"
EVENT_MULTIPLE = "multiple-customer-tags"
EVENT_INVALID = "invalid-customer-tag"
EVENT_AUTO_REPAIR = "auto-repair-placeholder"

#: Every event this component can emit. The vocabulary test in the consuming
#: repo imports this rather than grepping for string literals — a scan of source
#: text reads comments and misses values that live in a branch.
EVENTS = (EVENT_MISSING, EVENT_MULTIPLE, EVENT_INVALID, EVENT_AUTO_REPAIR)

#: The stream self_monitoring registers with the Wazuh agent. A default rather
#: than a required setting: an unset environment variable would otherwise mean
#: silence, and silence is what this module exists to end.
DEFAULT_LOG_PATH = "/var/log/iris/customer-tag-enforcer.json"
LOG_PATH_ENV = "SERAPH_16_TAG_ENFORCER_AUDIT_LOG"


def log_path() -> str:
    return os.environ.get(LOG_PATH_ENV) or DEFAULT_LOG_PATH


def emit(event: str, **fields: Any) -> None:
    """Append one JSON object per line. Never raises.

    Writing runs inside IRIS's own request handling. A tag enforcer that takes
    the case API down because a log file is unwritable is worse than one that
    degrades to the journal — the same call this repo made for the bridges after
    the severity engine went into a restart loop over exactly that.
    """
    record = {
        "timestamp_iso": datetime.now(UTC).isoformat(),
        "event": event,
        "seraph_16_component": COMPONENT,
        **fields,
    }
    try:
        with open(log_path(), "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
    except OSError:
        logger.exception("tag-enforcer audit stream %s is not writable", log_path())
