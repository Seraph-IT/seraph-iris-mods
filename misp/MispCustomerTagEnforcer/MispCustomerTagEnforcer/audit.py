"""Audit stream for MISP tag-enforcement findings (Wazuh rules 102630-102633).

Sibling of ``IrisCustomerTagEnforcer.audit`` and deliberately identical in
shape — same flat record, same convention that the event name carries no
component prefix, same promise never to raise. The reasons are written up
there and are not repeated here.

What differs is **who calls it**, and that difference is the whole point.

The IRIS enforcer runs inside IRIS and sees each case as it is written, so it
is preventive: it raises, and the case is refused. This module cannot do that.
MISP runs as a container stack (ADR-011) and its plugin loader is CakePHP, so a
Python validator dropped into ``app/Plugin/`` is never loaded — which is why
``/var/log/misp/customer-tag-enforcer.json`` stood at 0 bytes while the Wazuh
agent was already tailing it. ADR-012 settles that: enforcement runs *beside*
the container, polling the REST API.

So this stream is **detective, not preventive**. A finding here means a badly
tagged event already exists and was already visible to whoever could read it.
The delay between the write and the finding is the price of the container
boundary, and it is bounded by the poll interval, not by anything cleverer.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)

COMPONENT = "misp-tag-enforcer"

EVENT_MISSING = "customer-tag-missing"
EVENT_MULTIPLE = "multiple-customer-tags"
EVENT_INVALID = "invalid-customer-tag"

#: Emitted once per sweep when the poller could not reach MISP at all. Without
#: it, an unreachable MISP is indistinguishable from a clean sweep: both write
#: nothing, and "nothing" is what a healthy stack looks like.
EVENT_UNREACHABLE = "misp-unreachable"

#: Not in this tuple, on purpose: ``cross-customer-query`` (rule 102631).
#: Detecting it means seeing *reads*, and MISP only records those with
#: ``MISP.log_paranoid``, which is off on this stack. Claiming the event here
#: would put a name in the vocabulary that nothing can ever write — the exact
#: shape that let rules 102620-102623 sit dead for a month.
EVENTS = (EVENT_MISSING, EVENT_MULTIPLE, EVENT_INVALID, EVENT_UNREACHABLE)

#: The stream self_monitoring registers with the Wazuh agent. The agent runs on
#: the host and this poller runs on the host, so both mean the same file — no
#: bind mount in between, which is what broke the previous arrangement.
DEFAULT_LOG_PATH = "/var/log/misp/customer-tag-enforcer.json"
LOG_PATH_ENV = "SERAPH_16_MISP_TAG_AUDIT_LOG"


def log_path() -> str:
    return os.environ.get(LOG_PATH_ENV) or DEFAULT_LOG_PATH


def emit(event: str, **fields: Any) -> None:
    """Append one JSON object per line. Never raises."""
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
        logger.exception("misp tag-audit stream %s is not writable", log_path())
