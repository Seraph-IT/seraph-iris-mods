"""The audit record is a contract with a rule file, so it is tested like one.

Every one of these assertions stands for a way this stream has already failed
somewhere in the stack:

* it was written through ``logger.warning(..., extra={...})``, and a
  ``"%(message)s"`` formatter dropped the context — so the line held no
  ``event`` field at all;
* the writers that did emit an event named it ``bridges.hmac-mismatch`` while
  the rule anchored on ``^hmac-mismatch$``;
* and the records that nested their payload under a key moved every field to
  ``data.<name>``, which is a different namespace from the one the matchers
  address for a flat object.

None of those are visible by reading the module. They are visible here.
"""
from __future__ import annotations

import json

from MispCustomerTagEnforcer import audit


def test_record_is_one_json_object_per_line(tmp_path, monkeypatch):
    log = tmp_path / "customer-tag-enforcer.json"
    monkeypatch.setenv(audit.LOG_PATH_ENV, str(log))

    audit.emit(audit.EVENT_MISSING, misp_event_id="7", tags_seen=["tlp:amber"])
    audit.emit(audit.EVENT_INVALID, misp_event_id="8", tag_seen="customer:NOPE")

    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    for line in lines:
        json.loads(line)


def test_the_two_matched_fields_are_flat_and_top_level(tmp_path, monkeypatch):
    """Wazuh addresses a flat JSON root by bare field name.

    Nesting the payload would move these to ``data.event`` and
    ``data.seraph_16_component``, and every 102630-102634 matcher would stop
    firing while the writer kept reporting success.
    """
    log = tmp_path / "customer-tag-enforcer.json"
    monkeypatch.setenv(audit.LOG_PATH_ENV, str(log))
    audit.emit(audit.EVENT_MULTIPLE, misp_event_id="9",
               tags_seen=["customer:a", "customer:b"])

    record = json.loads(log.read_text(encoding="utf-8"))
    assert record["event"] == audit.EVENT_MULTIPLE
    assert record["seraph_16_component"] == audit.COMPONENT
    assert all(not isinstance(value, dict) for value in record.values())


def test_no_event_name_carries_a_component_prefix():
    """The rule already scopes on the component; a prefix can only break it."""
    assert all("." not in event for event in audit.EVENTS)
    assert all(not event.startswith(audit.COMPONENT) for event in audit.EVENTS)


def test_emit_stays_silent_when_the_stream_is_unwritable(tmp_path, monkeypatch):
    """A sweep that dies because a log file is missing reports nothing at all.

    Degrading to the journal keeps the other findings of the same sweep.
    """
    monkeypatch.setenv(audit.LOG_PATH_ENV, str(tmp_path / "no-such-dir" / "x.json"))
    audit.emit(audit.EVENT_MISSING, misp_event_id="1")


def test_the_default_path_is_the_stream_the_agent_is_told_to_tail():
    """Hard-coded on purpose. The Wazuh localfile entry names this file; the
    two have to be edited together, and a test is the only thing that says so.
    """
    assert audit.DEFAULT_LOG_PATH == "/var/log/misp/customer-tag-enforcer.json"
