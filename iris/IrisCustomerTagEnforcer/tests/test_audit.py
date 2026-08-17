"""The audit record is a contract with a rule file, so it is tested like one.

Mirror of the MISP module's test_audit.py; the reasoning is written up there
and applies here unchanged. These four assertions each stand for a way this
stream has already failed in this stack — context lost to ``extra=``, event
names carrying a component prefix the anchored regex rejected, and payloads
nested one level so every field moved to a namespace the matchers do not read.

Rules 102620-102623 depend on all of it and none of it is visible by reading
the module.
"""
from __future__ import annotations

import json

from IrisCustomerTagEnforcer import audit


def test_record_is_one_json_object_per_line(tmp_path, monkeypatch):
    log = tmp_path / "customer-tag-enforcer.json"
    monkeypatch.setenv(audit.LOG_PATH_ENV, str(log))

    audit.emit(audit.EVENT_MISSING, tags_seen=["tlp:amber"])
    audit.emit(audit.EVENT_AUTO_REPAIR, case_id=42)

    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    for line in lines:
        json.loads(line)


def test_the_two_matched_fields_are_flat_and_top_level(tmp_path, monkeypatch):
    log = tmp_path / "customer-tag-enforcer.json"
    monkeypatch.setenv(audit.LOG_PATH_ENV, str(log))
    audit.emit(audit.EVENT_MULTIPLE, tags_seen=["customer:a", "customer:b"])

    record = json.loads(log.read_text(encoding="utf-8"))
    assert record["event"] == audit.EVENT_MULTIPLE
    assert record["seraph_16_component"] == audit.COMPONENT
    assert all(not isinstance(value, dict) for value in record.values())


def test_no_event_name_carries_a_component_prefix():
    assert all("." not in event for event in audit.EVENTS)
    assert all(not event.startswith(audit.COMPONENT) for event in audit.EVENTS)


def test_emit_stays_silent_when_the_stream_is_unwritable(tmp_path, monkeypatch):
    """Writing runs inside IRIS's request handling. Taking the case API down
    over an unwritable log file is worse than degrading to the journal.
    """
    monkeypatch.setenv(audit.LOG_PATH_ENV, str(tmp_path / "no-such-dir" / "x.json"))
    audit.emit(audit.EVENT_MISSING)


def test_the_default_path_is_the_stream_the_agent_is_told_to_tail():
    assert audit.DEFAULT_LOG_PATH == "/var/log/iris/customer-tag-enforcer.json"
