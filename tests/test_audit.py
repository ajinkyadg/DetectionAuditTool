import os

from detection_audit_tool.audit import audit_rules
from detection_audit_tool.lookup import lookup_event, search
from detection_audit_tool.rule_loader import load_rules

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules")


def test_lookup_by_event_id_returns_expected_rules():
    rules = load_rules(RULES_DIR)
    matched = lookup_event(rules, "4625")
    ids = {r.id for r in matched}
    assert "WIN-1001" in ids
    assert "WIN-1002" in ids


def test_search_by_mitre_technique():
    rules = load_rules(RULES_DIR)
    matched = search(rules, "T1110")
    assert any(r.id == "WIN-1001" for r in matched)
    assert any(r.id == "LIN-2001" for r in matched)


def test_audit_flags_missing_required_field():
    rules = load_rules(RULES_DIR)
    win1001 = next(r for r in rules if r.id == "WIN-1001")

    events = [
        {
            "EventID": 4625,
            "TimeCreated": "2026-01-15T09:00:00+00:00",
            "TargetUserName": "jsmith",
            "IpAddress": "203.0.113.55",
            "LogonType": 3,
            # WorkstationName intentionally omitted
        }
    ]
    audits = audit_rules([win1001], events)
    assert len(audits) == 1
    workstation_coverage = next(
        fc for fc in audits[0].field_coverage if fc.field == "WorkstationName"
    )
    assert workstation_coverage.coverage_pct == 0.0
    assert audits[0].verdict == "NOT_READY"


def test_audit_no_data_when_event_id_absent_from_logs():
    rules = load_rules(RULES_DIR)
    win1003 = next(r for r in rules if r.id == "WIN-1003")
    audits = audit_rules([win1003], [{"EventID": 4624, "TimeCreated": "2026-01-15T09:00:00+00:00"}])
    assert audits[0].verdict == "NO_DATA"
