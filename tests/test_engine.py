import os

from detection_audit_tool.matcher import run_rules
from detection_audit_tool.rule_loader import load_rules
from detection_audit_tool.simulator import build_brute_force_scenario

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules")


def test_all_rules_load_without_error():
    rules = load_rules(RULES_DIR)
    assert len(rules) >= 8
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids)), "duplicate rule ids"


def test_brute_force_sequence_rule_fires_on_simulated_attack():
    rules = load_rules(RULES_DIR)
    events = build_brute_force_scenario(failed_attempts=6)
    detections = run_rules(rules, events)
    fired_ids = {d.rule.id for d in detections}
    assert "WIN-1001" in fired_ids


def test_brute_force_sequence_rule_does_not_fire_below_threshold():
    rules = load_rules(RULES_DIR)
    events = build_brute_force_scenario(failed_attempts=2)
    detections = run_rules(rules, events)
    fired_ids = {d.rule.id for d in detections}
    assert "WIN-1001" not in fired_ids


def test_rdp_threshold_rule_fires():
    rules = load_rules(RULES_DIR)
    events = [
        {
            "EventID": 4625,
            "TimeCreated": f"2026-01-15T09:00:{i:02d}+00:00",
            "TargetUserName": "admin",
            "IpAddress": "198.51.100.9",
            "LogonType": 10,
        }
        for i in range(10)
    ]
    detections = run_rules(rules, events)
    fired_ids = {d.rule.id for d in detections}
    assert "WIN-1002" in fired_ids
