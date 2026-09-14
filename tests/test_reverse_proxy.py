import json
import os

from detection_audit_tool.matcher import run_rules
from detection_audit_tool.rule_loader import load_rules

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules")
SAMPLE_LOG = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sample_logs", "reverse_proxy_sample.json"
)


def _load_sample_events():
    with open(SAMPLE_LOG, "r", encoding="utf-8") as fh:
        return json.load(fh)


def test_all_five_reverse_proxy_rules_fire_on_sample_log():
    rules = load_rules(RULES_DIR)
    events = _load_sample_events()
    detections = run_rules(rules, events)
    fired_ids = {d.rule.id for d in detections}
    for expected in ("RP-7001", "RP-7002", "RP-7003", "RP-7004", "RP-7005"):
        assert expected in fired_ids, f"{expected} did not fire against the sample log"


def test_host_sni_mismatch_does_not_fire_when_they_match():
    rules = load_rules(RULES_DIR)
    rp7001 = next(r for r in rules if r.id == "RP-7001")
    events = [
        {
            "timestamp": "2026-03-01T08:00:00+00:00",
            "client_ip": "198.51.100.1",
            "Host": "shop.corp.com",
            "SNI": "shop.corp.com",
            "uri": "/",
        }
    ]
    assert run_rules([rp7001], events) == []


def test_backend_error_spike_does_not_fire_below_threshold():
    rules = load_rules(RULES_DIR)
    rp7004 = next(r for r in rules if r.id == "RP-7004")
    events = [
        {
            "timestamp": f"2026-03-01T08:00:{i:02d}+00:00",
            "upstream_addr": "10.10.1.7:8080",
            "upstream_status": 502,
            "uri": "/x",
            "client_ip": "198.51.100.1",
        }
        for i in range(5)
    ]
    assert run_rules([rp7004], events) == []
