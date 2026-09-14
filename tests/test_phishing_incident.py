import os

from detection_audit_tool.phishing_incident import (
    STAGES,
    USERS,
    correlate_web_proxy_evidence,
    stage_reach_counts,
)
from detection_audit_tool.rule_loader import load_rules

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules")


def test_every_stage_rule_id_exists_in_the_catalogue():
    rules = load_rules(RULES_DIR)
    known_ids = {r.id for r in rules}
    for stage in STAGES:
        for rule_id in stage.rule_ids:
            assert rule_id in known_ids, f"stage '{stage.id}' references unknown rule '{rule_id}'"


def test_stage_reach_counts_are_monotonically_non_increasing():
    counts = stage_reach_counts()
    ordered = [counts[s.id] for s in STAGES]
    assert ordered == sorted(ordered, reverse=True)
    assert ordered[0] < len(USERS), "at least one user should have been blocked before/at delivery"


def test_web_proxy_correlation_confirms_who_clicked_and_who_entered_credentials():
    evidence = correlate_web_proxy_evidence()

    for user in USERS:
        ev = evidence[user.mailbox]
        clicked_per_narrative = user.furthest_stage >= 1
        creds_per_narrative = user.furthest_stage >= 2

        assert ev["clicked"] == clicked_per_narrative, (
            f"{user.name}: proxy log says clicked={ev['clicked']}, "
            f"narrative says {clicked_per_narrative}"
        )
        assert ev["credentials_entered"] == creds_per_narrative, (
            f"{user.name}: proxy log says credentials_entered={ev['credentials_entered']}, "
            f"narrative says {creds_per_narrative}"
        )


def test_users_who_never_clicked_have_no_proxy_evidence():
    evidence = correlate_web_proxy_evidence()
    for user in USERS:
        if user.furthest_stage < 1:
            assert evidence[user.mailbox]["events"] == []
