"""Invariants every incident must hold.

These loop over whatever `incidents/` contains rather than naming one, so an
incident added later inherits the same guarantees for free. The important one is
the last: an incident's narrative has to agree with the log evidence behind it,
or the walkthrough is just assertions with a chart on top.
"""

import os

from detection_audit_tool.evidence import correlate
from detection_audit_tool.incident_loader import load_incidents
from detection_audit_tool.rule_loader import load_rules

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(PROJECT_ROOT, "rules")
INCIDENTS_DIR = os.path.join(PROJECT_ROOT, "incidents")

INCIDENTS = load_incidents(INCIDENTS_DIR)


def test_incident_catalogue_loads():
    assert INCIDENTS, "no incidents found"
    ids = [i.id for i in INCIDENTS]
    assert len(set(ids)) == len(ids), f"duplicate incident ids in {ids}"


def test_every_stage_rule_id_exists_in_the_catalogue():
    known_ids = {r.id for r in load_rules(RULES_DIR)}
    for incident in INCIDENTS:
        for stage in incident.stages:
            for rule_id in stage.rule_ids:
                assert rule_id in known_ids, (
                    f"{incident.id} stage '{stage.id}' references unknown rule '{rule_id}'"
                )


def test_stage_reach_counts_are_monotonically_non_increasing():
    for incident in INCIDENTS:
        counts = incident.stage_reach_counts()
        ordered = [counts[s.id] for s in incident.stages]
        assert ordered == sorted(ordered, reverse=True), f"{incident.id}: {ordered}"
        assert ordered[0] < len(incident.entities), (
            f"{incident.id}: at least one entity should have been stopped at or before stage 0"
        )


def test_declared_status_matches_the_incidents_own_ladder():
    # If these disagree, either the narrative or the status ladder is wrong, and
    # the before/after impact panel would be quietly misleading.
    for incident in INCIDENTS:
        for entity in incident.entities:
            derived = incident.derive_status(entity.furthest_stage, entity.status)
            assert derived == entity.status, (
                f"{incident.id}: {entity.identifier} declares '{entity.status}' but the "
                f"ladder derives '{derived}' from furthest_stage {entity.furthest_stage}"
            )


def test_every_incident_has_at_least_one_documented_blind_spot():
    # A chain where every step is covered is a chain we modelled dishonestly.
    for incident in INCIDENTS:
        assert any(s.blind_spot_note for s in incident.stages), (
            f"{incident.id} claims full detection coverage - suspicious"
        )


def test_response_action_ids_are_unique_within_an_incident():
    # Selection state is keyed by action id; a collision would tick two boxes at once.
    for incident in INCIDENTS:
        ids = [a.id for s in incident.stages for a in s.actions]
        assert len(set(ids)) == len(ids), f"{incident.id}: duplicate action ids in {ids}"


def test_evidence_agrees_with_each_entitys_furthest_stage():
    """The claim the whole exercise rests on: outcomes are correlated from a log,
    not asserted. Each incident declares which stage its evidence proves.
    """
    for incident in INCIDENTS:
        if not incident.evidence:
            continue
        proves = incident.evidence.get("proves", {})
        if not proves:
            continue
        evidence = correlate(incident, PROJECT_ROOT)
        for entity in incident.entities:
            found = evidence[entity.identifier]
            for flag, min_stage in proves.items():
                expected = entity.furthest_stage >= min_stage
                assert found[flag] == expected, (
                    f"{incident.id}: {entity.identifier} log says {flag}={found[flag]}, "
                    f"but furthest_stage {entity.furthest_stage} implies {expected}"
                )


def test_entities_below_the_evidence_threshold_have_no_events():
    for incident in INCIDENTS:
        if not incident.evidence:
            continue
        proves = incident.evidence.get("proves", {})
        if not proves:
            continue
        floor = min(proves.values())
        evidence = correlate(incident, PROJECT_ROOT)
        for entity in incident.entities:
            if entity.furthest_stage < floor:
                assert evidence[entity.identifier]["events"] == [], (
                    f"{incident.id}: {entity.identifier} never reached stage {floor} "
                    f"but has correlated events"
                )
