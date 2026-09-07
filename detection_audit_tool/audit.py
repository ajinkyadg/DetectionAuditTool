"""Log validation / audit: for each rule, check whether the ingested log
sample actually carries the events and fields the rule depends on.

This answers the SOC-onboarding question "if I point this rule at our real
log feed, will it actually fire?" rather than just "is the rule syntax valid".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from .matcher import matches_selection
from .models import Event, Rule


def _base_selections(rule: Rule) -> List[Dict[str, Any]]:
    """The selection dict(s) that identify which events are 'in scope' for this rule,
    independent of aggregation/sequencing logic."""
    if rule.detection_type == "sequence":
        return [step.match for step in rule.steps]
    return [rule.selection] if rule.selection else []


@dataclass
class FieldCoverage:
    field: str
    present_count: int
    missing_count: int

    @property
    def total(self) -> int:
        return self.present_count + self.missing_count

    @property
    def coverage_pct(self) -> float:
        return 100.0 * self.present_count / self.total if self.total else 0.0


@dataclass
class RuleAudit:
    rule: Rule
    in_scope_events: int
    field_coverage: List[FieldCoverage] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        if self.in_scope_events == 0:
            return "NO_DATA"
        if not self.field_coverage:
            return "READY"
        worst = min((fc.coverage_pct for fc in self.field_coverage), default=100.0)
        if worst >= 99.9:
            return "READY"
        if worst >= 50.0:
            return "DEGRADED"
        return "NOT_READY"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule.id,
            "rule_title": self.rule.title,
            "verdict": self.verdict,
            "in_scope_events": self.in_scope_events,
            "field_coverage": [
                {
                    "field": fc.field,
                    "present": fc.present_count,
                    "missing": fc.missing_count,
                    "coverage_pct": round(fc.coverage_pct, 1),
                }
                for fc in self.field_coverage
            ],
            "audit_policy": self.rule.audit_policy,
        }


def audit_rule(rule: Rule, events: List[Event]) -> RuleAudit:
    selections = _base_selections(rule)
    in_scope = [e for e in events if any(matches_selection(e, sel) for sel in selections)]

    coverage: List[FieldCoverage] = []
    for req_field in rule.required_fields:
        present = sum(1 for e in in_scope if e.get(req_field) not in (None, ""))
        coverage.append(
            FieldCoverage(
                field=req_field,
                present_count=present,
                missing_count=len(in_scope) - present,
            )
        )

    return RuleAudit(rule=rule, in_scope_events=len(in_scope), field_coverage=coverage)


def audit_rules(rules: List[Rule], events: List[Event]) -> List[RuleAudit]:
    return [audit_rule(rule, events) for rule in rules]
