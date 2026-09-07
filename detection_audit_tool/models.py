"""Data model for rules, events, and detections."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

Event = Dict[str, Any]


@dataclass
class SequenceStep:
    name: str
    match: Dict[str, Any]
    threshold: int = 1


@dataclass
class Rule:
    id: str
    title: str
    description: str
    detection_type: str  # "selection" | "threshold" | "sequence"
    logsource: Dict[str, Any]
    level: str = "medium"
    mitre_attack: List[str] = field(default_factory=list)
    required_fields: List[str] = field(default_factory=list)
    false_positives: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    source_path: Optional[str] = None

    # identifiers this rule keys off of (Windows Event IDs, AWS eventName, etc.)
    # kept as strings so windows numeric IDs and cloud/linux named events share one index
    event_ids: List[str] = field(default_factory=list)

    # how to turn on the audit policy / logging config that produces the
    # events and fields this rule depends on
    audit_policy: Dict[str, Any] = field(default_factory=dict)

    # selection rules
    selection: Optional[Dict[str, Any]] = None

    # threshold rules
    groupby: Optional[str] = None
    timeframe_minutes: Optional[int] = None
    threshold: Optional[int] = None
    condition: str = "gte"

    # sequence rules
    steps: List[SequenceStep] = field(default_factory=list)


@dataclass
class Detection:
    rule: Rule
    group_value: Optional[str]
    matched_events: List[Event]
    summary: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule.id,
            "rule_title": self.rule.title,
            "level": self.rule.level,
            "mitre_attack": self.rule.mitre_attack,
            "group_value": self.group_value,
            "matched_event_count": len(self.matched_events),
            "summary": self.summary,
        }


def parse_time(event: Event) -> dt.datetime:
    ts = event.get("TimeCreated") or event.get("timestamp") or event.get("eventTime")
    if ts is None:
        raise ValueError(f"Event has no timestamp field: {event}")
    if isinstance(ts, dt.datetime):
        return ts
    return dt.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
