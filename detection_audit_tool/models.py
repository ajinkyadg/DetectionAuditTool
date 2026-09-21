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
class ResponseAction:
    id: str
    label: str
    # SANS PICERL phase: preparation | containment | eradication | recovery
    phase: str = "containment"


@dataclass
class Stage:
    """One step of an incident's kill chain.

    `index` is meaningful, not just ordering: an entity's `furthest_stage` is
    compared against it to decide who got how far, and checking a response
    action caps every entity at that action's stage index.
    """

    id: str
    index: int
    name: str
    mitre: List[str] = field(default_factory=list)
    narrative: str = ""
    rule_ids: List[str] = field(default_factory=list)
    actions: List[ResponseAction] = field(default_factory=list)
    icon: str = ""
    # Set when no internal log source can see this step at all. The *why* is the
    # most valuable part of an incident, so this is prose rather than a flag.
    blind_spot_note: str = ""


@dataclass
class AffectedEntity:
    """Whoever the incident happened to - a mailbox for a phishing campaign, a
    host for an intrusion. `furthest_stage` of -1 means never reached at all.
    """

    name: str
    identifier: str
    furthest_stage: int
    status: str  # an id from the incident's status_model
    note: str = ""


@dataclass
class StatusLevel:
    """One rung of an incident's own status ladder.

    Incidents don't share a status vocabulary - a phishing campaign ends at
    "compromised (active)", a ransomware intrusion ends at "encrypted" - so the
    ladder is declared per incident instead of hardcoded in each renderer.
    `tone` is semantic rather than a colour, leaving the palette to whichever
    renderer is drawing it.
    """

    id: str
    label: str
    tone: str  # good | neutral | warn | bad | critical
    # Highest furthest_stage still mapping to this level; None = catch-all top rung.
    max_stage: Optional[int] = None
    # A containment cap can never clear a sticky status: capping tells you
    # nothing about an entity you have no telemetry for.
    sticky: bool = False


@dataclass
class Incident:
    id: str
    slug: str
    title: str
    summary: str
    stages: List[Stage] = field(default_factory=list)
    entities: List[AffectedEntity] = field(default_factory=list)
    status_model: List[StatusLevel] = field(default_factory=list)
    # Attribution for incidents derived from published research: {name, url}.
    source: Dict[str, str] = field(default_factory=dict)
    # Free-form header facts, rendered as the incident's summary card.
    scenario: Dict[str, Any] = field(default_factory=dict)
    # Column header for the triage table ("Mailbox", "Host").
    entity_label: str = "Entity"
    # Emoji shown beside the incident name in both renderers.
    icon: str = "\U0001f6a8"
    # {correlator, log, ...} - see evidence.CORRELATORS. Optional: an incident
    # may assert its outcomes without a log source behind them.
    evidence: Optional[Dict[str, Any]] = None
    source_path: Optional[str] = None

    def derive_status(self, furthest_stage: int, original_status: str) -> str:
        """The status implied by how far an entity got, per this incident's ladder.

        A sticky original status wins over whatever the ladder would say.
        """
        current = next((s for s in self.status_model if s.id == original_status), None)
        if current is not None and current.sticky:
            return current.id
        for level in self.status_model:
            if level.max_stage is not None and furthest_stage <= level.max_stage:
                return level.id
        return self.status_model[-1].id

    def stage_reach_counts(self) -> Dict[str, int]:
        return {
            s.id: sum(1 for e in self.entities if e.furthest_stage >= s.index)
            for s in self.stages
        }


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
