"""Detection engine: evaluates selection / threshold / sequence rules against events."""

from __future__ import annotations

import datetime as dt
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional

from .models import Detection, Event, Rule, parse_time


def field_matches(event: Event, field: str, expected: Any) -> bool:
    if field not in event:
        return False
    value = event[field]
    if isinstance(expected, list):
        return value in expected
    return value == expected


def matches_selection(event: Event, selection: Dict[str, Any]) -> bool:
    return all(field_matches(event, field, expected) for field, expected in selection.items())


def _sorted_by_time(events: List[Event]) -> List[Event]:
    return sorted(events, key=parse_time)


def evaluate_selection_rule(rule: Rule, events: List[Event]) -> List[Detection]:
    matched = [e for e in events if matches_selection(e, rule.selection)]
    if not matched:
        return []
    return [
        Detection(
            rule=rule,
            group_value=None,
            matched_events=matched,
            summary=f"{len(matched)} event(s) matched selection for '{rule.title}'",
        )
    ]


def evaluate_threshold_rule(rule: Rule, events: List[Event]) -> List[Detection]:
    matched = [e for e in events if matches_selection(e, rule.selection)]
    if not matched:
        return []

    window = dt.timedelta(minutes=rule.timeframe_minutes or 0)
    groups: Dict[Optional[str], List[Event]] = defaultdict(list)
    for event in _sorted_by_time(matched):
        key = event.get(rule.groupby) if rule.groupby else "__all__"
        groups[key].append(event)

    detections: List[Detection] = []
    threshold = rule.threshold or 1
    for key, group_events in groups.items():
        buffer: deque = deque()
        fired_end: Optional[dt.datetime] = None
        for event in group_events:
            ts = parse_time(event)
            buffer.append(event)
            while window and parse_time(buffer[0]) < ts - window:
                buffer.popleft()
            if len(buffer) >= threshold:
                if fired_end is None or ts > fired_end:
                    detections.append(
                        Detection(
                            rule=rule,
                            group_value=str(key),
                            matched_events=list(buffer),
                            summary=(
                                f"{len(buffer)} event(s) matched '{rule.title}' "
                                f"for {rule.groupby}={key} within {rule.timeframe_minutes}m"
                            ),
                        )
                    )
                    fired_end = ts
                    buffer.clear()
    return detections


def evaluate_sequence_rule(rule: Rule, events: List[Event]) -> List[Detection]:
    """Detect an ordered sequence of steps (e.g. N failed logons then one success)
    occurring for the same group key within the rule's timeframe."""
    window = dt.timedelta(minutes=rule.timeframe_minutes or 0)
    ordered = _sorted_by_time(events)

    groups: Dict[Optional[str], List[Event]] = defaultdict(list)
    for event in ordered:
        key = event.get(rule.groupby) if rule.groupby else "__all__"
        groups[key].append(event)

    detections: List[Detection] = []
    for key, group_events in groups.items():
        step_idx = 0
        step_counts = 0
        step_events: List[Event] = []
        window_start: Optional[dt.datetime] = None

        for event in group_events:
            step = rule.steps[step_idx]
            if not matches_selection(event, step.match):
                continue

            ts = parse_time(event)
            if window_start is None:
                window_start = ts
            elif window and ts - window_start > window:
                # window expired before the sequence completed; restart at this event
                step_idx = 0
                step_counts = 0
                step_events = []
                window_start = ts
                step = rule.steps[step_idx]
                if not matches_selection(event, step.match):
                    continue

            step_events.append(event)
            step_counts += 1
            if step_counts >= step.threshold:
                step_idx += 1
                step_counts = 0
                if step_idx >= len(rule.steps):
                    step_names = " -> ".join(s.name for s in rule.steps)
                    detections.append(
                        Detection(
                            rule=rule,
                            group_value=str(key),
                            matched_events=list(step_events),
                            summary=(
                                f"Sequence [{step_names}] completed for "
                                f"{rule.groupby}={key} within {rule.timeframe_minutes}m"
                            ),
                        )
                    )
                    step_idx = 0
                    step_counts = 0
                    step_events = []
                    window_start = None
    return detections


def evaluate_rule(rule: Rule, events: List[Event]) -> List[Detection]:
    if rule.detection_type == "selection":
        return evaluate_selection_rule(rule, events)
    if rule.detection_type == "threshold":
        return evaluate_threshold_rule(rule, events)
    if rule.detection_type == "sequence":
        return evaluate_sequence_rule(rule, events)
    raise ValueError(f"Unknown detection_type '{rule.detection_type}' for rule {rule.id}")


def run_rules(rules: List[Rule], events: List[Event]) -> List[Detection]:
    detections: List[Detection] = []
    for rule in rules:
        detections.extend(evaluate_rule(rule, events))
    return detections
