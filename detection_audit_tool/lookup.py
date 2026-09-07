"""Search the rule catalogue by event ID / eventName / keyword."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from .models import Rule


def build_event_index(rules: List[Rule]) -> Dict[str, List[Rule]]:
    index: Dict[str, List[Rule]] = defaultdict(list)
    for rule in rules:
        for event_id in rule.event_ids:
            index[str(event_id)].append(rule)
    return index


def lookup_event(rules: List[Rule], event_id: str) -> List[Rule]:
    return build_event_index(rules).get(str(event_id), [])


def search(rules: List[Rule], query: str) -> List[Rule]:
    """Loose keyword search across id, title, event ids, and MITRE technique ids."""
    q = query.strip().lower()
    if not q:
        return list(rules)

    matched = []
    for rule in rules:
        haystack = [
            rule.id.lower(),
            rule.title.lower(),
            rule.description.lower(),
            *[e.lower() for e in rule.event_ids],
            *[t.lower() for t in rule.mitre_attack],
        ]
        if any(q in field for field in haystack):
            matched.append(rule)
    return matched
