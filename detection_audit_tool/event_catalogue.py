"""Windows Security Event reference catalogue - facts about each event
(what it means, what fields it carries, how to turn on the audit policy that
produces it), independent of whether a detection rule exists for it yet.

This is the "encyclopedia" layer; rules/ is the detection-logic layer.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import yaml

DEFAULT_CATALOGUE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "reference",
    "windows_security_events.yml",
)


@dataclass
class WindowsEvent:
    event_id: str
    name: str
    category: str
    subcategory: str
    criticality: str
    description: str
    key_fields: List[str] = field(default_factory=list)
    sample_log: Dict[str, Any] = field(default_factory=dict)
    audit_policy: Dict[str, Any] = field(default_factory=dict)
    mitre_attack: List[str] = field(default_factory=list)
    related_rules: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    logon_types: Dict[str, str] = field(default_factory=dict)


CATEGORY_ORDER = [
    "Account Logon",
    "Logon/Logoff",
    "Account Management",
    "Detailed Tracking",
    "DS Access",
    "Object Access",
    "Policy Change",
    "Privilege Use",
    "System",
]


def load_windows_events(path: str = DEFAULT_CATALOGUE_PATH) -> List[WindowsEvent]:
    with open(path, "r", encoding="utf-8") as fh:
        docs = yaml.safe_load(fh) or []

    events = [
        WindowsEvent(
            event_id=str(doc["event_id"]),
            name=doc["name"],
            category=doc["category"],
            subcategory=doc.get("subcategory", ""),
            criticality=doc.get("criticality", "informational"),
            description=doc.get("description", ""),
            key_fields=doc.get("key_fields", []),
            sample_log=doc.get("sample_log", {}),
            audit_policy=doc.get("audit_policy", {}),
            mitre_attack=doc.get("mitre_attack", []),
            related_rules=doc.get("related_rules", []),
            references=doc.get("references", []),
            logon_types={str(k): v for k, v in (doc.get("logon_types") or {}).items()},
        )
        for doc in docs
    ]

    def sort_key(e: WindowsEvent):
        try:
            cat_rank = CATEGORY_ORDER.index(e.category)
        except ValueError:
            cat_rank = len(CATEGORY_ORDER)
        return (cat_rank, e.event_id)

    return sorted(events, key=sort_key)


def find_event(events: List[WindowsEvent], event_id: str) -> Optional[WindowsEvent]:
    target = str(event_id)
    for e in events:
        if e.event_id == target:
            return e
    return None


def group_by_category(events: List[WindowsEvent]) -> "dict[str, List[WindowsEvent]]":
    groups: "dict[str, List[WindowsEvent]]" = {}
    for e in events:
        groups.setdefault(e.category, []).append(e)
    return groups
