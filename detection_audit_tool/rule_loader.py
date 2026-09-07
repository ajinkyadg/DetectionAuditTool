"""Load Sigma-style YAML detection rules from a directory tree."""

from __future__ import annotations

import glob
import os
from typing import List

import yaml

from .models import Rule, SequenceStep

VALID_DETECTION_TYPES = {"selection", "threshold", "sequence"}


class RuleLoadError(ValueError):
    pass


def _build_rule(doc: dict, path: str) -> Rule:
    for required in ("id", "title", "detection_type", "logsource"):
        if required not in doc:
            raise RuleLoadError(f"{path}: missing required field '{required}'")

    detection_type = doc["detection_type"]
    if detection_type not in VALID_DETECTION_TYPES:
        raise RuleLoadError(
            f"{path}: invalid detection_type '{detection_type}', "
            f"must be one of {sorted(VALID_DETECTION_TYPES)}"
        )

    steps = []
    for raw_step in doc.get("steps", []):
        steps.append(
            SequenceStep(
                name=raw_step["name"],
                match=raw_step["match"],
                threshold=raw_step.get("threshold", 1),
            )
        )

    if detection_type == "selection" and not doc.get("selection"):
        raise RuleLoadError(f"{path}: 'selection' rules require a 'selection' block")
    if detection_type == "threshold" and not doc.get("selection"):
        raise RuleLoadError(f"{path}: 'threshold' rules require a 'selection' block")
    if detection_type == "sequence" and len(steps) < 2:
        raise RuleLoadError(f"{path}: 'sequence' rules require at least 2 'steps'")

    return Rule(
        id=doc["id"],
        title=doc["title"],
        description=doc.get("description", ""),
        detection_type=detection_type,
        logsource=doc["logsource"],
        level=doc.get("level", "medium"),
        mitre_attack=doc.get("mitre_attack", []),
        required_fields=doc.get("required_fields", []),
        false_positives=doc.get("false_positives", []),
        references=doc.get("references", []),
        source_path=path,
        event_ids=[str(e) for e in doc.get("event_ids", [])],
        audit_policy=doc.get("audit_policy", {}),
        selection=doc.get("selection"),
        groupby=doc.get("groupby"),
        timeframe_minutes=doc.get("timeframe_minutes"),
        threshold=doc.get("threshold"),
        condition=doc.get("condition", "gte"),
        steps=steps,
    )


def load_rule_file(path: str) -> Rule:
    with open(path, "r", encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    if not isinstance(doc, dict):
        raise RuleLoadError(f"{path}: rule file did not parse to a YAML mapping")
    return _build_rule(doc, path)


def load_rules(rules_dir: str) -> List[Rule]:
    pattern = os.path.join(rules_dir, "**", "*.yml")
    paths = sorted(glob.glob(pattern, recursive=True)) + sorted(
        glob.glob(os.path.join(rules_dir, "**", "*.yaml"), recursive=True)
    )
    rules = [load_rule_file(p) for p in paths]
    seen_ids = {}
    for rule in rules:
        if rule.id in seen_ids:
            raise RuleLoadError(
                f"Duplicate rule id '{rule.id}' in {rule.source_path} and {seen_ids[rule.id]}"
            )
        seen_ids[rule.id] = rule.source_path
    return rules
