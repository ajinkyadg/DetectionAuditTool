"""Load incident definitions from a directory of YAML files.

Deliberately shaped like rule_loader: incidents are data the same way rules are,
so adding one is a file, not a code change. Validation errors name the offending
path because these are hand-authored.
"""

from __future__ import annotations

import glob
import os
from typing import List

import yaml

from .models import AffectedEntity, Incident, ResponseAction, Stage, StatusLevel

VALID_PHASES = {"preparation", "containment", "eradication", "recovery"}
VALID_TONES = {"good", "neutral", "warn", "bad", "critical"}


class IncidentLoadError(ValueError):
    pass


def _build_status_model(docs: list, path: str) -> List[StatusLevel]:
    if not docs:
        raise IncidentLoadError(f"{path}: 'status_model' must list at least one status")
    levels = []
    for raw in docs:
        tone = raw.get("tone", "neutral")
        if tone not in VALID_TONES:
            raise IncidentLoadError(
                f"{path}: status '{raw.get('id')}' has invalid tone '{tone}', "
                f"must be one of {sorted(VALID_TONES)}"
            )
        levels.append(
            StatusLevel(
                id=raw["id"],
                label=raw["label"],
                tone=tone,
                max_stage=raw.get("max_stage"),
                sticky=bool(raw.get("sticky", False)),
            )
        )
    # derive_status walks this in order and falls through to the last rung, so a
    # mis-ordered ladder silently mislabels everyone.
    bounded = [level.max_stage for level in levels if level.max_stage is not None]
    if bounded != sorted(bounded):
        raise IncidentLoadError(
            f"{path}: 'status_model' must be ordered by ascending max_stage, got {bounded}"
        )
    if levels[-1].max_stage is not None:
        raise IncidentLoadError(
            f"{path}: the last status ('{levels[-1].id}') is the catch-all rung "
            "and must not set max_stage"
        )
    return levels


def _build_stage(raw: dict, path: str) -> Stage:
    for required in ("id", "index", "name"):
        if required not in raw:
            raise IncidentLoadError(f"{path}: stage missing required field '{required}'")

    actions = []
    for raw_action in raw.get("actions", []):
        phase = raw_action.get("phase", "containment")
        if phase not in VALID_PHASES:
            raise IncidentLoadError(
                f"{path}: action '{raw_action.get('id')}' has invalid phase '{phase}', "
                f"must be one of {sorted(VALID_PHASES)}"
            )
        actions.append(
            ResponseAction(id=raw_action["id"], label=raw_action["label"], phase=phase)
        )

    return Stage(
        id=raw["id"],
        index=raw["index"],
        name=raw["name"],
        mitre=raw.get("mitre", []),
        narrative=raw.get("narrative", ""),
        rule_ids=raw.get("rule_ids", []),
        actions=actions,
        icon=raw.get("icon", ""),
        blind_spot_note=raw.get("blind_spot_note", ""),
    )


def _build_incident(doc: dict, path: str) -> Incident:
    for required in ("id", "title", "stages", "entities", "status_model"):
        if required not in doc:
            raise IncidentLoadError(f"{path}: missing required field '{required}'")

    stages = [_build_stage(s, path) for s in doc["stages"]]
    indices = [s.index for s in stages]
    if indices != list(range(len(indices))):
        raise IncidentLoadError(
            f"{path}: stage indices must be contiguous from 0, got {indices}"
        )

    status_model = _build_status_model(doc["status_model"], path)
    known_statuses = {level.id for level in status_model}

    entities = []
    for raw in doc["entities"]:
        status = raw["status"]
        if status not in known_statuses:
            raise IncidentLoadError(
                f"{path}: entity '{raw.get('identifier')}' has status '{status}' "
                f"which is not in status_model {sorted(known_statuses)}"
            )
        if raw["furthest_stage"] >= len(stages):
            raise IncidentLoadError(
                f"{path}: entity '{raw.get('identifier')}' has furthest_stage "
                f"{raw['furthest_stage']} but there are only {len(stages)} stages"
            )
        entities.append(
            AffectedEntity(
                name=raw["name"],
                identifier=raw["identifier"],
                furthest_stage=raw["furthest_stage"],
                status=status,
                note=raw.get("note", ""),
            )
        )

    evidence = doc.get("evidence")
    if evidence is not None and "log" not in evidence:
        raise IncidentLoadError(f"{path}: 'evidence' block requires a 'log' path")

    return Incident(
        id=doc["id"],
        slug=doc.get("slug", doc["id"]),
        title=doc["title"],
        summary=doc.get("summary", ""),
        stages=stages,
        entities=entities,
        status_model=status_model,
        source=doc.get("source", {}),
        scenario=doc.get("scenario", {}),
        entity_label=doc.get("entity_label", "Entity"),
        icon=doc.get("icon", "\U0001f6a8"),
        evidence=evidence,
        source_path=path,
    )


def load_incident_file(path: str) -> Incident:
    with open(path, "r", encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    if not isinstance(doc, dict):
        raise IncidentLoadError(f"{path}: incident file did not parse to a YAML mapping")
    return _build_incident(doc, path)


def load_incidents(incidents_dir: str) -> List[Incident]:
    paths = sorted(glob.glob(os.path.join(incidents_dir, "**", "*.yml"), recursive=True)) + sorted(
        glob.glob(os.path.join(incidents_dir, "**", "*.yaml"), recursive=True)
    )
    incidents = [load_incident_file(p) for p in paths]
    seen_ids = {}
    for incident in incidents:
        if incident.id in seen_ids:
            raise IncidentLoadError(
                f"Duplicate incident id '{incident.id}' in {incident.source_path} "
                f"and {seen_ids[incident.id]}"
            )
        seen_ids[incident.id] = incident.source_path
    return incidents


def find_incident(incidents: List[Incident], incident_id: str) -> Incident:
    match = next((i for i in incidents if i.id == incident_id), None)
    if match is None:
        raise IncidentLoadError(
            f"unknown incident '{incident_id}', available: {sorted(i.id for i in incidents)}"
        )
    return match
