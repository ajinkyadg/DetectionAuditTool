"""Correlate an incident's stated outcomes against a real log sample.

An incident's `entities` block asserts who got how far. That assertion is worth
very little on its own - the point of these walkthroughs is that the outcome is
*derived* from a log source, the same way it would be during a real triage. Each
correlator here takes an incident plus a log sample and returns per-entity
evidence; a test then fails if the narrative and the evidence ever disagree.

Correlators are named in incident YAML (`evidence.correlator`) so adding an
incident with a new evidence style is a new function here plus a registry entry,
not a new branch in the exporter.
"""

from __future__ import annotations

import json
import ntpath
import os
from typing import Any, Callable, Dict, List

from .models import Event, Incident


def load_evidence_log(path: str, base_dir: str) -> List[Event]:
    full = path if os.path.isabs(path) else os.path.join(base_dir, path)
    with open(full, "r", encoding="utf-8") as fh:
        return json.load(fh)


def correlate_web_proxy_get_post(incident: Incident, events: List[Event]) -> Dict[str, Dict[str, Any]]:
    """Derive clicked/credentials_entered from GET vs. POST against the campaign's
    lookalike domain - the distinction a "request to a newly-registered domain"
    rule alone can't make, since it only sees that a request happened, not what
    kind. The GET is the page load; the POST right after it is the form
    submission, i.e. credentials actually typed.

    Matches the mailbox local-part against the proxy log's `user` field.
    """
    def summarise(event: Event) -> str:
        if event["method"] == "POST":
            return "form submission - payload size says credentials were entered"
        return "page load only"

    domain = incident.scenario.get("lookalike_domain")
    by_user: Dict[str, List[Event]] = {}
    for event in events:
        if event.get("domain") != domain:
            continue
        by_user.setdefault(event["user"], []).append(event)

    result: Dict[str, Dict[str, Any]] = {}
    for entity in incident.entities:
        local_part = entity.identifier.split("@")[0]
        matched = sorted(by_user.get(local_part, []), key=lambda e: e["timestamp"])
        result[entity.identifier] = {
            "clicked": any(e["method"] == "GET" for e in matched),
            "credentials_entered": any(e["method"] == "POST" for e in matched),
            "caption": f"web_proxy hits against {domain}",
            "events": [
                {
                    "timestamp": e["timestamp"],
                    "headline": f"{e['method']} {e['url']}",
                    "summary": summarise(e),
                    "notable": e["method"] == "POST",
                }
                for e in matched
            ],
        }
    return result


def _windows_basename(path: str) -> str:
    """Basename of a Windows path regardless of the host OS. os.path.basename
    splits on "/" only when running on posix, so it returns Windows paths whole.
    """
    return ntpath.basename(str(path))


def _sysmon_headline(event: Event) -> str:
    """One line naming what the Sysmon event actually recorded."""
    event_id = str(event.get("EventID", "?"))
    image = _windows_basename(event.get("Image", ""))
    if event.get("TargetImage"):
        target = _windows_basename(event["TargetImage"])
        return f"Sysmon {event_id}: {image} -> {target} ({event.get('GrantedAccess', '')})"
    if event.get("TargetFilename"):
        return f"Sysmon {event_id}: {image} wrote {event['TargetFilename']}"
    return f"Sysmon {event_id}: {image}"


def correlate_sysmon_host_activity(incident: Incident, events: List[Event]) -> Dict[str, Dict[str, Any]]:
    """Derive per-host intrusion evidence from a Sysmon sample.

    Hosts are matched on `Computer`. The flags mirror the questions asked during
    a live ransomware triage, in escalating order of certainty:

    - `executed`: any process creation attributed to the intrusion at all
    - `credential_access`: a handle opened against lsass.exe (Sysmon 10)
    - `encrypted`: the ransomware binary itself ran here

    A host with no events is *not* evidence of safety - it may simply have no
    Sysmon deployed, which is why the incident marks such hosts `unknown` rather
    than `safe`, and why `unknown` is a sticky status.
    """
    lsass_target = "lsass.exe"
    ransomware_names = {
        name.lower() for name in incident.scenario.get("ransomware_binaries", [])
    }

    by_host: Dict[str, List[Event]] = {}
    for event in events:
        host = event.get("Computer")
        if host:
            by_host.setdefault(host, []).append(event)

    result: Dict[str, Dict[str, Any]] = {}
    for entity in incident.entities:
        matched = sorted(by_host.get(entity.identifier, []), key=lambda e: e["timestamp"])
        result[entity.identifier] = {
            "executed": bool(matched),
            "credential_access": any(
                str(e.get("TargetImage", "")).lower().endswith(lsass_target) for e in matched
            ),
            "encrypted": any(
                _windows_basename(e.get("Image", "")).lower() in ransomware_names
                for e in matched
            ),
            "caption": "sysmon events attributed to this intrusion",
            "events": [
                {
                    "timestamp": e["timestamp"],
                    "headline": _sysmon_headline(e),
                    "summary": e.get("note", ""),
                    "notable": str(e.get("TargetImage", "")).lower().endswith(lsass_target)
                    or _windows_basename(e.get("Image", "")).lower() in ransomware_names,
                }
                for e in matched
            ],
        }
    return result


Correlator = Callable[[Incident, List[Event]], Dict[str, Dict[str, Any]]]

CORRELATORS: Dict[str, Correlator] = {
    "web_proxy_get_post": correlate_web_proxy_get_post,
    "sysmon_host_activity": correlate_sysmon_host_activity,
}


def correlate(incident: Incident, base_dir: str) -> Dict[str, Dict[str, Any]]:
    """Run an incident's declared correlator. Returns empty evidence per entity
    when the incident declares none, so callers never branch on its absence.
    """
    spec = incident.evidence
    if not spec:
        return {e.identifier: {"events": []} for e in incident.entities}

    name = spec.get("correlator")
    if name not in CORRELATORS:
        raise ValueError(
            f"{incident.source_path}: unknown evidence correlator '{name}', "
            f"must be one of {sorted(CORRELATORS)}"
        )
    events = load_evidence_log(spec["log"], base_dir)
    return CORRELATORS[name](incident, events)
