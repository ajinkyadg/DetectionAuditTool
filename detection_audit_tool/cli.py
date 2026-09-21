"""Command line entry point.

    dat rules list [--platform windows]
    dat rules show WIN-1001
    dat events list [--category "Logon/Logoff"]
    dat events show 4625
    dat lookup 4625
    dat search "brute force"
    dat simulate brute-force
    dat incidents list
    dat incidents show phishing_account_takeover
    dat simulate incident <id> [--out page.html] [--json exports/incidents/<id>.json]
    dat run --logs sample_logs/windows_security_sample.json
    dat audit --logs sample_logs/windows_security_sample.json
    dat export-html [--out catalogue.html]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List

from .audit import audit_rules
from .event_catalogue import DEFAULT_CATALOGUE_PATH, find_event, load_windows_events
from .html_export import export_html
from .incident_export import export_incident_html, export_incident_json
from .lookup import lookup_event, search
from .matcher import run_rules
from .models import Event, Rule
from .incident_loader import IncidentLoadError, find_incident, load_incidents
from .rule_loader import RuleLoadError, load_rules
from .simulator import build_brute_force_scenario, narrate_scenario

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_RULES_DIR = os.path.join(PROJECT_ROOT, "rules")
DEFAULT_INCIDENTS_DIR = os.path.join(PROJECT_ROOT, "incidents")


def _load_incidents(incidents_dir: str):
    try:
        return load_incidents(incidents_dir)
    except IncidentLoadError as exc:
        print(f"error loading incidents: {exc}", file=sys.stderr)
        sys.exit(1)


def _find(incidents, incident_id: str):
    try:
        return find_incident(incidents, incident_id)
    except IncidentLoadError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)


def _load(rules_dir: str) -> List[Rule]:
    try:
        rules = load_rules(rules_dir)
    except RuleLoadError as exc:
        print(f"error loading rules: {exc}", file=sys.stderr)
        sys.exit(1)
    if not rules:
        print(f"no rules found under {rules_dir}", file=sys.stderr)
    return rules


def _load_events(path: str) -> List[Event]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _print_rule_card(rule: Rule) -> None:
    print(f"[{rule.id}] {rule.title}  (level: {rule.level}, type: {rule.detection_type})")
    if rule.mitre_attack:
        print(f"  MITRE ATT&CK: {', '.join(rule.mitre_attack)}")
    if rule.event_ids:
        print(f"  Event IDs: {', '.join(rule.event_ids)}")
    if rule.description:
        print(f"  {rule.description}")
    if rule.required_fields:
        print("  Required log fields:")
        for f in rule.required_fields:
            print(f"    - {f}")
    if rule.audit_policy:
        print("  How to enable this audit data:")
        for key in ("gpo_path", "command", "notes"):
            if rule.audit_policy.get(key):
                print(f"    {key}: {rule.audit_policy[key]}")
    print()


def cmd_rules_list(args: argparse.Namespace) -> None:
    rules = _load(args.rules_dir)
    for rule in rules:
        if args.platform and rule.logsource.get("product") != args.platform:
            continue
        print(f"[{rule.id}] {rule.title}  ({rule.logsource.get('product', '?')}, level={rule.level})")


def cmd_rules_show(args: argparse.Namespace) -> None:
    rules = _load(args.rules_dir)
    for rule in rules:
        if rule.id == args.rule_id:
            _print_rule_card(rule)
            return
    print(f"no rule with id '{args.rule_id}'", file=sys.stderr)
    sys.exit(1)


def _print_event_card(event) -> None:
    print(f"EventID {event.event_id}: {event.name}")
    print(f"  Category: {event.category} > {event.subcategory}  (criticality: {event.criticality})")
    if event.description:
        print(f"  {event.description.strip()}")
    if event.mitre_attack:
        print(f"  MITRE ATT&CK: {', '.join(event.mitre_attack)}")
    if event.key_fields:
        print("  Key fields:")
        for f in event.key_fields:
            print(f"    - {f}")
    if event.audit_policy:
        print("  How to enable this audit data:")
        for key in ("gpo_path", "command", "notes"):
            if event.audit_policy.get(key):
                print(f"    {key}: {event.audit_policy[key]}")
    print()


def cmd_events_list(args: argparse.Namespace) -> None:
    events = load_windows_events(args.events_file)
    for e in events:
        if args.category and e.category.lower() != args.category.lower():
            continue
        print(f"[{e.event_id}] {e.name}  ({e.category}, criticality={e.criticality})")


def cmd_events_show(args: argparse.Namespace) -> None:
    events = load_windows_events(args.events_file)
    event = find_event(events, args.event_id)
    if not event:
        print(f"no reference entry for event id '{args.event_id}'", file=sys.stderr)
        sys.exit(1)
    _print_event_card(event)


def cmd_lookup(args: argparse.Namespace) -> None:
    rules = _load(args.rules_dir)
    events = load_windows_events(args.events_file)

    event = find_event(events, args.event_id)
    matched_rules = lookup_event(rules, args.event_id)

    if not event and not matched_rules:
        print(f"no reference entry or rules for event id '{args.event_id}'")
        return

    if event:
        print("=== What this event is ===")
        _print_event_card(event)

    if matched_rules:
        print(f"=== {len(matched_rules)} detection rule(s) using this event ===\n")
        for rule in matched_rules:
            _print_rule_card(rule)
    else:
        print("=== No detection rule currently uses this event ===\n")


def cmd_search(args: argparse.Namespace) -> None:
    rules = _load(args.rules_dir)
    matched = search(rules, args.query)
    if not matched:
        print(f"no rules match '{args.query}'")
        return
    for rule in matched:
        _print_rule_card(rule)


def cmd_simulate_brute_force(args: argparse.Namespace) -> None:
    rules = _load(args.rules_dir)
    events = build_brute_force_scenario(failed_attempts=args.failed_attempts)

    print("=== Attack timeline ===")
    for line in narrate_scenario(events):
        print(line)

    print("\n=== Running detection rules against this timeline ===")
    detections = run_rules(rules, events)
    if not detections:
        print("no rule fired against this scenario")
        return
    for d in detections:
        print(f"\nDETECTION FIRED: [{d.rule.id}] {d.rule.title} (level: {d.rule.level})")
        if d.rule.mitre_attack:
            print(f"  MITRE ATT&CK: {', '.join(d.rule.mitre_attack)}")
        print(f"  {d.summary}")


def cmd_incidents_list(args: argparse.Namespace) -> None:
    incidents = _load_incidents(args.incidents_dir)
    if not incidents:
        print("no incidents found")
        return
    for incident in incidents:
        print(f"[{incident.id}] {incident.title}")
        print(f"  {len(incident.stages)} stages, {len(incident.entities)} {incident.entity_label.lower()}(s)")
        if incident.source.get("url"):
            print(f"  modelled on: {incident.source.get('name', incident.source['url'])}")


def cmd_incidents_show(args: argparse.Namespace) -> None:
    incident = _find(_load_incidents(args.incidents_dir), args.incident_id)
    counts = incident.stage_reach_counts()
    total = len(incident.entities)
    label = incident.entity_label.lower()

    print(f"=== {incident.title} ===")
    if incident.summary:
        print(f"{incident.summary}\n")
    if incident.source.get("url"):
        print(f"Modelled on public research: {incident.source.get('name', '')} {incident.source['url']}\n")

    print(f"=== {total} {label}(s), kill-chain reach ===\n")
    for stage in incident.stages:
        print(f"[{stage.index}] {stage.name}: {counts[stage.id]}/{total} reached this stage")
        if stage.rule_ids:
            print(f"      detected by: {', '.join(stage.rule_ids)}")
        if stage.blind_spot_note:
            print(f"      blind spot: {stage.blind_spot_note}")

    print(f"\n=== {incident.entity_label} triage ===\n")
    width = max((len(e.name) for e in incident.entities), default=10)
    for entity in incident.entities:
        print(f"{entity.name:<{width}} ({entity.identifier}): {entity.status.upper()}")
        if entity.note:
            print(f"    {entity.note}")


def cmd_simulate_incident(args: argparse.Namespace) -> None:
    incident = _find(_load_incidents(args.incidents_dir), args.incident_id)
    cmd_incidents_show(args)
    if args.out or args.json:
        rules = _load(args.rules_dir)
        if args.out:
            export_incident_html(incident, rules, args.out, PROJECT_ROOT)
            print(f"\nwrote interactive walkthrough to {args.out}")
        if args.json:
            export_incident_json(incident, rules, args.json, PROJECT_ROOT)
            print(f"wrote incident data to {args.json}")


def cmd_simulate_phishing(args: argparse.Namespace) -> None:
    """Back-compat alias for `simulate incident phishing_account_takeover`."""
    args.incident_id = "phishing_account_takeover"
    cmd_simulate_incident(args)


def cmd_run(args: argparse.Namespace) -> None:
    rules = _load(args.rules_dir)
    events = _load_events(args.logs)
    detections = run_rules(rules, events)
    if args.json:
        print(json.dumps([d.to_dict() for d in detections], indent=2))
        return
    if not detections:
        print("no detections")
        return
    for d in detections:
        print(f"[{d.rule.id}] {d.rule.title} (level: {d.rule.level}) - {d.summary}")


def cmd_audit(args: argparse.Namespace) -> None:
    rules = _load(args.rules_dir)
    events = _load_events(args.logs)
    audits = audit_rules(rules, events)

    if args.json:
        print(json.dumps([a.to_dict() for a in audits], indent=2))
        return

    for a in audits:
        print(f"[{a.rule.id}] {a.rule.title}: {a.verdict}  ({a.in_scope_events} in-scope events)")
        for fc in a.field_coverage:
            flag = "OK" if fc.coverage_pct >= 99.9 else "!!"
            print(f"    {flag} {fc.field}: {fc.coverage_pct:.1f}% populated ({fc.present_count}/{fc.total})")
        if a.verdict != "READY" and a.rule.audit_policy.get("notes"):
            print(f"    fix: {a.rule.audit_policy['notes']}")


def cmd_export_html(args: argparse.Namespace) -> None:
    rules = _load(args.rules_dir)
    events = load_windows_events(args.events_file)
    export_html(rules, events, args.out)
    print(f"wrote {len(rules)} rules and {len(events)} reference events to {args.out}")


def _add_export_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--out", help="write the interactive HTML kill-chain walkthrough to this path")
    parser.add_argument(
        "--json",
        help="write the incident as JSON data for another renderer to consume, e.g. SignalHunt",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dat", description="Detection rule catalogue, simulator, and log auditor")
    parser.add_argument("--rules-dir", default=DEFAULT_RULES_DIR, help="directory of Sigma-style YAML rules")
    parser.add_argument(
        "--incidents-dir", default=DEFAULT_INCIDENTS_DIR, help="directory of YAML incident definitions"
    )
    parser.add_argument(
        "--events-file", default=DEFAULT_CATALOGUE_PATH, help="Windows Security event reference YAML"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_rules = sub.add_parser("rules", help="browse the rule catalogue")
    rules_sub = p_rules.add_subparsers(dest="rules_command", required=True)
    p_rules_list = rules_sub.add_parser("list", help="list all rules")
    p_rules_list.add_argument("--platform", help="filter by logsource product, e.g. windows/linux/aws")
    p_rules_list.set_defaults(func=cmd_rules_list)
    p_rules_show = rules_sub.add_parser("show", help="show full detail for one rule")
    p_rules_show.add_argument("rule_id")
    p_rules_show.set_defaults(func=cmd_rules_show)

    p_events = sub.add_parser("events", help="browse the Windows Security event reference catalogue")
    events_sub = p_events.add_subparsers(dest="events_command", required=True)
    p_events_list = events_sub.add_parser("list", help="list all reference events")
    p_events_list.add_argument("--category", help="filter by audit category, e.g. 'Logon/Logoff'")
    p_events_list.set_defaults(func=cmd_events_list)
    p_events_show = events_sub.add_parser("show", help="show full detail for one event id")
    p_events_show.add_argument("event_id")
    p_events_show.set_defaults(func=cmd_events_show)

    p_lookup = sub.add_parser("lookup", help="find rules + reference facts by event id / eventName")
    p_lookup.add_argument("event_id")
    p_lookup.set_defaults(func=cmd_lookup)

    p_search = sub.add_parser("search", help="keyword search across the catalogue")
    p_search.add_argument("query")
    p_search.set_defaults(func=cmd_search)

    p_incidents = sub.add_parser("incidents", help="browse the incident walkthroughs")
    incidents_sub = p_incidents.add_subparsers(dest="incidents_command", required=True)
    p_inc_list = incidents_sub.add_parser("list", help="list every incident")
    p_inc_list.set_defaults(func=cmd_incidents_list)
    p_inc_show = incidents_sub.add_parser("show", help="print one incident's kill chain and triage")
    p_inc_show.add_argument("incident_id")
    p_inc_show.set_defaults(func=cmd_incidents_show)

    p_simulate = sub.add_parser("simulate", help="run a canned attack-to-detection scenario")
    sim_sub = p_simulate.add_subparsers(dest="simulate_command", required=True)
    p_sim_bf = sim_sub.add_parser("brute-force", help="password spray -> successful logon")
    p_sim_bf.add_argument("--failed-attempts", type=int, default=6)
    p_sim_bf.set_defaults(func=cmd_simulate_brute_force)

    p_sim_incident = sim_sub.add_parser(
        "incident", help="walk one incident's kill chain, with optional interactive HTML/JSON export"
    )
    p_sim_incident.add_argument("incident_id", help="incident id, as listed by `dat incidents list`")
    _add_export_args(p_sim_incident)
    p_sim_incident.set_defaults(func=cmd_simulate_incident)

    # Kept so existing docs and scripts don't break now that incidents are data.
    p_sim_phish = sim_sub.add_parser("phishing", help="alias for `simulate incident phishing_account_takeover`")
    _add_export_args(p_sim_phish)
    p_sim_phish.set_defaults(func=cmd_simulate_phishing)

    p_run = sub.add_parser("run", help="run all rules against a log file")
    p_run.add_argument("--logs", required=True, help="path to a JSON array of log events")
    p_run.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    p_run.set_defaults(func=cmd_run)

    p_audit = sub.add_parser("audit", help="validate a log file has the fields each rule needs")
    p_audit.add_argument("--logs", required=True, help="path to a JSON array of log events")
    p_audit.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    p_audit.set_defaults(func=cmd_audit)

    p_export = sub.add_parser("export-html", help="export a searchable static HTML catalogue")
    p_export.add_argument("--out", default="catalogue.html")
    p_export.set_defaults(func=cmd_export_html)

    return parser


def main(argv: List[str] = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
