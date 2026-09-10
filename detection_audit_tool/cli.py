"""Command line entry point.

    dat rules list [--platform windows]
    dat rules show WIN-1001
    dat events list [--category "Logon/Logoff"]
    dat events show 4625
    dat lookup 4625
    dat search "brute force"
    dat simulate brute-force
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
from .lookup import lookup_event, search
from .matcher import run_rules
from .models import Event, Rule
from .rule_loader import RuleLoadError, load_rules
from .simulator import build_brute_force_scenario, narrate_scenario

DEFAULT_RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules")


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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dat", description="Detection rule catalogue, simulator, and log auditor")
    parser.add_argument("--rules-dir", default=DEFAULT_RULES_DIR, help="directory of Sigma-style YAML rules")
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

    p_simulate = sub.add_parser("simulate", help="run a canned attack-to-detection scenario")
    sim_sub = p_simulate.add_subparsers(dest="simulate_command", required=True)
    p_sim_bf = sim_sub.add_parser("brute-force", help="password spray -> successful logon")
    p_sim_bf.add_argument("--failed-attempts", type=int, default=6)
    p_sim_bf.set_defaults(func=cmd_simulate_brute_force)

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
