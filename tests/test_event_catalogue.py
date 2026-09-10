from detection_audit_tool.event_catalogue import (
    CATEGORY_ORDER,
    find_event,
    group_by_category,
    load_windows_events,
)
from detection_audit_tool.html_export import _mermaid_mindmap


def test_catalogue_loads_and_ids_are_unique():
    events = load_windows_events()
    assert len(events) >= 40
    ids = [e.event_id for e in events]
    assert len(ids) == len(set(ids))


def test_every_event_has_required_reference_fields():
    events = load_windows_events()
    for e in events:
        assert e.event_id
        assert e.name
        assert e.category in CATEGORY_ORDER
        assert e.description
        assert e.sample_log, f"{e.event_id} has no sample log"
        assert e.sample_log.get("EventID") is not None or e.category == "System"


def test_find_event_returns_none_for_unknown_id():
    events = load_windows_events()
    assert find_event(events, "9999") is None
    assert find_event(events, "4625") is not None


def test_all_nine_categories_are_represented():
    events = load_windows_events()
    groups = group_by_category(events)
    for category in CATEGORY_ORDER:
        assert category in groups, f"no reference events for category '{category}'"


def test_mindmap_definition_has_no_unescaped_parentheses_in_labels():
    events = load_windows_events()
    mindmap = _mermaid_mindmap(events)
    for line in mindmap.splitlines():
        if '("' not in line:
            continue
        label = line.split('("', 1)[1].rsplit('")', 1)[0]
        assert "(" not in label and ")" not in label
