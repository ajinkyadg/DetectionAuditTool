"""Export the catalogue as a single self-contained, searchable HTML page.

No server, no bundler - open the file directly in a browser (Mermaid loads
from a CDN for the mind map / flowchart views, everything else is inline).
Three views:

  Catalogue   - searchable rule cards (Event ID / MITRE / platform / keyword)
  Windows Events - a table of every reference event, click a row for the
                   full detail: fields, sample log, how to enable auditing,
                   and (when a rule exists) a generated attack-to-detection
                   flowchart.
  Mind Map    - all reference events grouped by audit category, as a Mermaid
                mindmap.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from .event_catalogue import CATEGORY_ORDER, WindowsEvent, group_by_category
from .models import Rule

LEVEL_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def rule_to_dict(rule: Rule) -> Dict[str, Any]:
    return {
        "id": rule.id,
        "title": rule.title,
        "description": rule.description,
        "level": rule.level,
        "platform": rule.logsource.get("product") or rule.logsource.get("category") or "",
        "logsource": rule.logsource,
        "mitre_attack": rule.mitre_attack,
        "event_ids": rule.event_ids,
        "required_fields": rule.required_fields,
        "audit_policy": rule.audit_policy,
        "false_positives": rule.false_positives,
        "detection_type": rule.detection_type,
    }


def event_to_dict(event: WindowsEvent, rules: List[Rule]) -> Dict[str, Any]:
    related = {r.id for r in rules if event.event_id in r.event_ids}
    related.update(event.related_rules)
    return {
        "event_id": event.event_id,
        "name": event.name,
        "category": event.category,
        "subcategory": event.subcategory,
        "criticality": event.criticality,
        "description": event.description,
        "key_fields": event.key_fields,
        "sample_log": event.sample_log,
        "audit_policy": event.audit_policy,
        "mitre_attack": event.mitre_attack,
        "related_rules": sorted(related),
        "references": event.references,
    }


def _mermaid_mindmap(events: List[WindowsEvent]) -> str:
    groups = group_by_category(events)
    lines = ["mindmap", "  root((Windows Security Events))"]
    for category in CATEGORY_ORDER:
        cat_events = groups.get(category, [])
        if not cat_events:
            continue
        cat_id = "cat_" + "".join(ch if ch.isalnum() else "_" for ch in category)
        lines.append(f'    {cat_id}["{category}"]')
        for event in cat_events:
            leaf_id = f"ev{event.event_id.replace(' ', '')}"
            name = "".join(ch for ch in event.name if ch not in '()"[]{}')
            if len(name) > 42:
                name = name[:39] + "..."
            lines.append(f'      {leaf_id}("{event.event_id} {name}")')
    return "\n".join(lines)


_TEMPLATE = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Detection Rule Catalogue</title>
<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
<style>
  :root {
    color-scheme: light dark;
    --bg: #f7f8fa; --card: #ffffff; --text: #1c1e21; --muted: #666;
    --border: #e2e4e8; --accent: #2563eb;
  }
  @media (prefers-color-scheme: dark) {
    :root { --bg: #16181c; --card: #1f2227; --text: #e8e9eb; --muted: #9aa0a8; --border: #33363b; }
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--text);
         font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
  header { padding: 20px 24px 0; }
  h1 { margin: 0 0 4px; font-size: 20px; }
  .sub { color: var(--muted); font-size: 13px; margin-bottom: 14px; }
  .tabs { display: flex; gap: 4px; border-bottom: 1px solid var(--border); padding: 0 24px; }
  .tab-btn { border: none; background: none; color: var(--muted); padding: 10px 14px; font-size: 13px;
             cursor: pointer; border-bottom: 2px solid transparent; }
  .tab-btn.active { color: var(--accent); border-bottom-color: var(--accent); font-weight: 600; }
  .tab-panel { display: none; padding: 18px 24px 40px; }
  .tab-panel.active { display: block; }
  #search, #ev-search { width: 100%; max-width: 520px; padding: 10px 14px; font-size: 14px;
            border-radius: 8px; border: 1px solid var(--border); background: var(--card);
            color: var(--text); }
  select { padding: 9px 10px; font-size: 13px; border-radius: 8px; border: 1px solid var(--border);
           background: var(--card); color: var(--text); }
  .toolbar { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 10px; align-items: center; }
  #count, #ev-count { color: var(--muted); font-size: 12px; margin: 8px 0 0; }
  main.cards { display: grid; gap: 14px; max-width: 900px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 16px 18px; }
  .card h2 { margin: 0 0 6px; font-size: 15px; }
  .card .id { color: var(--muted); font-weight: 400; font-size: 12px; }
  .badges { display: flex; flex-wrap: wrap; gap: 6px; margin: 8px 0; }
  .chip { display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 11px;
          border: 1px solid var(--border); color: var(--muted); }
  .chip.event { color: var(--accent); border-color: var(--accent); cursor: pointer; }
  .level, .crit { text-transform: uppercase; font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 4px; }
  .level-informational, .crit-informational, .level-low, .crit-low { background: #dbeafe; color: #1e40af; }
  .level-medium, .crit-medium { background: #fef3c7; color: #92400e; }
  .level-high, .crit-high { background: #fed7aa; color: #9a3412; }
  .level-critical, .crit-critical { background: #fecaca; color: #991b1b; }
  .desc { font-size: 13px; color: var(--muted); margin: 6px 0 10px; }
  .section-title { font-size: 11px; text-transform: uppercase; letter-spacing: .04em;
                    color: var(--muted); margin: 10px 0 4px; }
  .fields { display: flex; flex-wrap: wrap; gap: 6px; }
  .field { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px;
           background: var(--bg); border: 1px solid var(--border); border-radius: 5px; padding: 2px 6px; }
  .enable { font-size: 13px; line-height: 1.5; }
  .enable code, pre.sample { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background: var(--bg);
                 border: 1px solid var(--border); border-radius: 4px; padding: 1px 5px; }
  pre.sample { display: block; padding: 10px; font-size: 12px; overflow-x: auto; white-space: pre; }
  .empty { color: var(--muted); padding: 40px 0; text-align: center; }
  .events-layout { display: grid; grid-template-columns: minmax(280px, 420px) 1fr; gap: 18px; align-items: start; }
  table.ev-table { width: 100%; border-collapse: collapse; font-size: 13px; background: var(--card);
                    border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
  table.ev-table th, table.ev-table td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); }
  table.ev-table tr.ev-row { cursor: pointer; }
  table.ev-table tr.ev-row:hover { background: var(--bg); }
  table.ev-table tr.ev-row.selected { background: color-mix(in srgb, var(--accent) 12%, var(--card)); }
  #ev-detail { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 18px; min-height: 200px; }
  button.flow-btn { margin-top: 10px; padding: 7px 12px; font-size: 12px; border-radius: 6px;
                     border: 1px solid var(--accent); background: none; color: var(--accent); cursor: pointer; }
  .mermaid-wrap { margin-top: 12px; overflow-x: auto; background: var(--bg); border: 1px solid var(--border);
                  border-radius: 8px; padding: 10px; }
  #mindmap-container { background: var(--card); border: 1px solid var(--border); border-radius: 10px;
                        padding: 16px; overflow: auto; }
</style>
</head>
<body>
<header>
  <h1>Detection Rule Catalogue</h1>
  <div class="sub">Rules, MITRE ATT&amp;CK mapping, required log fields, audit-enablement steps, and a Windows Security event reference.</div>
</header>
<nav class="tabs">
  <button class="tab-btn active" data-tab="catalogue">Catalogue</button>
  <button class="tab-btn" data-tab="events">Windows Events</button>
  <button class="tab-btn" data-tab="mindmap">Mind Map</button>
</nav>

<section id="tab-catalogue" class="tab-panel active">
  <div class="toolbar">
    <input id="search" placeholder="4625, T1110, brute force, aws...">
  </div>
  <div id="count"></div>
  <main class="cards" id="results"></main>
</section>

<section id="tab-events" class="tab-panel">
  <div class="toolbar">
    <input id="ev-search" placeholder="Search by event id, name, or category...">
    <select id="ev-category"><option value="">All categories</option></select>
  </div>
  <div id="ev-count"></div>
  <div class="events-layout">
    <table class="ev-table">
      <thead><tr><th>ID</th><th>Name</th><th>Category</th><th>Criticality</th></tr></thead>
      <tbody id="ev-rows"></tbody>
    </table>
    <div id="ev-detail"><div class="empty">Select an event to see its fields, sample log, and how to enable it.</div></div>
  </div>
</section>

<section id="tab-mindmap" class="tab-panel">
  <div class="sub">All reference events grouped by Windows Advanced Audit Policy category.</div>
  <div id="mindmap-container"><div class="empty">Loading diagram...</div></div>
</section>

<script>
const RULES = __RULES_JSON__;
const EVENTS = __EVENTS_JSON__;
const MINDMAP_DEF = __MINDMAP_DEF__;

var prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
mermaid.initialize({ startOnLoad: false, theme: prefersDark ? 'dark' : 'default' });

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, function(c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
  });
}

function chipList(items, cls) {
  return (items || []).map(function(i) {
    return '<span class="chip' + (cls ? ' ' + cls : '') + '">' + escapeHtml(i) + '</span>';
  }).join('');
}

function auditPolicyHtml(ap) {
  if (!ap || Object.keys(ap).length === 0) return '<div class="enable">No audit-enablement notes recorded yet.</div>';
  var parts = [];
  if (ap.gpo_path) parts.push('<div><strong>GPO path:</strong> ' + escapeHtml(ap.gpo_path) + '</div>');
  if (ap.command) parts.push('<div><strong>Command:</strong> <code>' + escapeHtml(ap.command) + '</code></div>');
  if (ap.notes) parts.push('<div>' + escapeHtml(ap.notes) + '</div>');
  return '<div class="enable">' + parts.join('') + '</div>';
}

/* ---------- Tabs ---------- */
document.querySelectorAll('.tab-btn').forEach(function(btn) {
  btn.addEventListener('click', function() {
    document.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
    document.querySelectorAll('.tab-panel').forEach(function(p) { p.classList.remove('active'); });
    btn.classList.add('active');
    document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
    if (btn.dataset.tab === 'mindmap') renderMindmap();
  });
});

/* ---------- Catalogue tab ---------- */
function levelClass(level) { return "level level-" + (level || "medium").toLowerCase(); }

function cardHtml(r) {
  return '' +
    '<div class="card">' +
      '<h2>' + escapeHtml(r.title) + ' <span class="id">' + escapeHtml(r.id) + '</span>' +
        ' <span class="' + levelClass(r.level) + '">' + escapeHtml(r.level) + '</span></h2>' +
      '<div class="badges">' +
        chipList(r.event_ids, 'event') +
        chipList(r.mitre_attack) +
        chipList([r.platform]) +
      '</div>' +
      '<div class="desc">' + escapeHtml(r.description || '') + '</div>' +
      '<div class="section-title">Required log fields</div>' +
      '<div class="fields">' + (r.required_fields && r.required_fields.length
        ? r.required_fields.map(function(f){ return '<span class="field">' + escapeHtml(f) + '</span>'; }).join('')
        : '<span class="desc">none recorded</span>') + '</div>' +
      '<div class="section-title">How to enable this audit data</div>' +
      auditPolicyHtml(r.audit_policy) +
      '<button class="flow-btn" data-rule="' + escapeHtml(r.id) + '">Show attack &rarr; detection flow</button>' +
      '<div class="mermaid-wrap" id="flow-' + escapeHtml(r.id) + '" hidden></div>' +
    '</div>';
}

function catalogueMatches(r, q) {
  if (!q) return true;
  var hay = [r.id, r.title, r.description, r.platform]
    .concat(r.event_ids || []).concat(r.mitre_attack || []).join(' ').toLowerCase();
  return hay.indexOf(q) !== -1;
}

function renderCatalogue(query) {
  var q = (query || '').trim().toLowerCase();
  var filtered = RULES.filter(function(r) { return catalogueMatches(r, q); });
  document.getElementById('count').textContent = filtered.length + ' of ' + RULES.length + ' rules';
  var results = document.getElementById('results');
  results.innerHTML = filtered.length ? filtered.map(cardHtml).join('')
    : '<div class="empty">No rules match "' + escapeHtml(query) + '"</div>';
  results.querySelectorAll('.flow-btn').forEach(function(btn) {
    btn.addEventListener('click', function() { toggleRuleFlow(btn.dataset.rule); });
  });
}

document.getElementById('search').addEventListener('input', function(e) { renderCatalogue(e.target.value); });
renderCatalogue('');

/* ---------- Attack -> detection flowcharts (Mermaid, rendered on demand) ---------- */
function ruleFlowchartDef(r) {
  var lines = ['flowchart LR', 'ATT["Attacker action"]'];
  var prev = 'ATT';
  (r.event_ids || []).forEach(function(eid, i) {
    var node = 'EV' + i;
    lines.push(node + '["Event ' + eid + '"]');
    lines.push(prev + ' --> ' + node);
    prev = node;
  });
  var title = (r.id + ': ' + r.title).replace(/["()\[\]{}]/g, '');
  lines.push('RULE["' + title + '"]');
  lines.push(prev + ' --> RULE');
  if (r.mitre_attack && r.mitre_attack.length) {
    lines.push('MITRE["' + r.mitre_attack.join(', ') + '"]');
    lines.push('RULE --> MITRE');
  }
  lines.push('ALERT["Alert: ' + String(r.level).toUpperCase() + '"]');
  lines.push('RULE --> ALERT');
  return lines.join('\\n');
}

var flowRenderCounter = 0;
function toggleRuleFlow(ruleId) {
  var container = document.getElementById('flow-' + ruleId);
  if (!container) return;
  if (!container.hidden) { container.hidden = true; return; }
  container.hidden = false;
  if (container.dataset.rendered) return;
  var rule = RULES.find(function(r) { return r.id === ruleId; });
  if (!rule) return;
  var id = 'mmd-flow-' + (flowRenderCounter++);
  mermaid.render(id, ruleFlowchartDef(rule)).then(function(res) {
    container.innerHTML = res.svg;
    container.dataset.rendered = '1';
  }).catch(function(err) {
    container.innerHTML = '<div class="empty">Could not render diagram: ' + escapeHtml(String(err)) + '</div>';
  });
}

/* ---------- Windows Events tab ---------- */
var categories = Array.from(new Set(EVENTS.map(function(e) { return e.category; })));
var catSelect = document.getElementById('ev-category');
categories.forEach(function(c) {
  var opt = document.createElement('option');
  opt.value = c; opt.textContent = c;
  catSelect.appendChild(opt);
});

function eventMatches(e, q, cat) {
  if (cat && e.category !== cat) return false;
  if (!q) return true;
  var hay = [e.event_id, e.name, e.category, e.subcategory].concat(e.mitre_attack || []).join(' ').toLowerCase();
  return hay.indexOf(q) !== -1;
}

var selectedEventId = null;

function renderEventRows() {
  var q = document.getElementById('ev-search').value.trim().toLowerCase();
  var cat = catSelect.value;
  var filtered = EVENTS.filter(function(e) { return eventMatches(e, q, cat); });
  document.getElementById('ev-count').textContent = filtered.length + ' of ' + EVENTS.length + ' events';
  var rows = document.getElementById('ev-rows');
  rows.innerHTML = filtered.map(function(e) {
    return '<tr class="ev-row' + (e.event_id === selectedEventId ? ' selected' : '') + '" data-id="' + escapeHtml(e.event_id) + '">' +
      '<td>' + escapeHtml(e.event_id) + '</td>' +
      '<td>' + escapeHtml(e.name) + '</td>' +
      '<td>' + escapeHtml(e.category) + '</td>' +
      '<td><span class="crit crit-' + escapeHtml(e.criticality) + '">' + escapeHtml(e.criticality) + '</span></td>' +
    '</tr>';
  }).join('') || '<tr><td colspan="4" class="empty">No events match</td></tr>';
  rows.querySelectorAll('.ev-row').forEach(function(tr) {
    tr.addEventListener('click', function() { selectEvent(tr.dataset.id); });
  });
}

function eventDetailHtml(e) {
  var sampleJson = JSON.stringify(e.sample_log, null, 2);
  var relatedRules = (e.related_rules || []).map(function(id) {
    return '<span class="chip">' + escapeHtml(id) + '</span>';
  }).join('') || '<span class="desc">no rule implemented yet</span>';
  return '' +
    '<h2>' + escapeHtml(e.name) + ' <span class="id">EventID ' + escapeHtml(e.event_id) + '</span></h2>' +
    '<div class="badges">' +
      '<span class="crit crit-' + escapeHtml(e.criticality) + '">' + escapeHtml(e.criticality) + '</span>' +
      chipList([e.category + ' > ' + e.subcategory]) +
      chipList(e.mitre_attack) +
    '</div>' +
    '<div class="desc">' + escapeHtml(e.description || '') + '</div>' +
    '<div class="section-title">Key log fields</div>' +
    '<div class="fields">' + (e.key_fields || []).map(function(f) { return '<span class="field">' + escapeHtml(f) + '</span>'; }).join('') + '</div>' +
    '<div class="section-title">Sample log</div>' +
    '<pre class="sample">' + escapeHtml(sampleJson) + '</pre>' +
    '<div class="section-title">How to enable this audit data</div>' +
    auditPolicyHtml(e.audit_policy) +
    '<div class="section-title">Detection rules using this event</div>' +
    '<div class="badges">' + relatedRules + '</div>' +
    ((e.related_rules || []).length
      ? '<button class="flow-btn" id="ev-flow-btn">Show attack &rarr; detection flow</button><div class="mermaid-wrap" id="ev-flow" hidden></div>'
      : '');
}

function selectEvent(eventId) {
  selectedEventId = eventId;
  renderEventRows();
  var event = EVENTS.find(function(e) { return e.event_id === eventId; });
  var detail = document.getElementById('ev-detail');
  if (!event) { detail.innerHTML = '<div class="empty">Not found</div>'; return; }
  detail.innerHTML = eventDetailHtml(event);
  var btn = document.getElementById('ev-flow-btn');
  if (btn) {
    btn.addEventListener('click', function() {
      var ruleId = event.related_rules[0];
      var container = document.getElementById('ev-flow');
      container.hidden = !container.hidden;
      if (container.hidden || container.dataset.rendered) return;
      var rule = RULES.find(function(r) { return r.id === ruleId; });
      if (!rule) return;
      var id = 'mmd-ev-' + (flowRenderCounter++);
      mermaid.render(id, ruleFlowchartDef(rule)).then(function(res) {
        container.innerHTML = res.svg;
        container.dataset.rendered = '1';
      });
    });
  }
}

document.getElementById('ev-search').addEventListener('input', renderEventRows);
catSelect.addEventListener('change', renderEventRows);
renderEventRows();

/* ---------- Mind map tab ---------- */
var mindmapRendered = false;
function renderMindmap() {
  if (mindmapRendered) return;
  mermaid.render('mmd-mindmap', MINDMAP_DEF).then(function(res) {
    document.getElementById('mindmap-container').innerHTML = res.svg;
    mindmapRendered = true;
  }).catch(function(err) {
    document.getElementById('mindmap-container').innerHTML =
      '<div class="empty">Could not render mind map: ' + escapeHtml(String(err)) + '</div>';
  });
}
</script>
</body>
</html>
"""


def export_html(rules: List[Rule], events: List[WindowsEvent], output_path: str) -> None:
    rules_data = [rule_to_dict(r) for r in rules]
    events_data = [event_to_dict(e, rules) for e in events]
    html = (
        _TEMPLATE.replace("__RULES_JSON__", json.dumps(rules_data))
        .replace("__EVENTS_JSON__", json.dumps(events_data))
        .replace("__MINDMAP_DEF__", json.dumps(_mermaid_mindmap(events)))
    )
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
