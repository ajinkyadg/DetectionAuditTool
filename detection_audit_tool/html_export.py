"""Export the rule catalogue as a single self-contained, searchable HTML page.

No server, no external assets - open the file directly in a browser. Search
by Event ID, MITRE technique, platform, or keyword and see: the rule(s) that
fire on it, the fields the rule needs from the log, and how to turn on the
audit policy that produces those fields.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

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


_TEMPLATE = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Detection Rule Catalogue</title>
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
  header { padding: 24px 24px 12px; }
  h1 { margin: 0 0 4px; font-size: 20px; }
  .sub { color: var(--muted); font-size: 13px; margin-bottom: 16px; }
  #search { width: 100%; max-width: 520px; padding: 10px 14px; font-size: 14px;
            border-radius: 8px; border: 1px solid var(--border); background: var(--card);
            color: var(--text); }
  #count { color: var(--muted); font-size: 12px; margin: 8px 0 0; }
  main { padding: 0 24px 40px; display: grid; gap: 14px; max-width: 900px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 16px 18px; }
  .card h2 { margin: 0 0 6px; font-size: 15px; }
  .card .id { color: var(--muted); font-weight: 400; font-size: 12px; }
  .badges { display: flex; flex-wrap: wrap; gap: 6px; margin: 8px 0; }
  .chip { display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 11px;
          border: 1px solid var(--border); color: var(--muted); }
  .chip.event { color: var(--accent); border-color: var(--accent); }
  .level { text-transform: uppercase; font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 4px; }
  .level-informational, .level-low { background: #dbeafe; color: #1e40af; }
  .level-medium { background: #fef3c7; color: #92400e; }
  .level-high { background: #fed7aa; color: #9a3412; }
  .level-critical { background: #fecaca; color: #991b1b; }
  .desc { font-size: 13px; color: var(--muted); margin: 6px 0 10px; }
  .section-title { font-size: 11px; text-transform: uppercase; letter-spacing: .04em;
                    color: var(--muted); margin: 10px 0 4px; }
  .fields { display: flex; flex-wrap: wrap; gap: 6px; }
  .field { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px;
           background: var(--bg); border: 1px solid var(--border); border-radius: 5px; padding: 2px 6px; }
  .enable { font-size: 13px; line-height: 1.5; }
  .enable code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background: var(--bg);
                 border: 1px solid var(--border); border-radius: 4px; padding: 1px 5px; }
  .empty { color: var(--muted); padding: 40px 0; text-align: center; }
</style>
</head>
<body>
<header>
  <h1>Detection Rule Catalogue</h1>
  <div class="sub">Search by Event ID (e.g. 4625), MITRE technique (e.g. T1110), platform, or keyword.</div>
  <input id="search" placeholder="4625, T1110, brute force, aws...">
  <div id="count"></div>
</header>
<main id="results"></main>
<script>
const RULES = __RULES_JSON__;

function levelClass(level) { return "level level-" + (level || "medium").toLowerCase(); }

function chipList(items, cls) {
  return (items || []).map(function(i) {
    return '<span class="chip' + (cls ? ' ' + cls : '') + '">' + escapeHtml(String(i)) + '</span>';
  }).join('');
}

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, function(c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
  });
}

function auditPolicyHtml(ap) {
  if (!ap || Object.keys(ap).length === 0) return '<div class="enable">No audit-enablement notes recorded for this rule yet.</div>';
  var parts = [];
  if (ap.gpo_path) parts.push('<div><strong>GPO path:</strong> ' + escapeHtml(ap.gpo_path) + '</div>');
  if (ap.command) parts.push('<div><strong>Command:</strong> <code>' + escapeHtml(ap.command) + '</code></div>');
  if (ap.notes) parts.push('<div>' + escapeHtml(ap.notes) + '</div>');
  return '<div class="enable">' + parts.join('') + '</div>';
}

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
    '</div>';
}

function matches(r, q) {
  if (!q) return true;
  var hay = [r.id, r.title, r.description, r.platform]
    .concat(r.event_ids || [])
    .concat(r.mitre_attack || [])
    .join(' ')
    .toLowerCase();
  return hay.indexOf(q) !== -1;
}

function render(query) {
  var q = (query || '').trim().toLowerCase();
  var filtered = RULES.filter(function(r) { return matches(r, q); });
  var results = document.getElementById('results');
  var count = document.getElementById('count');
  count.textContent = filtered.length + ' of ' + RULES.length + ' rules';
  results.innerHTML = filtered.length
    ? filtered.map(cardHtml).join('')
    : '<div class="empty">No rules match "' + escapeHtml(query) + '"</div>';
}

document.getElementById('search').addEventListener('input', function(e) { render(e.target.value); });
render('');
</script>
</body>
</html>
"""


def export_html(rules: List[Rule], output_path: str) -> None:
    data = [rule_to_dict(r) for r in rules]
    html = _TEMPLATE.replace("__RULES_JSON__", json.dumps(data))
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
