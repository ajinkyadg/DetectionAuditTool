"""Export the phishing incident as a single self-contained, interactive HTML
page: a clickable kill chain where you build a detection + response plan
stage by stage and watch the user-triage table recompute live.

No server - open the file directly in a browser.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any, Dict, List

from .html_export import rule_to_dict
from .models import Rule
from .phishing_incident import CAMPAIGN, STAGES, USERS, Stage, UserOutcome, correlate_web_proxy_evidence


def _stage_to_dict(stage: Stage, rules_by_id: Dict[str, Rule]) -> Dict[str, Any]:
    return {
        "id": stage.id,
        "index": stage.index,
        "name": stage.name,
        "mitre": stage.mitre,
        "narrative": stage.narrative,
        "blind_spot_note": stage.blind_spot_note,
        "rules": [rule_to_dict(rules_by_id[rid]) for rid in stage.rule_ids if rid in rules_by_id],
        "actions": [{"id": a.id, "label": a.label, "stage_index": stage.index} for a in stage.actions],
    }


def _user_to_dict(user: UserOutcome, evidence: Dict[str, Any]) -> Dict[str, Any]:
    data = asdict(user)
    data["proxy_evidence"] = evidence.get(user.mailbox, {"clicked": False, "credentials_entered": False, "events": []})
    return data


_TEMPLATE = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Phishing Incident Walkthrough</title>
<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
<style>
  :root {
    color-scheme: light dark;
    --bg: #f7f8fa; --card: #ffffff; --text: #1c1e21; --muted: #666;
    --border: #e2e4e8; --accent: #2563eb;
    --safe: #16a34a; --unknown: #6b7280; --atrisk: #d97706; --compromised: #dc2626; --active: #7c1d1d;
  }
  @media (prefers-color-scheme: dark) {
    :root { --bg: #16181c; --card: #1f2227; --text: #e8e9eb; --muted: #9aa0a8; --border: #33363b; }
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--text);
         font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
  header { padding: 20px 24px 0; max-width: 1200px; }
  h1 { margin: 0 0 4px; font-size: 20px; }
  .sub { color: var(--muted); font-size: 13px; margin-bottom: 14px; }
  .campaign-card { background: var(--card); border: 1px solid var(--border); border-radius: 10px;
                    padding: 14px 18px; margin: 0 24px 20px; max-width: 1152px; font-size: 13px; }
  .campaign-card .row { display: flex; flex-wrap: wrap; gap: 6px 22px; margin-top: 6px; }
  .campaign-card .row div { color: var(--muted); }
  .campaign-card strong { color: var(--text); }
  main { padding: 0 24px 40px; max-width: 1200px; }
  .diagram-panel { background: var(--bg); border-bottom: 1px solid var(--border); padding: 10px 0 12px;
                    position: sticky; top: 0; z-index: 20; }
  .diagram-panel.stuck { box-shadow: 0 6px 14px -8px rgba(0,0,0,.35); }
  .diagram-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
  .diagram-panel h2 { margin: 0; font-size: 13px; }
  .legend-toggle { background: none; border: 1px solid var(--border); color: var(--muted); border-radius: 999px;
                    font-size: 11px; padding: 3px 10px; cursor: pointer; }
  .legend { display: none; flex-wrap: wrap; gap: 10px; margin: 8px 0 0; font-size: 11px; color: var(--muted); }
  .legend.open { display: flex; }
  .legend-item { display: flex; align-items: center; gap: 5px; }
  .swatch { width: 16px; height: 16px; border-radius: 5px; display: inline-flex; align-items: center;
            justify-content: center; font-size: 10px; line-height: 1; }
  #diagram-container { min-height: 90px; max-height: 42vh; overflow: auto; }
  .killchain { display: flex; flex-direction: column; gap: 8px; margin-top: 16px; }
  .stage-card { background: var(--card); border: 1px solid var(--border); border-top: 3px solid var(--accent);
                border-radius: 10px; padding: 0; width: 100%; }
  .stage-card.capped { opacity: 0.55; }
  .stage-card > summary { list-style: none; cursor: pointer; padding: 12px 14px; }
  .stage-card > summary::-webkit-details-marker { display: none; }
  .stage-body { padding: 0 14px 14px; display: flex; flex-direction: column; gap: 8px; }
  .stage-idx { display: inline-block; width: 20px; height: 20px; line-height: 20px; text-align: center;
               border-radius: 50%; background: var(--accent); color: #fff; font-size: 11px; margin-right: 6px; }
  .stage-header { display: flex; align-items: center; gap: 10px; }
  .stage-icon-circle { flex: none; width: 32px; height: 32px; border-radius: 50%; display: flex;
                        align-items: center; justify-content: center; font-size: 15px;
                        box-shadow: 0 1px 3px rgba(0,0,0,.25); }
  .stage-summary-text { flex: 1; min-width: 0; }
  .stage-card h3 { margin: 0; font-size: 14px; display: flex; align-items: center; }
  .reach-inline { font-size: 11px; color: var(--muted); margin-top: 1px; }
  .chevron { color: var(--muted); font-size: 12px; transition: transform .15s; flex: none; }
  .stage-card[open] .chevron { transform: rotate(90deg); }
  .reach-count { font-size: 22px; font-weight: 700; }
  .reach-label { font-size: 11px; color: var(--muted); }
  .chip { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 10px;
          border: 1px solid var(--border); color: var(--muted); margin: 0 4px 4px 0; }
  .narrative { font-size: 12px; color: var(--muted); line-height: 1.4; }
  .blind-spot { font-size: 11px; background: color-mix(in srgb, var(--atrisk) 15%, var(--card));
                border: 1px solid var(--atrisk); border-radius: 6px; padding: 6px 8px; color: var(--text); }
  .section-title { font-size: 10px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); margin-top: 4px; }
  .rule-chip-btn { background: none; border: 1px solid #7c3aed; color: #7c3aed; border-radius: 999px;
                   font-size: 10px; padding: 2px 8px; cursor: pointer; margin: 0 4px 4px 0; }
  .rule-detail { font-size: 11px; background: var(--bg); border: 1px solid var(--border); border-radius: 6px;
                 padding: 8px; margin-top: 4px; line-height: 1.5; }
  .action-row { display: flex; align-items: flex-start; gap: 6px; font-size: 12px; margin-top: 3px; }
  .action-row input { margin-top: 2px; accent-color: #0d9488; }
  .plan-and-kpi { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin: 20px 0; }
  .panel { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 16px; }
  .panel h2 { margin: 0 0 8px; font-size: 14px; }
  .plan-list { font-size: 12px; padding-left: 18px; margin: 6px 0; }
  .plan-empty { color: var(--muted); font-size: 12px; }
  .kpi-row { display: flex; gap: 14px; flex-wrap: wrap; }
  .kpi { flex: 1; min-width: 100px; text-align: center; }
  .kpi .num { font-size: 22px; font-weight: 700; }
  .kpi .lbl { font-size: 10px; color: var(--muted); text-transform: uppercase; }
  .kpi.safe .num { color: var(--safe); }
  .kpi.unknown .num { color: var(--unknown); }
  .kpi.at_risk .num { color: var(--atrisk); }
  .kpi.compromised .num, .kpi.compromised_active .num { color: var(--compromised); }
  table.triage { width: 100%; border-collapse: collapse; font-size: 13px; background: var(--card);
                 border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
  table.triage th, table.triage td { text-align: left; padding: 9px 10px; border-bottom: 1px solid var(--border); }
  .status-badge { font-size: 10px; text-transform: uppercase; font-weight: 700; padding: 3px 8px; border-radius: 4px; color: #fff; }
  .status-safe { background: var(--safe); }
  .status-unknown { background: var(--unknown); }
  .status-at_risk { background: var(--atrisk); }
  .status-compromised { background: var(--compromised); }
  .status-compromised_active { background: var(--active); }
  .arrow-cell { color: var(--muted); font-size: 12px; }
  .caveat { font-size: 11px; color: var(--muted); margin: 6px 0 18px; max-width: 900px; }
</style>
</head>
<body>
<header>
  <h1>Phishing Incident Walkthrough</h1>
  <div class="sub">A worked kill chain, correlated from real log evidence. Expand a stage for its detection rule and response actions.</div>
</header>
<div class="campaign-card" id="campaign-card"></div>
<main>
  <div class="diagram-panel" id="diagram-panel">
    <div class="diagram-head">
      <h2>Kill Chain - click a stage below for detail</h2>
      <button class="legend-toggle" id="legend-toggle" type="button">Legend</button>
    </div>
    <div class="legend" id="legend"></div>
    <div id="diagram-container"><div class="narrative">Rendering diagram...</div></div>
  </div>
  <div class="killchain" id="killchain"></div>
  <div class="caveat">
    Checking a response action assumes that control existed <em>before</em> this campaign started -
    it caps every user's outcome at that stage. It's a teaching simplification, not a claim about
    what any single mid-incident action would retroactively undo.
  </div>
  <div class="plan-and-kpi">
    <div class="panel">
      <h2>Your Incident Response Plan</h2>
      <div class="section-title">Detection rules referenced</div>
      <div id="plan-rules" class="plan-empty">None selected yet - click a rule chip on any stage.</div>
      <div class="section-title">Response actions selected</div>
      <div id="plan-actions" class="plan-empty">None selected yet - check a response action on any stage.</div>
    </div>
    <div class="panel">
      <h2>Impact: Before vs. After Your Plan</h2>
      <div class="section-title">Before (as the incident actually unfolded)</div>
      <div class="kpi-row" id="kpi-before"></div>
      <div class="section-title" style="margin-top:10px;">After (with your selected response actions)</div>
      <div class="kpi-row" id="kpi-after"></div>
    </div>
  </div>
  <div class="panel">
    <h2>User Triage</h2>
    <table class="triage">
      <thead><tr><th>User</th><th>Mailbox</th><th>Furthest Stage</th><th>Original</th><th></th><th>Revised</th><th>Notes</th><th>Evidence</th></tr></thead>
      <tbody id="triage-rows"></tbody>
    </table>
  </div>
</main>
<script>
const CAMPAIGN = __CAMPAIGN_JSON__;
const STAGES = __STAGES_JSON__;
const USERS = __USERS_JSON__;

const STAGE_COLORS = ['#2563eb', '#d97706', '#ea580c', '#dc2626', '#7c1d1d'];
const STAGE_ICONS = ['\U0001F4E7', '\U0001F5B1', '\U0001F511', '\U0001F575', '\U0001F4E4'];
const RULE_COLOR = '#7c3aed';
const ACTION_COLOR = '#0d9488';
const BLINDSPOT_COLOR = '#6b7280';
const RULE_ICON = '\U0001F50D';
const ACTION_ICON = '\U0001F6E1';
const BLINDSPOT_ICON = '❓';
const CAMPAIGN_ICON = '\U0001F3A3';
const STATUS_ICONS = { safe: '✅', unknown: '❔', at_risk: '⚠', compromised: '\U0001F6A8', compromised_active: '\U0001F525' };

var prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
mermaid.initialize({
  startOnLoad: false,
  theme: prefersDark ? 'dark' : 'default',
  themeVariables: { fontSize: '16px' },
  flowchart: { htmlLabels: true, nodeSpacing: 40, rankSpacing: 55 },
});

/* Mermaid ships each SVG at width="100%" with a max-width style, so it
   shrinks (text included) to fit whatever container it lands in - great for
   a small diagram, unreadable for a wide branching one. Force it back to
   its natural pixel size and let the container scroll instead of squeezing. */
function useNaturalSvgSize(svgMarkup) {
  var wrapper = document.createElement('div');
  wrapper.innerHTML = svgMarkup;
  var svg = wrapper.querySelector('svg');
  if (svg) {
    var viewBox = (svg.getAttribute('viewBox') || '').split(/\s+/).map(Number);
    if (viewBox.length === 4 && viewBox[2] && viewBox[3]) {
      svg.setAttribute('width', Math.round(viewBox[2]) + 'px');
      svg.setAttribute('height', Math.round(viewBox[3]) + 'px');
      svg.style.maxWidth = 'none';
    }
  }
  return wrapper.innerHTML;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, function(c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
  });
}

/* ---------- Campaign summary ---------- */
document.getElementById('campaign-card').innerHTML =
  '<strong>' + escapeHtml(CAMPAIGN.name) + '</strong>' +
  '<div class="row">' +
    '<div>From: <strong>' + escapeHtml(CAMPAIGN.sender_display_name) + ' &lt;' + escapeHtml(CAMPAIGN.sender_address) + '&gt;</strong></div>' +
    '<div>Subject: <strong>' + escapeHtml(CAMPAIGN.subject) + '</strong></div>' +
    '<div>Lookalike domain: <strong>' + escapeHtml(CAMPAIGN.lookalike_domain) + '</strong></div>' +
    '<div>Sent: <strong>' + escapeHtml(CAMPAIGN.sent_at) + '</strong></div>' +
    '<div>Recipients: <strong>' + escapeHtml(String(CAMPAIGN.recipients)) + '</strong></div>' +
  '</div>';

/* ---------- State ---------- */
var selectedActionIds = new Set();
var selectedRuleIds = new Set();

function containmentCap() {
  var cap = Infinity;
  STAGES.forEach(function(stage) {
    stage.actions.forEach(function(a) {
      if (selectedActionIds.has(a.id)) cap = Math.min(cap, stage.index);
    });
  });
  return cap;
}

function deriveStatus(furthestStage, originalStatus) {
  if (originalStatus === 'unknown') return 'unknown';
  if (furthestStage <= 0) return 'safe';
  if (furthestStage === 1) return 'at_risk';
  if (furthestStage < 4) return 'compromised';
  return 'compromised_active';
}

function revisedStage(user, cap) {
  return cap === Infinity ? user.furthest_stage : Math.min(user.furthest_stage, cap);
}

/* ---------- Kill chain rendering ---------- */
function auditPolicyHtml(ap) {
  if (!ap || Object.keys(ap).length === 0) return '';
  var parts = [];
  if (ap.gpo_path) parts.push('<div><strong>Where:</strong> ' + escapeHtml(ap.gpo_path) + '</div>');
  if (ap.command) parts.push('<div><strong>Command:</strong> <code>' + escapeHtml(ap.command) + '</code></div>');
  if (ap.notes) parts.push('<div style="margin-top:4px;">' + escapeHtml(ap.notes) + '</div>');
  return parts.join('');
}

function ruleDetailHtml(r) {
  return '' +
    '<div class="rule-detail">' +
      '<div><strong>' + escapeHtml(r.id) + '</strong>: ' + escapeHtml(r.title) + ' (' + escapeHtml(r.level) + ')</div>' +
      '<div style="margin:4px 0;">' + escapeHtml(r.description || '') + '</div>' +
      '<div><strong>Fields needed:</strong> ' + (r.required_fields || []).map(escapeHtml).join(', ') + '</div>' +
      auditPolicyHtml(r.audit_policy) +
    '</div>';
}

var expandedStageId = STAGES[0].id;

function stageCardHtml(stage, reachCount, cap) {
  var capped = cap !== Infinity && stage.index > cap;
  var rulesHtml = stage.rules.length
    ? stage.rules.map(function(r) {
        return '<button class="rule-chip-btn" data-stage="' + stage.id + '" data-rule="' + escapeHtml(r.id) + '">' + escapeHtml(r.id) + '</button>';
      }).join('')
    : '<div class="narrative">No internal detection rule covers this step.</div>';
  var blindSpot = stage.blind_spot_note
    ? '<div class="blind-spot">Blind spot: ' + escapeHtml(stage.blind_spot_note) + '</div>' : '';
  var actionsHtml = stage.actions.map(function(a) {
    var checked = selectedActionIds.has(a.id) ? ' checked' : '';
    return '<label class="action-row"><input type="checkbox" data-action="' + escapeHtml(a.id) + '"' + checked + '> ' + escapeHtml(a.label) + '</label>';
  }).join('');
  var borderColor = STAGE_COLORS[stage.index] || '#2563eb';
  var icon = STAGE_ICONS[stage.index] || '';
  var isOpen = stage.id === expandedStageId;
  return '' +
    '<details class="stage-card' + (capped ? ' capped' : '') + '" data-stage-id="' + stage.id + '"' +
        ' style="border-top-color:' + borderColor + '"' + (isOpen ? ' open' : '') + '>' +
      '<summary>' +
        '<div class="stage-header">' +
          '<span class="stage-icon-circle" style="background:' + borderColor + '">' + icon + '</span>' +
          '<div class="stage-summary-text">' +
            '<h3><span class="stage-idx" style="background:' + borderColor + '">' + stage.index + '</span>' + escapeHtml(stage.name) + '</h3>' +
            '<div class="reach-inline">' + reachCount + ' / ' + USERS.length + ' users reached this stage</div>' +
          '</div>' +
          '<span class="chevron">&#9656;</span>' +
        '</div>' +
      '</summary>' +
      '<div class="stage-body">' +
        '<div>' + stage.mitre.map(function(m) { return '<span class="chip">' + escapeHtml(m) + '</span>'; }).join('') + '</div>' +
        '<div class="narrative">' + escapeHtml(stage.narrative) + '</div>' +
        blindSpot +
        '<div class="section-title">Detection rule</div>' +
        '<div id="rules-' + stage.id + '">' + rulesHtml + '</div>' +
        '<div class="section-title">Response actions</div>' +
        actionsHtml +
      '</div>' +
    '</details>';
}

function renderKillchain() {
  var cap = containmentCap();
  var html = [];
  STAGES.forEach(function(stage) {
    var reachCount = USERS.filter(function(u) { return revisedStage(u, cap) >= stage.index; }).length;
    html.push(stageCardHtml(stage, reachCount, cap));
  });
  var killchainEl = document.getElementById('killchain');
  killchainEl.innerHTML = html.join('');

  killchainEl.querySelectorAll('details.stage-card').forEach(function(details) {
    details.addEventListener('toggle', function() {
      if (details.open) {
        expandedStageId = details.dataset.stageId;
        killchainEl.querySelectorAll('details.stage-card').forEach(function(other) {
          if (other !== details) other.open = false;
        });
      } else if (expandedStageId === details.dataset.stageId) {
        expandedStageId = null;
      }
    });
  });

  killchainEl.querySelectorAll('.rule-chip-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var stageId = btn.dataset.stage, ruleId = btn.dataset.rule;
      var container = document.getElementById('rules-' + stageId);
      var existing = container.querySelector('.rule-detail[data-for="' + ruleId + '"]');
      if (existing) { existing.remove(); return; }
      var stage = STAGES.find(function(s) { return s.id === stageId; });
      var rule = stage.rules.find(function(r) { return r.id === ruleId; });
      var div = document.createElement('div');
      div.innerHTML = ruleDetailHtml(rule);
      div.firstChild.setAttribute('data-for', ruleId);
      container.appendChild(div.firstChild);
      selectedRuleIds.add(ruleId);
      renderPlan();
    });
  });

  killchainEl.querySelectorAll('[data-action]').forEach(function(cb) {
    cb.addEventListener('change', function() {
      if (cb.checked) selectedActionIds.add(cb.dataset.action);
      else selectedActionIds.delete(cb.dataset.action);
      renderAll();
    });
  });
}

/* ---------- Plan panel ---------- */
function renderPlan() {
  var rulesEl = document.getElementById('plan-rules');
  if (selectedRuleIds.size === 0) {
    rulesEl.className = 'plan-empty';
    rulesEl.textContent = 'None selected yet - click a rule chip on any stage.';
  } else {
    rulesEl.className = 'plan-list';
    rulesEl.innerHTML = '<ul class="plan-list">' + Array.from(selectedRuleIds).map(function(id) {
      return '<li>' + escapeHtml(id) + '</li>';
    }).join('') + '</ul>';
  }

  var actionsEl = document.getElementById('plan-actions');
  var chosen = [];
  STAGES.forEach(function(stage) {
    stage.actions.forEach(function(a) {
      if (selectedActionIds.has(a.id)) chosen.push(stage.name + ': ' + a.label);
    });
  });
  if (chosen.length === 0) {
    actionsEl.className = 'plan-empty';
    actionsEl.textContent = 'None selected yet - check a response action on any stage.';
  } else {
    actionsEl.className = 'plan-list';
    actionsEl.innerHTML = '<ul class="plan-list">' + chosen.map(function(c) { return '<li>' + escapeHtml(c) + '</li>'; }).join('') + '</ul>';
  }
}

/* ---------- KPI + triage table ---------- */
var STATUS_LABELS = { safe: 'Safe', unknown: 'Unknown', at_risk: 'At Risk', compromised: 'Compromised', compromised_active: 'Compromised (Active)' };
var STATUS_ORDER = ['safe', 'unknown', 'at_risk', 'compromised', 'compromised_active'];

function kpiHtml(statuses) {
  var counts = {};
  STATUS_ORDER.forEach(function(s) { counts[s] = 0; });
  statuses.forEach(function(s) { counts[s]++; });
  return STATUS_ORDER.map(function(s) {
    return '<div class="kpi ' + s + '"><div class="num">' + STATUS_ICONS[s] + ' ' + counts[s] + '</div><div class="lbl">' + STATUS_LABELS[s] + '</div></div>';
  }).join('');
}

function renderKpiAndTriage() {
  var cap = containmentCap();
  var beforeStatuses = USERS.map(function(u) { return u.status; });
  var afterStatuses = USERS.map(function(u) { return deriveStatus(revisedStage(u, cap), u.status); });
  document.getElementById('kpi-before').innerHTML = kpiHtml(beforeStatuses);
  document.getElementById('kpi-after').innerHTML = kpiHtml(afterStatuses);

  var stageNameByIndex = {};
  STAGES.forEach(function(s) { stageNameByIndex[s.index] = s.name; });
  stageNameByIndex[-1] = 'Never delivered';

  var rows = USERS.map(function(u, i) {
    var revised = revisedStage(u, cap);
    var revisedStatus = afterStatuses[i];
    var changed = revisedStatus !== u.status;
    var events = (u.proxy_evidence && u.proxy_evidence.events) || [];
    var evidenceCell = events.length
      ? '<button class="rule-chip-btn" data-evidence="' + escapeHtml(u.mailbox) + '">' + events.length + ' log(s)</button>'
      : '<span class="narrative">none</span>';
    var mainRow = '<tr>' +
      '<td>' + escapeHtml(u.name) + '</td>' +
      '<td>' + escapeHtml(u.mailbox) + '</td>' +
      '<td>' + escapeHtml(stageNameByIndex[revised] || String(revised)) + '</td>' +
      '<td><span class="status-badge status-' + u.status + '">' + STATUS_ICONS[u.status] + ' ' + STATUS_LABELS[u.status] + '</span></td>' +
      '<td class="arrow-cell">' + (changed ? '&rarr;' : '') + '</td>' +
      '<td><span class="status-badge status-' + revisedStatus + '">' + STATUS_ICONS[revisedStatus] + ' ' + STATUS_LABELS[revisedStatus] + '</span></td>' +
      '<td>' + escapeHtml(u.note) + '</td>' +
      '<td>' + evidenceCell + '</td>' +
    '</tr>';
    var evidenceRow = events.length
      ? '<tr class="evidence-row" id="evidence-' + escapeHtml(u.mailbox) + '" hidden><td colspan="8">' +
          '<div class="rule-detail">' +
            '<div><strong>web_proxy</strong> hits against ' + escapeHtml(CAMPAIGN.lookalike_domain) + ' for user "' + escapeHtml(u.mailbox.split('@')[0]) + '":</div>' +
            events.map(function(e) {
              return '<div style="margin-top:4px;"><code>' + escapeHtml(e.timestamp) + '</code> ' +
                escapeHtml(e.method) + ' ' + escapeHtml(e.url) +
                ' (bytes_out=' + escapeHtml(String(e.bytes_out)) + ')' +
                (e.method === 'POST' ? ' &larr; form submission (WEBPROXY-9002 + payload size = credentials entered)' : ' &larr; page load only') +
                '</div>';
            }).join('') +
          '</div>' +
        '</td></tr>'
      : '';
    return mainRow + evidenceRow;
  });
  document.getElementById('triage-rows').innerHTML = rows.join('');

  document.querySelectorAll('[data-evidence]').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var row = document.getElementById('evidence-' + btn.dataset.evidence);
      if (row) row.hidden = !row.hidden;
    });
  });
}

/* ---------- Kill chain diagram (Mermaid) ---------- */
function renderLegend() {
  var items = STAGES.map(function(s, i) {
    return '<span class="legend-item"><span class="swatch" style="background:' + STAGE_COLORS[i] + '">' + STAGE_ICONS[i] + '</span>' + escapeHtml(s.name) + '</span>';
  });
  items.push('<span class="legend-item"><span class="swatch" style="background:' + RULE_COLOR + '">' + RULE_ICON + '</span>Detection rule</span>');
  items.push('<span class="legend-item"><span class="swatch" style="background:' + ACTION_COLOR + '">' + ACTION_ICON + '</span>Response action</span>');
  items.push('<span class="legend-item"><span class="swatch" style="background:' + BLINDSPOT_COLOR + '">' + BLINDSPOT_ICON + '</span>No internal detection (blind spot)</span>');
  document.getElementById('legend').innerHTML = items.join('');
}

document.getElementById('legend-toggle').addEventListener('click', function() {
  document.getElementById('legend').classList.toggle('open');
});

/* Shadow on the sticky diagram bar once the page has actually scrolled under it */
var diagramPanelEl = document.getElementById('diagram-panel');
window.addEventListener('scroll', function() {
  diagramPanelEl.classList.toggle('stuck', window.scrollY > 4);
});

function sanitizeLabel(s, maxLen) {
  var cleaned = String(s).replace(/["()\[\]{}]/g, '');
  if (maxLen && cleaned.length > maxLen) cleaned = cleaned.slice(0, maxLen - 1) + '…';
  return cleaned;
}

function buildDiagramDef(cap) {
  var lines = ['flowchart LR', 'CAMP["' + CAMPAIGN_ICON + ' ' + sanitizeLabel(CAMPAIGN.name, 30) + '"]'];
  var prevNode = 'CAMP';

  STAGES.forEach(function(stage, i) {
    var sNode = 'S' + stage.index;
    var capped = cap !== Infinity && stage.index > cap;
    lines.push(sNode + '["' + STAGE_ICONS[stage.index] + ' ' + stage.index + '. ' + sanitizeLabel(stage.name, 30) + '"]');
    lines.push(prevNode + ' --> ' + sNode);
    lines.push('class ' + sNode + ' stage' + stage.index + (capped ? 'Capped' : ''));
    prevNode = sNode;

    if (stage.rules.length) {
      stage.rules.forEach(function(r, ri) {
        var rNode = 'R' + stage.index + '_' + ri;
        lines.push(rNode + '["' + RULE_ICON + ' ' + sanitizeLabel(r.id, 24) + '"]');
        lines.push(sNode + ' -.->|detects| ' + rNode);
        lines.push('class ' + rNode + ' ruleNode');
      });
    } else {
      var nrNode = 'NR' + stage.index;
      lines.push(nrNode + '["' + BLINDSPOT_ICON + ' no internal rule"]');
      lines.push(sNode + ' -.-> ' + nrNode);
      lines.push('class ' + nrNode + ' blindSpotNode');
    }

    stage.actions.forEach(function(a, ai) {
      var aNode = 'A' + stage.index + '_' + ai;
      var selected = selectedActionIds.has(a.id);
      lines.push(aNode + '["' + ACTION_ICON + ' ' + sanitizeLabel(a.label, 34) + '"]');
      lines.push(sNode + ' --> ' + aNode);
      lines.push('class ' + aNode + (selected ? ' actionSelected' : ' actionNode'));
      if (i < STAGES.length - 1) {
        lines.push(aNode + ' -.->|would stop| S' + STAGES[i + 1].index);
      }
    });
  });

  lines.push('classDef campNode fill:#475569,color:#fff,stroke:#334155');
  lines.push('classDef ruleNode fill:' + RULE_COLOR + ',color:#fff,stroke:#5b21b6');
  lines.push('classDef actionNode fill:' + ACTION_COLOR + ',color:#fff,stroke:#0f766e');
  lines.push('classDef actionSelected fill:' + ACTION_COLOR + ',color:#fff,stroke:#fff,stroke-width:3px');
  lines.push('classDef blindSpotNode fill:' + BLINDSPOT_COLOR + ',color:#fff,stroke:#4b5563,stroke-dasharray: 3 3');
  STAGE_COLORS.forEach(function(color, idx) {
    lines.push('classDef stage' + idx + ' fill:' + color + ',color:#fff,stroke:#00000033');
    lines.push('classDef stage' + idx + 'Capped fill:' + color + ',color:#fff,stroke:#00000033,opacity:0.3');
  });
  lines.push('class CAMP campNode');

  return lines.join('\\n');
}

var diagramRenderCounter = 0;
function renderDiagram() {
  var cap = containmentCap();
  var container = document.getElementById('diagram-container');
  mermaid.render('mmd-incident-' + (diagramRenderCounter++), buildDiagramDef(cap)).then(function(res) {
    container.innerHTML = useNaturalSvgSize(res.svg);
  }).catch(function(err) {
    container.innerHTML = '<div class="narrative">Could not render diagram: ' + escapeHtml(String(err)) + '</div>';
  });
}

function renderAll() {
  renderKillchain();
  renderPlan();
  renderKpiAndTriage();
  renderDiagram();
}

renderLegend();
renderAll();
</script>
</body>
</html>
"""


def export_phishing_incident_html(rules: List[Rule], output_path: str) -> None:
    rules_by_id = {r.id: r for r in rules}
    evidence = correlate_web_proxy_evidence()
    stages_data = [_stage_to_dict(s, rules_by_id) for s in STAGES]
    users_data = [_user_to_dict(u, evidence) for u in USERS]

    html = (
        _TEMPLATE.replace("__CAMPAIGN_JSON__", json.dumps(CAMPAIGN))
        .replace("__STAGES_JSON__", json.dumps(stages_data))
        .replace("__USERS_JSON__", json.dumps(users_data))
    )
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
