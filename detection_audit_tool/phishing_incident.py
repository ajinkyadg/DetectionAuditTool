"""A worked phishing-to-account-takeover incident: a 5-stage kill chain, a
campaign narrative, and a set of simulated recipients with different
outcomes - the "who's actually impacted" triage exercise this tool builds
towards.

Stage indices are meaningful: they define how far a user got. -1 means the
email never reached the mailbox at all.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List

DEFAULT_WEB_PROXY_LOG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "sample_logs",
    "phishing_campaign_web_proxy.json",
)

CAMPAIGN: Dict[str, Any] = {
    "name": "Password Expiry Phishing Campaign",
    "sender_display_name": "IT Helpdesk",
    "sender_address": "it-support@corp-secure-verify.com",
    "subject": "Action Required: Your password expires today",
    "lookalike_domain": "corp-secure-verify.com",
    "phishing_kit_url": "https://corp-secure-verify.com/reset",
    "sent_at": "2026-04-02T08:45:00+00:00",
    "recipients": 8,
}


@dataclass
class ResponseAction:
    id: str
    label: str


@dataclass
class Stage:
    id: str
    index: int
    name: str
    mitre: List[str]
    narrative: str
    rule_ids: List[str]
    actions: List[ResponseAction]
    blind_spot_note: str = ""


@dataclass
class UserOutcome:
    name: str
    mailbox: str
    furthest_stage: int  # -1 = never delivered
    status: str  # safe | unknown | at_risk | compromised | compromised_active
    note: str


STAGES: List[Stage] = [
    Stage(
        id="delivery",
        index=0,
        name="Email Delivered",
        mitre=["T1566.002"],
        narrative=(
            "The spoofed 'IT Helpdesk' email lands in 7 of 8 mailboxes; the email "
            "gateway's own sandboxing catches and blocks it for the 8th."
        ),
        rule_ids=["EMAIL-8006"],
        actions=[
            ResponseAction("block-sender", "Retroactively purge / block sender domain at the email gateway"),
            ResponseAction("url-rewrite", "Enable time-of-click URL rewriting / sandboxing (Safe Links)"),
        ],
    ),
    Stage(
        id="click",
        index=1,
        name="Link Clicked",
        mitre=["T1204.001"],
        narrative=(
            "4 recipients click through to the lookalike domain's fake Microsoft-style login page - "
            "confirmed as a GET to the phishing URL in the web proxy log, correlated per user below."
        ),
        rule_ids=["WEBPROXY-9002"],
        actions=[
            ResponseAction("block-domain-proxy", "Block the lookalike domain at the web proxy/firewall"),
            ResponseAction("isolate-endpoint", "Isolate the endpoint via EDR network containment"),
        ],
    ),
    Stage(
        id="credentials",
        index=2,
        name="Credentials Entered",
        mitre=["T1598.003", "T1556"],
        narrative=(
            "3 of those recipients type their corporate username and password into the fake page."
        ),
        rule_ids=[],
        blind_spot_note=(
            "The credential submission itself happens on attacker-controlled infrastructure - no "
            "internal log sees the password. The proxy log's best proxy signal is a POST request to "
            "the same phishing URL right after the GET (see per-user evidence below); the first "
            "hard confirmation usually comes later, at the attacker sign-in stage."
        ),
        actions=[
            ResponseAction("force-reset", "Force a password reset for every user who reached this stage"),
            ResponseAction("mfa-reenroll", "Require MFA re-registration before the next sign-in"),
        ],
    ),
    Stage(
        id="attacker-logon",
        index=3,
        name="Attacker Signs In",
        mitre=["T1078", "T1078.004"],
        narrative=(
            "The attacker replays the harvested credentials. One attempt is blocked by an MFA "
            "challenge it can't satisfy; one succeeds outright from a different country minutes later."
        ),
        rule_ids=["ID-9001"],
        actions=[
            ResponseAction("disable-account", "Disable the compromised account"),
            ResponseAction("revoke-sessions", "Revoke all active sessions/refresh tokens"),
        ],
    ),
    Stage(
        id="post-compromise",
        index=4,
        name="Post-Compromise Action",
        mitre=["T1114.003", "T1098.002"],
        narrative=(
            "Inside the mailbox, the attacker immediately creates a quiet external forwarding rule "
            "to keep receiving mail after the password is eventually changed."
        ),
        rule_ids=["ID-9002"],
        actions=[
            ResponseAction("remove-rule", "Remove the malicious inbox forwarding rule"),
            ResponseAction("notify-contacts", "Notify recipients of any lateral phishing sent from the mailbox"),
            ResponseAction("forensics", "Open a full forensic review of the mailbox and OAuth app consents"),
        ],
    ),
]


USERS: List[UserOutcome] = [
    UserOutcome(
        name="Tariq Nguyen",
        mailbox="tnguyen@corp.com",
        furthest_stage=-1,
        status="safe",
        note="Email gateway sandboxing detonated the link and blocked delivery outright.",
    ),
    UserOutcome(
        name="Asha Smith",
        mailbox="asmith@corp.com",
        furthest_stage=0,
        status="safe",
        note="Reported the email via the Report Phishing button within 4 minutes of delivery.",
    ),
    UserOutcome(
        name="Jamie Doe",
        mailbox="jdoe@corp.com",
        furthest_stage=0,
        status="safe",
        note="Read the subject line, recognized it as suspicious, and deleted it without clicking.",
    ),
    UserOutcome(
        name="Kayla Garcia",
        mailbox="kgarcia@corp.com",
        furthest_stage=0,
        status="unknown",
        note=(
            "No corporate proxy/EDR telemetry for this user in the window - the email was opened "
            "on an unmanaged personal device. Treat as compromised until confirmed otherwise."
        ),
    ),
    UserOutcome(
        name="Ben Wong",
        mailbox="bwong@corp.com",
        furthest_stage=1,
        status="at_risk",
        note="Clicked the link, saw the fake login page, got suspicious and closed the tab without entering anything.",
    ),
    UserOutcome(
        name="Liam Jackson",
        mailbox="ljackson@corp.com",
        furthest_stage=2,
        status="compromised",
        note=(
            "Entered credentials on the fake page; no follow-on sign-in observed yet in this "
            "window - assume the credential is live and unused so far, reset immediately."
        ),
    ),
    UserOutcome(
        name="Raj Patel",
        mailbox="rpatel@corp.com",
        furthest_stage=2,
        status="compromised",
        note=(
            "Entered credentials; the attacker's follow-on sign-in from Russia was blocked by an "
            "MFA challenge it couldn't satisfy. Credentials are burned but the account itself "
            "was not taken over."
        ),
    ),
    UserOutcome(
        name="Maria Chen",
        mailbox="mchen@corp.com",
        furthest_stage=4,
        status="compromised_active",
        note=(
            "Entered credentials; the attacker signed in 14 minutes later from Nigeria and "
            "immediately added an external mailbox forwarding rule."
        ),
    ),
]


def stage_reach_counts(stages: List[Stage] = STAGES, users: List[UserOutcome] = USERS) -> Dict[str, int]:
    return {s.id: sum(1 for u in users if u.furthest_stage >= s.index) for s in stages}


def load_web_proxy_evidence(path: str = DEFAULT_WEB_PROXY_LOG_PATH) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def correlate_web_proxy_evidence(
    users: List[UserOutcome] = USERS,
    events: List[Dict[str, Any]] = None,
) -> Dict[str, Dict[str, Any]]:
    """For each user, pull every web proxy hit against the campaign's lookalike
    domain and derive clicked/credentials_entered from GET vs. POST - the same
    distinction WEBPROXY-9002 alone can't make (it only sees "a request to a
    newly-registered domain happened", not what kind).

    This is what actually answers "who clicked and who entered credentials" -
    the USERS narrative above states the outcome, this function proves it from
    a log source.
    """
    if events is None:
        events = load_web_proxy_evidence()

    by_local_part: Dict[str, List[Dict[str, Any]]] = {}
    for event in events:
        if event.get("domain") != CAMPAIGN["lookalike_domain"]:
            continue
        by_local_part.setdefault(event["user"], []).append(event)

    result: Dict[str, Dict[str, Any]] = {}
    for user in users:
        local_part = user.mailbox.split("@")[0]
        matched = sorted(by_local_part.get(local_part, []), key=lambda e: e["timestamp"])
        result[user.mailbox] = {
            "clicked": any(e["method"] == "GET" for e in matched),
            "credentials_entered": any(e["method"] == "POST" for e in matched),
            "events": matched,
        }
    return result
