"""Generates a synthetic attack -> detection cycle: a password-spray brute
force against a Windows account that finally succeeds, and the sequence rule
that catches it.
"""

from __future__ import annotations

import datetime as dt
from typing import List

from .models import Event

ATTACKER_IP = "203.0.113.55"
TARGET_USER = "jsmith"
TARGET_SID = "S-1-5-21-3623811015-3361044348-30300820-1104"
WORKSTATION = "WKSTN01"


def build_brute_force_scenario(failed_attempts: int = 6) -> List[Event]:
    """failed_attempts EventID 4625 (bad password) followed by one EventID 4624
    (successful logon), all from the same source IP against the same account,
    spaced 30s apart so they land inside a 10-minute detection window."""
    start = dt.datetime(2026, 1, 15, 3, 12, 0, tzinfo=dt.timezone.utc)
    events: List[Event] = []

    for i in range(failed_attempts):
        events.append(
            {
                "EventID": 4625,
                "TimeCreated": (start + dt.timedelta(seconds=30 * i)).isoformat(),
                "TargetUserName": TARGET_USER,
                "TargetSid": "S-1-0-0",  # SID is unresolved on failed logon, as in real Windows logs
                "IpAddress": ATTACKER_IP,
                "LogonType": 3,
                "WorkstationName": WORKSTATION,
                "FailureReason": "%%2313",  # unknown user name or bad password
                "SubStatus": "0xC000006A",
            }
        )

    success_time = start + dt.timedelta(seconds=30 * failed_attempts)
    events.append(
        {
            "EventID": 4624,
            "TimeCreated": success_time.isoformat(),
            "TargetUserName": TARGET_USER,
            "TargetSid": TARGET_SID,
            "IpAddress": ATTACKER_IP,
            "LogonType": 3,
            "WorkstationName": WORKSTATION,
        }
    )
    return events


def narrate_scenario(events: List[Event]) -> List[str]:
    lines = []
    for e in events:
        ts = e["TimeCreated"]
        if e["EventID"] == 4625:
            lines.append(
                f"[{ts}] EventID 4625 FAILED LOGON  user={e['TargetUserName']} "
                f"src_ip={e['IpAddress']} logon_type={e['LogonType']}"
            )
        elif e["EventID"] == 4624:
            lines.append(
                f"[{ts}] EventID 4624 SUCCESSFUL LOGON  user={e['TargetUserName']} "
                f"sid={e['TargetSid']} src_ip={e['IpAddress']} logon_type={e['LogonType']}"
            )
    return lines
