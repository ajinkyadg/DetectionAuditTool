# Detection Audit Tool

A small, from-scratch detection engineering toolkit built around three ideas
from SOC/SIEM onboarding and incident response work:

1. **A rule catalogue** of top attacks per platform (Windows, Linux, AWS),
   written as Sigma-style YAML, each tagged with MITRE ATT&CK, the exact log
   fields the rule needs, and how to turn on the audit policy that produces
   those fields.
2. **A lookup/search interface** - given an Event ID (or MITRE technique, or
   keyword), find every rule that depends on it, what fields it needs, and
   how to enable the audit setting that populates them. Available as a CLI
   command and as a static, searchable HTML page.
3. **An attack-to-detection simulator and log auditor** - a canned
   brute-force scenario shows the full cycle from raw events to a fired
   detection, and the `audit` command validates a real log sample against
   every rule's required fields before you trust the rule in production.

## Install

```bash
cd DetectionAuditTool
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -e .   # installs the `dat` command
```

## Usage

Browse the catalogue:

```bash
dat rules list
dat rules list --platform windows
dat rules show WIN-1001
```

Look up a rule by Event ID - the core "I got paged on Event ID 4625, what do
I do" workflow:

```bash
dat lookup 4625
```

```
Event ID 4625 -> 2 rule(s)

[WIN-1001] Brute Force Logon Followed by Success  (level: critical, type: sequence)
  MITRE ATT&CK: T1110, T1110.001
  Event IDs: 4625, 4624
  ...
  Required log fields:
    - TargetUserName
    - TargetSid
    - IpAddress
    - LogonType
    - WorkstationName
  How to enable this audit data:
    gpo_path: Computer Configuration > ... > Audit Logon (Success and Failure)
    command: auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

Keyword / MITRE search:

```bash
dat search T1110
dat search "brute force"
```

Export a searchable, static, offline HTML catalogue (no server needed - open
directly in a browser):

```bash
dat export-html --out catalogue.html
open catalogue.html
```

Run the canned attack-to-detection simulation (password spray against
`jsmith` that finally succeeds, and the sequence rule that catches it):

```bash
dat simulate brute-force
```

Run the whole rule set against a real/sample log file:

```bash
dat run --logs sample_logs/windows_security_sample.json
```

Audit a log sample - for every rule, is the data actually there to make it
fire reliably (`READY` / `DEGRADED` / `NOT_READY` / `NO_DATA`), field by
field:

```bash
dat audit --logs sample_logs/windows_security_sample.json
```

```
[WIN-1001] Brute Force Logon Followed by Success: DEGRADED  (8 in-scope events)
    OK TargetUserName: 100.0% populated (8/8)
    !! TargetSid: 50.0% populated (4/8)
    OK IpAddress: 100.0% populated (8/8)
    OK LogonType: 100.0% populated (8/8)
    !! WorkstationName: 50.0% populated (4/8)
```

## Rule catalogue layout

```
rules/
  windows/    brute force, RDP spraying, privileged group changes, pass-the-hash
  linux/      SSH brute force, suspicious sudo usage
  cloud_aws/  console login brute force, root account usage
```

Each rule is a YAML file with:

- `detection_type`: `selection` (single match), `threshold` (count within a
  time window, grouped by a field - e.g. 5+ failed logons from one IP), or
  `sequence` (an ordered chain of steps within a window - e.g. N failures
  then a success)
- `mitre_attack`: ATT&CK technique IDs
- `required_fields`: the log fields the rule needs populated to be reliable
- `audit_policy`: how to turn on the Windows audit subcategory / Linux log
  config / CloudTrail setting that produces those fields

## Extending the catalogue

Add a new `.yml` file under `rules/<platform>/`. See any existing rule for
the schema; `load_rules()` validates required fields and rejects duplicate
IDs at load time. Run `pytest` after adding rules to make sure they parse and
the engine can evaluate them.

## Tests

```bash
pytest
```

## Roadmap ideas

- More platforms: macOS unified log, Okta, Azure AD sign-in logs, EDR
  telemetry (Sysmon/CrowdStrike/Defender)
- A `dat convert` command to import upstream public Sigma rules and map them
  into this schema
- A thin web dashboard (FastAPI) on top of the same engine for a live demo
  instead of the static HTML export
