# SOC Incident Investigation Lab

A defensive Blue Team portfolio project that walks through an L1/L2-style SOC investigation using **synthetic telemetry only**. The lab correlates authentication, endpoint, process, account, and network events into an investigation timeline, assigns evidence-based findings, maps observed behavior to MITRE ATT&CK, and generates a structured incident handoff report.

> No real systems, credentials, malware, or external targets are used. All IPs, domains, users, and events are fictional or documentation-only values.

## Scenario

A workstation produces a sequence of suspicious security events: repeated authentication failures, a successful login from the same source, suspicious PowerShell telemetry, creation of a new account, a privilege change, and repeated outbound connections. The analyst must correlate the events rather than treat each alert in isolation.

## What this demonstrates

- SOC alert triage and investigation workflow
- Event correlation and timeline reconstruction
- Authentication, endpoint, process, and network log analysis
- Evidence vs. hypothesis separation
- IOC extraction and case scoping
- MITRE ATT&CK mapping
- Incident severity and confidence assessment
- Containment / eradication / recovery recommendations
- Analyst handoff and incident documentation
- Python automation and unit testing

## Investigation workflow

```text
Initial Alert
    |
    v
Validate & Scope
    |
    v
Correlate Telemetry
    |
    v
Build Timeline
    |
    v
Map ATT&CK + Extract IOCs
    |
    v
Assess Severity / Confidence
    |
    v
Recommend Response Actions
    |
    v
Generate SOC Handoff Report
```

## Quick start

Python 3.10+ is enough; no third-party packages are required.

```bash
python main.py data/case_events.jsonl
python main.py data/case_events.jsonl --report examples/investigation_report.md
python main.py data/case_events.jsonl --json
python -m unittest discover -s tests -v
```

## Expected result

The sample case produces a chronological investigation showing a plausible sequence from failed authentication through account/privilege changes and outbound activity. The tool labels conclusions carefully: correlated events increase confidence, but the report does **not** claim attribution or compromise beyond the evidence available.

## Project structure

```text
SOC-Incident-Investigation-Lab/
├── main.py
├── investigation/
│   ├── __init__.py
│   ├── analyzer.py
│   └── report.py
├── data/
│   └── case_events.jsonl
├── examples/
│   └── investigation_report.md
└── tests/
    └── test_investigation.py
```

## Detection / ATT&CK coverage

| Observed behavior | ATT&CK |
|---|---|
| Repeated authentication failures | T1110 — Brute Force |
| PowerShell execution | T1059.001 — PowerShell |
| Account creation | T1136 — Create Account |
| Privileged role assignment | T1098 — Account Manipulation |
| Repeated web-protocol outbound activity | T1071.001 — Web Protocols |

## Analyst mindset

This project intentionally separates:

- **Evidence:** what the telemetry directly records.
- **Assessment:** what the correlated evidence reasonably suggests.
- **Unknowns:** what cannot be established from the available logs.
- **Actions:** what a defender should validate or contain next.

That distinction is important in real SOC work because an alert is an investigation lead, not proof by itself.

## Author

Omar Al Tamimi — Cybersecurity student focused on SOC operations, threat detection, incident response, Linux, networking, and Python automation.
