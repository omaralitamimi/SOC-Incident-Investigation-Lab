# SOC Incident Investigation Report

## Case Summary
- Severity: **CRITICAL**
- Confidence: **HIGH**
- Risk score: 100/100
- Events analyzed: 13
- Host in scope: ws-17
- Primary user: omar.lab

## Evidence-Based Findings
- 5 failed logins targeted omar.lab from 203.0.113.77.
- A successful login for omar.lab followed failures from the same source.
- Encoded PowerShell execution was recorded on the investigated host.
- A new account (svc-lab) was created during the investigation window.
- Account svc-lab received elevated privileges.
- 4 repeated outbound connections from ws-17 to 198.51.100.88 were recorded.

## MITRE ATT&CK Mapping
- T1059.001 — PowerShell
- T1071.001 — Web Protocols
- T1098 — Account Manipulation
- T1110 — Brute Force
- T1136 — Create Account

## Indicators Observed
- IP addresses: 198.51.100.88, 203.0.113.77
- Domain: telemetry-lab.example
- SHA-256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb

## Analyst Assessment
The synthetic telemetry contains several correlated behaviors that justify escalation and validation. The evidence supports a high-confidence security investigation, but it does not establish human attribution or authorization status without additional context.

## Recommended Response
Validate the account and host owner, preserve telemetry, isolate the endpoint if activity is unauthorized, review the new privileged account, validate indicators before blocking, hunt for related activity on other assets, and document all containment decisions.
