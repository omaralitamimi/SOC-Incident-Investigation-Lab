from datetime import datetime, timezone


def build_report(case: dict) -> str:
    lines = [
        "# SOC Incident Investigation Report",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
        "## Case Summary",
        f"- Severity: **{case['severity'].upper()}**",
        f"- Confidence: **{case['confidence'].upper()}**",
        f"- Risk score: {case['risk_score']}/100",
        f"- Events analyzed: {case['summary']['events_analyzed']}",
        f"- Hosts in scope: {', '.join(case['summary']['hosts']) or 'None'}",
        f"- Users in scope: {', '.join(case['summary']['users']) or 'None'}",
        "",
        "## Evidence-Based Findings",
    ]
    lines += [f"- {finding}" for finding in case["findings"]] or ["- No significant correlated findings."]
    lines += ["", "## Investigation Timeline"]
    for item in case["timeline"]:
        lines.append(f"- **{item['timestamp']}** — {item['detail']}")

    lines += ["", "## MITRE ATT&CK Mapping"]
    for technique in case["mitre"]:
        lines.append(f"- {technique['id']} — {technique['name']}")

    lines += [
        "",
        "## Indicators Observed",
        f"- IP addresses: {', '.join(case['iocs']['ips']) or 'None'}",
        f"- Domains: {', '.join(case['iocs']['domains']) or 'None'}",
        f"- SHA-256 hashes: {', '.join(case['iocs']['hashes']) or 'None'}",
        "",
        "## Unknowns / Validation Gaps",
    ]
    lines += [f"- {item}" for item in case["unknowns"]]
    lines += ["", "## Recommended Response Actions"]
    lines += [f"- {action}" for action in case["recommended_actions"]]
    lines += [
        "",
        "## Analyst Assessment",
        "The supplied telemetry contains multiple correlated behaviors that justify escalation and validation. "
        "This report does not attribute the activity to a person or claim facts beyond the available evidence.",
        "",
    ]
    return "\n".join(lines)
