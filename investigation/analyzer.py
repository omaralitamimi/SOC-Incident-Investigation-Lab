from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
import json
import re
from pathlib import Path

ATTACK = {
    "auth_failure": {"id": "T1110", "name": "Brute Force"},
    "suspicious_powershell": {"id": "T1059.001", "name": "PowerShell"},
    "account_created": {"id": "T1136", "name": "Create Account"},
    "privilege_change": {"id": "T1098", "name": "Account Manipulation"},
    "repeated_outbound": {"id": "T1071.001", "name": "Web Protocols"},
}

HASH_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")


def load_events(path: str | Path) -> list[dict]:
    events = []
    with open(path, encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_number}: {exc}") from exc
            if "timestamp" not in event or "event_type" not in event:
                raise ValueError(f"Line {line_number} is missing timestamp/event_type")
            events.append(event)
    return sorted(events, key=lambda item: item["timestamp"])


def _extract_iocs(events: list[dict]) -> dict:
    ips, domains, hashes = set(), set(), set()
    for event in events:
        for key in ("src_ip", "dst_ip"):
            if event.get(key):
                ips.add(event[key])
        if event.get("domain"):
            domains.add(event["domain"])
        for value in event.values():
            if isinstance(value, str):
                hashes.update(x.lower() for x in HASH_RE.findall(value))
    return {"ips": sorted(ips), "domains": sorted(domains), "hashes": sorted(hashes)}


def _timeline(events: list[dict]) -> list[dict]:
    output = []
    for event in events:
        kind = event["event_type"]
        detail = {
            "auth_failure": f"Failed login for {event.get('user', 'unknown')} from {event.get('src_ip', 'unknown')}",
            "auth_success": f"Successful login for {event.get('user', 'unknown')} from {event.get('src_ip', 'unknown')}",
            "process_start": f"Process observed on {event.get('host', 'unknown')}: {event.get('process', 'unknown')}",
            "account_created": f"Account created: {event.get('target_user', 'unknown')}",
            "privilege_change": f"Privilege changed for {event.get('target_user', 'unknown')} to {event.get('new_role', 'unknown')}",
            "network_connection": f"Outbound connection from {event.get('host', 'unknown')} to {event.get('dst_ip', 'unknown')}:{event.get('dst_port', 'unknown')}",
        }.get(kind, f"Observed {kind}")
        output.append({"timestamp": event["timestamp"], "event_type": kind, "detail": detail})
    return output


def investigate(events: list[dict]) -> dict:
    findings = []
    techniques = {}
    score = 0

    failures = defaultdict(list)
    successes = []
    outbound = defaultdict(list)

    for event in events:
        kind = event["event_type"]
        if kind == "auth_failure":
            failures[(event.get("user"), event.get("src_ip"))].append(event)
        elif kind == "auth_success":
            successes.append(event)
        elif kind == "process_start":
            command = event.get("command_line", "").lower()
            process = event.get("process", "").lower()
            if "powershell" in process and any(token in command for token in ("-enc", "-encodedcommand", "frombase64string")):
                findings.append("Encoded PowerShell execution was recorded on the investigated host.")
                techniques["suspicious_powershell"] = ATTACK["suspicious_powershell"]
                score += 25
        elif kind == "account_created":
            findings.append(f"A new account ({event.get('target_user', 'unknown')}) was created during the investigation window.")
            techniques["account_created"] = ATTACK["account_created"]
            score += 15
        elif kind == "privilege_change" and str(event.get("new_role", "")).lower() in {"administrator", "admin", "root"}:
            findings.append(f"Account {event.get('target_user', 'unknown')} received elevated privileges.")
            techniques["privilege_change"] = ATTACK["privilege_change"]
            score += 20
        elif kind == "network_connection" and event.get("direction") == "outbound":
            outbound[(event.get("host"), event.get("dst_ip"))].append(event)

    for (user, src), group in failures.items():
        if len(group) >= 5:
            findings.append(f"{len(group)} failed logins targeted {user} from {src}.")
            techniques["auth_failure"] = ATTACK["auth_failure"]
            score += 15
            if any(s.get("user") == user and s.get("src_ip") == src for s in successes):
                findings.append(f"A successful login for {user} followed failures from the same source {src}.")
                score += 15

    for (host, dst), group in outbound.items():
        if len(group) >= 4:
            findings.append(f"{len(group)} repeated outbound connections from {host} to {dst} were recorded.")
            techniques["repeated_outbound"] = ATTACK["repeated_outbound"]
            score += 10

    score = min(score, 100)
    severity = "critical" if score >= 85 else "high" if score >= 60 else "medium" if score >= 30 else "low"
    confidence = "high" if len(techniques) >= 4 else "medium" if len(techniques) >= 2 else "low"

    actions = [
        "Validate the affected user and asset with the system owner.",
        "Preserve relevant authentication, endpoint, and network telemetry.",
        "If the activity is unauthorized, isolate the affected endpoint using approved response procedures.",
        "Reset or disable affected credentials if compromise is confirmed or strongly suspected.",
        "Review newly created accounts and privilege changes against authorized change records.",
        "Block confirmed malicious indicators using approved controls after validation.",
        "Hunt for the same indicators and behaviors across other assets.",
        "Document containment decisions and maintain an analyst handoff trail.",
    ]

    return {
        "summary": {
            "events_analyzed": len(events),
            "event_types": dict(Counter(e["event_type"] for e in events)),
            "hosts": sorted({e.get("host") for e in events if e.get("host")}),
            "users": sorted({e.get("user") for e in events if e.get("user")}),
        },
        "severity": severity,
        "confidence": confidence,
        "risk_score": score,
        "findings": findings,
        "timeline": _timeline(events),
        "iocs": _extract_iocs(events),
        "mitre": sorted(techniques.values(), key=lambda x: x["id"]),
        "recommended_actions": actions,
        "unknowns": [
            "Whether the observed activity was authorized administrative work.",
            "Whether the source identity can be attributed to a specific person.",
            "Whether additional affected hosts exist outside the supplied telemetry.",
        ],
    }
