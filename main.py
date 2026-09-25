import argparse
import json
from pathlib import Path

from investigation.analyzer import load_events, investigate
from investigation.report import build_report


def main():
    parser = argparse.ArgumentParser(description="Synthetic SOC incident investigation lab")
    parser.add_argument("logfile", help="JSONL telemetry file")
    parser.add_argument("--report", help="Write Markdown investigation report")
    parser.add_argument("--json", action="store_true", help="Print machine-readable case output")
    args = parser.parse_args()

    events = load_events(args.logfile)
    case = investigate(events)

    if args.json:
        print(json.dumps(case, indent=2))
    else:
        print(f"Case severity: {case['severity'].upper()} | Confidence: {case['confidence'].upper()}")
        print(f"Events analyzed: {case['summary']['events_analyzed']}")
        print(f"Timeline entries: {len(case['timeline'])}")
        print(f"ATT&CK techniques: {', '.join(x['id'] for x in case['mitre'])}")
        print("\nKey findings:")
        for finding in case["findings"]:
            print(f"- {finding}")

    if args.report:
        Path(args.report).write_text(build_report(case), encoding="utf-8")
        print(f"\nReport written to {args.report}")


if __name__ == "__main__":
    main()
