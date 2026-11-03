
"""Command-line entry point for the SSH log analyzer."""

import argparse
from pathlib import Path

from detector import detect_brute_force
from log_parser import parse_log_file
from report_generator import write_csv_report


def build_parser():

    parser = argparse.ArgumentParser(
        description=(
            "Analyze SSH authentication logs "
            "for repeated failed logins."
        )
    )

    parser.add_argument(
        "--input",
        required=True,
        help="Path to the SSH authentication log."
    )

    parser.add_argument(
        "--output",
        default="reports/analysis.csv",
        help="Path for the CSV report."
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Failed attempts required to trigger detection."
    )

    parser.add_argument(
        "--window-minutes",
        type=int,
        default=10,
        help="Sliding-window duration in minutes."
    )

    return parser


def main():

    args = build_parser().parse_args()

    if args.threshold < 1:
        raise SystemExit("Threshold must be at least 1.")

    if args.window_minutes < 1:
        raise SystemExit("Window must be at least 1 minute.")

    input_path = Path(args.input)

    if not input_path.is_file():
        raise SystemExit(
            f"Input file not found: {input_path}"
        )

    # Parse authentication logs.
    events, skipped = parse_log_file(input_path)

    # Detect suspicious authentication activity.
    findings = detect_brute_force(
        events,
        threshold=args.threshold,
        window_minutes=args.window_minutes
    )

    # Generate CSV report.
    write_csv_report(
        findings,
        output_path=args.output,
        threshold=args.threshold,
        window_minutes=args.window_minutes
    )

    failed_count = sum(
        event.event_type == "failed"
        for event in events
    )

    success_count = sum(
        event.event_type == "success"
        for event in events
    )

    print(f"Parsed events: {len(events)}")
    print(f"Failed logins: {failed_count}")
    print(f"Successful logins: {success_count}")
    print(f"Skipped lines: {skipped}")
    print(f"Suspicious IPs: {len(findings)}")
    print(f"CSV report: {args.output}")

    if findings:

        print("\nPotential brute-force activity:")

        for finding in findings:

            print(
                f"- {finding.ip_address}: "
                f"{finding.failed_attempts_in_window} failures "
                f"from {finding.window_start.isoformat()} "
                f"to {finding.window_end.isoformat()}"
            )

    else:
        print(
            "\nNo IP addresses met the detection threshold."
        )


if __name__ == "__main__":
    main()
