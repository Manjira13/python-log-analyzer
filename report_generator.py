
"""Generate CSV reports from detection findings."""

import csv
from pathlib import Path

from detector import Detection


def write_csv_report(
    findings,
    output_path,
    threshold,
    window_minutes
):

    output = Path(output_path)

    # Create the output directory if necessary.
    output.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    fieldnames = [
        "ip_address",
        "failed_attempts_in_window",
        "window_start",
        "window_end",
        "threshold",
        "window_minutes"
    ]

    with output.open(
        "w",
        newline="",
        encoding="utf-8"
    ) as csv_file:

        writer = csv.DictWriter(
            csv_file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for finding in findings:

            writer.writerow({
                "ip_address": finding.ip_address,
                "failed_attempts_in_window":
                    finding.failed_attempts_in_window,
                "window_start":
                    finding.window_start.isoformat(),
                "window_end":
                    finding.window_end.isoformat(),
                "threshold": threshold,
                "window_minutes": window_minutes
            })

    return output
