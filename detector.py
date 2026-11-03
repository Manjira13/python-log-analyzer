
"""Sliding-window detection of repeated failed SSH logins."""

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta

from log_parser import AuthEvent


@dataclass(frozen=True)
class Detection:
    ip_address: str
    failed_attempts_in_window: int
    window_start: datetime
    window_end: datetime


def detect_brute_force(
    events,
    threshold=5,
    window_minutes=10
):
    """
    Detect IP addresses with repeated failed logins
    within a configurable time window.
    """

    if threshold < 1:
        raise ValueError("threshold must be at least 1")

    if window_minutes < 1:
        raise ValueError("window_minutes must be at least 1")

    failures_by_ip = defaultdict(list)

    # Group failed login timestamps by source IP.
    for event in events:
        if event.event_type == "failed":
            failures_by_ip[event.ip_address].append(
                event.timestamp
            )

    window_size = timedelta(minutes=window_minutes)

    detections = []

    for ip_address, timestamps in failures_by_ip.items():

        # Sort events chronologically.
        timestamps.sort()

        # Maintain the active sliding window.
        active_window = deque()

        best = None

        for current_time in timestamps:

            active_window.append(current_time)

            # Remove events outside the configured window.
            while (
                active_window
                and current_time - active_window[0] > window_size
            ):
                active_window.popleft()

            # Check whether the threshold is reached.
            if len(active_window) >= threshold:

                candidate = Detection(
                    ip_address=ip_address,
                    failed_attempts_in_window=len(active_window),
                    window_start=active_window[0],
                    window_end=current_time
                )

                if (
                    best is None
                    or candidate.failed_attempts_in_window
                    > best.failed_attempts_in_window
                    or (
                        candidate.failed_attempts_in_window
                        == best.failed_attempts_in_window
                        and candidate.window_end > best.window_end
                    )
                ):
                    best = candidate

        if best is not None:
            detections.append(best)

    # Rank IP addresses by failed login count.
    return sorted(
        detections,
        key=lambda item: (
            -item.failed_attempts_in_window,
            item.ip_address
        )
    )
