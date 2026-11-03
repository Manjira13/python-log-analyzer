
from datetime import datetime, timedelta, timezone

import pytest

from detector import detect_brute_force
from log_parser import AuthEvent


def make_event(
    minutes,
    ip="203.0.113.10",
    kind="failed"
):

    timestamp = (
        datetime(2026, 11, 3, 10, 0, tzinfo=timezone.utc)
        + timedelta(minutes=minutes)
    )

    return AuthEvent(
        timestamp,
        kind,
        ip
    )


def test_detects_threshold_within_window():

    events = [
        make_event(0),
        make_event(2),
        make_event(4),
        make_event(6),
        make_event(8)
    ]

    findings = detect_brute_force(
        events,
        threshold=5,
        window_minutes=10
    )

    assert len(findings) == 1

    assert findings[0].ip_address == "203.0.113.10"

    assert findings[0].failed_attempts_in_window == 5


def test_does_not_detect_failures_outside_window():

    events = [
        make_event(0),
        make_event(20),
        make_event(40),
        make_event(60)
    ]

    findings = detect_brute_force(
        events,
        threshold=4,
        window_minutes=10
    )

    assert findings == []


def test_successful_logins_are_not_counted():

    events = [
        make_event(i, kind="success")
        for i in range(5)
    ]

    findings = detect_brute_force(
        events,
        threshold=5,
        window_minutes=10
    )

    assert findings == []


def test_separate_ips_are_grouped_separately():

    events = [
        make_event(0, "203.0.113.10"),
        make_event(1, "203.0.113.10"),
        make_event(2, "203.0.113.20"),
        make_event(3, "203.0.113.20")
    ]

    findings = detect_brute_force(
        events,
        threshold=3,
        window_minutes=10
    )

    assert findings == []


def test_invalid_threshold_raises_error():

    with pytest.raises(ValueError):

        detect_brute_force(
            [],
            threshold=0,
            window_minutes=10
        )
