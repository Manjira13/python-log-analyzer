
from log_parser import parse_log_lines


def test_parse_failed_and_successful_events():

    lines = [
        "2026-11-03T10:00:00Z sshd[1]: Failed password for admin from 203.0.113.10 port 22 ssh2",

        "2026-11-03T10:01:00Z sshd[2]: Accepted password for user from 198.51.100.5 port 22 ssh2"
    ]

    events, skipped = parse_log_lines(lines)

    assert len(events) == 2

    assert events[0].event_type == "failed"
    assert events[0].ip_address == "203.0.113.10"

    assert events[1].event_type == "success"

    assert skipped == 0


def test_invalid_line_is_skipped():

    events, skipped = parse_log_lines([
        "This is not a valid authentication log"
    ])

    assert events == []
    assert skipped == 1


def test_invalid_ip_is_skipped():

    lines = [
        "2026-11-03T10:00:00Z sshd[1]: Failed password for admin from 999.1.1.1 port 22 ssh2"
    ]

    events, skipped = parse_log_lines(lines)

    assert events == []
    assert skipped == 1
