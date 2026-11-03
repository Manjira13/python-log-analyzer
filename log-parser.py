
"""Parse timestamped SSH authentication messages."""

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import ipaddress
import re


@dataclass(frozen=True)
class AuthEvent:
    timestamp: datetime
    event_type: str
    ip_address: str


TIMESTAMP_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]"
    r"\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+"
)

IP_RE = re.compile(
    r"\bfrom\s+(?P<ip>"
    r"(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+)\b"
)


def _parse_timestamp(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    return datetime.fromisoformat(normalized)


def parse_log_lines(lines):
    events = []
    skipped = 0

    for line in lines:
        line = line.strip()

        if not line:
            continue

        timestamp_match = TIMESTAMP_RE.match(line)

        if not timestamp_match:
            skipped += 1
            continue

        message = line[timestamp_match.end():]
        lowered = message.lower()

        if "failed password" in lowered:
            event_type = "failed"

        elif "accepted password" in lowered:
            event_type = "success"

        else:
            skipped += 1
            continue

        ip_match = IP_RE.search(message)

        if not ip_match:
            skipped += 1
            continue

        ip_value = ip_match.group("ip")

        try:
            normalized_ip = str(
                ipaddress.ip_address(ip_value)
            )

            timestamp = _parse_timestamp(
                timestamp_match.group("timestamp")
            )

        except ValueError:
            skipped += 1
            continue

        events.append(
            AuthEvent(
                timestamp,
                event_type,
                normalized_ip
            )
        )

    return events, skipped


def parse_log_file(path):
    with Path(path).open(
        "r",
        encoding="utf-8",
        errors="replace"
    ) as log_file:

        return parse_log_lines(log_file)
