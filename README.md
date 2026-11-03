
# Python Log Analyzer & Brute-Force Detector

## Project Overview

Python Log Analyzer & Brute-Force Detector is a Python-based security log analysis tool designed to identify suspicious authentication activity in SSH logs.

The application parses authentication logs, extracts failed and successful login attempts, groups failed attempts by source IP address, and detects potential brute-force activity using a configurable sliding time window.

It generates structured CSV reports containing suspicious IP addresses and their associated authentication activity.

The project demonstrates practical Python programming, data structures, algorithmic problem-solving, file handling, and automated testing.

## Objectives

- Parse SSH authentication logs using Python.
- Extract timestamps, source IP addresses, and authentication status.
- Count failed login attempts using hash-map-based aggregation.
- Detect repeated failed logins using a sliding-window algorithm.
- Sort suspicious IP addresses based on detected activity.
- Generate CSV reports for analysis.
- Validate functionality through automated unit tests using pytest.

## Features

- SSH authentication log parsing.
- Failed and successful login identification.
- IP-based failed login aggregation.
- Configurable brute-force detection threshold.
- Sliding-window detection algorithm.
- Timestamp-based event analysis.
- CSV report generation.
- Automated unit testing.

## Technologies Used

| Technology | Purpose |
|---|---|
| Python 3.10+ | Core application |
| Collections | Hash maps and sliding window |
| Datetime | Timestamp processing |
| Regular Expressions | Log parsing |
| CSV | Report generation |
| Pytest | Unit testing |
| Git & GitHub | Version control |

## Detection Logic

The application uses the following workflow:

1. Read SSH authentication logs.
2. Extract relevant authentication events.
3. Group failed login attempts by source IP address.
4. Sort events chronologically.
5. Apply a sliding-window algorithm to identify repeated failures.
6. Flag IP addresses meeting the configured threshold.
7. Generate a CSV report containing detection results.

## Detection Configuration

The detection threshold and time window can be customized.

Example:

- Failed login threshold: 5 attempts
- Time window: 10 minutes

An IP address generating five or more failed login attempts within the configured time window is flagged for investigation.

## Project Structure

```text
python-log-analyzer/
├── README.md
├── main.py
├── log_parser.py
├── detector.py
├── report_generator.py
├── requirements.txt
├── sample_logs/
├── reports/
└── tests/
```

## Installation

Clone the repository:

```bash
git clone https://github.com/Manjira13/python-log-analyzer.git
cd python-log-analyzer
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate the environment on Windows:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run the analyzer:

```bash
python main.py --input sample_logs/auth.log --output reports/analysis.csv --threshold 5 --window-minutes 10
```

Run unit tests:

```bash
python -m pytest -v
```

## Sample Output

The analyzer displays:

- Total parsed authentication events.
- Failed login attempts.
- Successful login attempts.
- Skipped log entries.
- Number of suspicious IP addresses.
- Detection details.

The generated CSV report includes:

- Source IP address.
- Failed attempts within the detected window.
- Window start and end timestamps.
- Detection threshold.
- Configured time window.

## Testing

Unit tests validate:

- Authentication log parsing.
- Invalid log entry handling.
- IP address validation.
- Failed login aggregation.
- Sliding-window detection.
- Threshold validation.
- Successful login exclusion.

## Limitations

- Currently supports timestamped OpenSSH-style authentication logs.
- Does not directly monitor live network traffic.
- Does not automatically block suspicious IP addresses.
- Uses sample authentication logs for demonstration.
- Requires valid timestamps and source IP addresses.

## Future Improvements

- Windows authentication event log support.
- HTML-based detection reports.
- JSON report generation.
- Configurable trusted IP allowlists.
- Detection of successful logins following repeated failures.
- Additional log formats and parsing rules.

## Disclaimer

This project is developed for educational and defensive security purposes. The detection results identify potentially suspicious authentication activity and should be investigated before drawing conclusions.

## Author

Manjira Das

GitHub: https://github.com/Manjira13
