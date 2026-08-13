# Network Security Scanner

A Python-based network security scanner that identifies open TCP ports, detects basic services, evaluates security risk, and generates JSON scan reports.

## Features

- Scan a configurable TCP port range
- Detect open ports
- Identify basic network services
- Detect HTTP services
- Assign risk levels to detected services
- Provide security findings and recommendations
- Generate timestamped JSON reports
- Validate user input and port ranges
- Automated tests with pytest
- Concurrent port scanning using Python threads

## Project Structure

```text
network-security-scanner/
├── scanner/
│   ├── main.py
│   ├── services.py
│   ├── risk.py
│   ├── reporting.py
│   └── __init__.py
├── tests/
│   └── test_scanner.py
├── reports/
├── .gitignore
├── README.md
└── requirements.txt