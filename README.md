# Network Security Scanner

A Python-based network security scanner that identifies open TCP ports, detects basic network services, evaluates security risks, and generates structured JSON scan reports.

## Live Demo

https://network-security-scanner.onrender.com

## Features

- Configurable TCP port scanning
- Detects open ports
- Identifies basic network services
- Detects HTTP services
- Assigns risk levels to detected services
- Provides security findings and recommendations
- Generates timestamped JSON reports
- Validates user input and port ranges
- Concurrent port scanning using Python threads
- Automated testing with pytest
- Flask-based web interface
- Production deployment using Gunicorn

## 🛠️ Tech Stack

- Python
- Flask
- Gunicorn
- TCP Sockets
- ThreadPoolExecutor
- Pytest
- HTML/CSS
- JSON

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
├── templates/
│   └── index.html
├── app.py
├── Procfile
├── requirements.txt
├── .gitignore
└── README.md