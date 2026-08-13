import json
from datetime import datetime


def save_report(target, results):
    report = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "open_ports": results
    }

    filename = (
        f"reports/scan_"
        f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )

    with open(filename, "w") as file:
        json.dump(report, file, indent=4)

    print(f"\nReport saved to: {filename}")