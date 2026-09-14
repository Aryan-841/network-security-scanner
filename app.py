from flask import Flask, render_template, request, jsonify
import ipaddress
from concurrent.futures import ThreadPoolExecutor

from scanner.main import check_port, validate_port_range
from scanner.services import detect_service
from scanner.risk import assess
from scanner.reporting import save_report

app = Flask(__name__)


def run_scan(target, start_port, end_port):
    if not validate_port_range(start_port, end_port):
        raise ValueError("Invalid port range.")

    ports = range(start_port, end_port + 1)

    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(
            lambda port: check_port(target, port),
            ports
        )

    open_ports = [port for port in results if port is not None]
    report_results = []

    for port in open_ports:
        service = detect_service(target, port)
        assessment = assess(port, service["protocol"])

        report_results.append({
            "port": port,
            "status": "OPEN",
            "protocol": service["protocol"],
            "service": service["service"],
            "response": service["response"],
            "risk": assessment["risk"],
            "finding": assessment["finding"],
            "recommendation": assessment["recommendation"]
        })

    save_report(target, report_results)

    return report_results


@app.route("/", methods=["GET", "POST"])
def index():
    results = None
    error = None
    target = ""

    if request.method == "POST":
        target = request.form.get("target", "").strip()

        try:
            start_port = int(request.form.get("start_port"))
            end_port = int(request.form.get("end_port"))

            results = run_scan(
                target,
                start_port,
                end_port
            )

        except ValueError as e:
            error = str(e)

        except Exception as e:
            error = f"Scan failed: {e}"

    return render_template(
        "index.html",
        results=results,
        error=error,
        target=target
    )

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}

    target = str(data.get("target", "")).strip()

    if not target:
        return jsonify({
            "error": "Target IP address is required."
        }), 400

    try:
        ipaddress.ip_address(target)
    except ValueError:
        return jsonify({
            "error": "Invalid IP address. Enter a valid IPv4 or IPv6 address."
        }), 400

    try:
        start_port = int(data.get("start_port"))
        end_port = int(data.get("end_port"))
    except (TypeError, ValueError):
        return jsonify({
            "error": "Starting and ending ports must be valid numbers."
        }), 400

    if not validate_port_range(start_port, end_port):
        return jsonify({
            "error": "Invalid port range. Ports must be between 1 and 1000, and starting port cannot be greater than ending port."
        }), 400

    try:
        results = run_scan(
            target,
            start_port,
            end_port
        )

        return jsonify({
            "target": target,
            "results": results
        })

    except Exception as e:
        return jsonify({
            "error": f"Scan failed: {str(e)}"
        }), 500
if __name__ == "__main__":
    app.run(debug=True, port=5000)
