import socket
from concurrent.futures import ThreadPoolExecutor
from scanner.services import detect_service
from scanner.risk import assess
from scanner.reporting import save_report

def check_port(target, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)

    result = sock.connect_ex((target, port))

    sock.close()

    return port if result == 0 else None

def validate_port_range(start_port, end_port):
    if start_port < 1 or end_port > 65535:
        return False

    if start_port > end_port:
        return False

    return True


def main():
    target = input("Enter target IP address: ")

    while True:
        try:
            start_port = int(input("Enter starting port: "))
            end_port = int(input("Enter ending port: "))
            if not validate_port_range(start_port, end_port):
                print("Invalid port range. Ports must be between 1 and 65535, and starting port cannot be greater than ending port.")
                continue

            break

        except ValueError:
            print("Please enter valid numbers.")

    print(f"\nScanning {target} from port {start_port} to {end_port}...\n")

    ports = range(start_port, end_port + 1)

    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(
            lambda port: check_port(target, port),
            ports
        )

    open_ports = [port for port in results if port is not None]
    print(f"\nFound {len(open_ports)} open port(s).\n")
    report_results = []

    if open_ports:
        print("Open ports:\n")
        for port in open_ports:
            service = detect_service(target, port)
            assessment = assess(port, service["protocol"])
            report_results.append({
                "port": port,
                "status": "OPEN",
                "protocol": service["protocol"],
                "response": service["response"],
                "risk": assessment["risk"],
                "finding": assessment["finding"],
                "recommendation": assessment["recommendation"]
            })
            print(f"Port {port}")
            print(f"  Status: OPEN")
            print(f"  Protocol: {service['protocol']}")
            print(f"  Response: {service['response']}")
            print(f"  Risk: {assessment['risk']}")
            print(f"  Finding: {assessment['finding']}")
            print(f"  Recommendation: {assessment['recommendation']}\n")
                   
    else:
        print("No open ports found.")
    save_report(target, report_results)


if __name__ == "__main__":
    main()