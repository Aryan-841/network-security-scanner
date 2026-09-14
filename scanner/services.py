import socket


KNOWN_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
}


def detect_service(target, port):
    service_name = KNOWN_SERVICES.get(port, "Unknown")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        sock.connect((target, port))

        sock.sendall(
            b"HEAD / HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Connection: close\r\n\r\n"
        )

        response = sock.recv(1024).decode(errors="ignore")
        sock.close()

        if response:
            first_line = response.splitlines()[0]

            if first_line.startswith("HTTP/"):
                return {
                    "protocol": "HTTP",
                    "service": (
                        service_name
                        if service_name != "Unknown"
                        else "HTTP Web Service"
                    ),
                    "response": first_line,
                }

            return {
                "protocol": "Unknown",
                "service": service_name,
                "response": first_line,
            }

        return {
            "protocol": "Unknown",
            "service": service_name,
            "response": "No response",
        }

    except (ConnectionRefusedError, TimeoutError, OSError):
        return {
            "protocol": "Unknown",
            "service": service_name,
            "response": "Unable to identify service",
        }
