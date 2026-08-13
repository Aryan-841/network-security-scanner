import socket


def detect_service(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        sock.connect((target, port))
        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")

        response = sock.recv(1024).decode(errors="ignore")

        sock.close()

        if response:
            first_line = response.splitlines()[0]

            if first_line.startswith("HTTP/"):
                return {
                    "protocol": "HTTP",
                    "response": first_line
                }

            return {
                "protocol": "Unknown",
                "response": first_line
            }

        return {
            "protocol": "Unknown",
            "response": "No response"
        }

    except (ConnectionRefusedError, TimeoutError, OSError):
        return {
            "protocol": "Unknown",
            "response": "Unable to identify service"
        }