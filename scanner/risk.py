def assess(port, protocol):
    protocol = protocol.upper()

    # Preserve original scanner behavior for HTTP
    if protocol == "HTTP":
        return {
            "risk": "INFORMATIONAL",
            "finding": "Web service detected",
            "recommendation": (
                "Review whether this service needs to be exposed "
                "and ensure it is properly secured."
            ),
        }

    high_risk_ports = {
        21: ("FTP", "Unencrypted file transfer service"),
        22: ("SSH", "Remote administration service detected"),
        23: ("Telnet", "Insecure remote access service"),
        3306: ("MySQL", "Database service exposed on the network"),
        3389: ("RDP", "Remote desktop service exposed"),
        5432: ("PostgreSQL", "Database service exposed on the network"),
        6379: ("Redis", "In-memory database service exposed"),
        27017: ("MongoDB", "Database service exposed on the network"),
    }

    medium_risk_ports = {
        25: ("SMTP", "Mail transfer service detected"),
        53: ("DNS", "DNS service detected"),
        8080: ("HTTP-alt", "Alternative HTTP service detected"),
    }

    low_risk_ports = {
        443: ("HTTPS", "Encrypted web service detected"),
    }

    if port in high_risk_ports:
        service, finding = high_risk_ports[port]
        return {
            "risk": "HIGH",
            "finding": finding,
            "recommendation": (
                f"Review the {service} service, restrict network exposure "
                "where possible, and verify authentication and access controls."
            ),
        }

    if port in medium_risk_ports:
        service, finding = medium_risk_ports[port]
        return {
            "risk": "MEDIUM",
            "finding": finding,
            "recommendation": (
                f"Review the {service} service and verify that it is required, "
                "properly configured, and appropriately restricted."
            ),
        }

    if port in low_risk_ports:
        service, finding = low_risk_ports[port]
        return {
            "risk": "LOW",
            "finding": finding,
            "recommendation": (
                f"{service} is generally safer when properly configured. "
                "Verify encryption, authentication, and intended exposure."
            ),
        }

    return {
        "risk": "LOW",
        "finding": "Open service detected",
        "recommendation": (
            "Identify the service and verify that the exposure is intentional."
        ),
    }