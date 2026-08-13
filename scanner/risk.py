def assess_risk(port, protocol):
    if protocol == "HTTP":
        return {
            "risk": "INFORMATIONAL",
            "finding": "Web service detected",
            "recommendation": (
                "Review whether this service needs to be exposed "
                "and ensure it is properly secured."
            )
        }

    if port in [21, 22, 23]:
        return {
            "risk": "HIGH",
            "finding": "Potentially insecure legacy service",
            "recommendation": (
                "Verify whether the service is required and "
                "consider using a more secure alternative."
            )
        }

    return {
        "risk": "LOW",
        "finding": "Open service detected",
        "recommendation": (
            "Identify the service and verify that the exposure "
            "is intentional."
        )
    }