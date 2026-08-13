from scanner.risk import assess_risk
from scanner.main import validate_port_range

def test_http_service_is_informational():
    result = assess_risk(3000, "HTTP")

    assert result["risk"] == "INFORMATIONAL"


def test_https_service_is_low_risk():
    result = assess_risk(443, "HTTPS")

    assert result["risk"] == "LOW"


def test_ssh_service_is_high_risk():
    result = assess_risk(22, "SSH")

    assert result["risk"] == "HIGH"


def test_valid_port_range():
    assert validate_port_range(1, 100) is True


def test_invalid_reversed_port_range():
    assert validate_port_range(3000, 100) is False