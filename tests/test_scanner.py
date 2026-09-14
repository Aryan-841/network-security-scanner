from scanner.risk import assess
from scanner.main import validate_port_range, validate_target

def test_http_service_is_informational():
    result = assess(3000, "HTTP")

    assert result["risk"] == "INFORMATIONAL"


def test_https_service_is_low_risk():
    result = assess(443, "HTTPS")

    assert result["risk"] == "LOW"


def test_ssh_service_is_high_risk():
    result = assess(22, "SSH")

    assert result["risk"] == "HIGH"


def test_valid_port_range():
    assert validate_port_range(1, 100) is True

def test_invalid_reversed_port_range():
    assert validate_port_range(3000, 100) is False

def test_valid_target():
    assert validate_target("127.0.0.1") is True

def test_invalid_target():
    assert validate_target("999.999.999.999") is False