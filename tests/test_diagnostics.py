
from src.diagnostics import analyze_dhcp


def test_apipa_address():
    # APIPA address suggests the workstation didn't get its normal DHCP configuration.
    result = analyze_dhcp({"ip_address": "169.254.12.34"})

    assert result["status"] == "investigate"
    assert "APIPA" in result["finding"]


def test_normal_address():
    # Having a normal-range IP address doesn't guarantee network connectivity.
    result = analyze_dhcp({"ip_address": "192.168.1.25"})

    assert result["status"] == "no_apipa"
    assert "does not confirm" in result["finding"]


def test_missing_address():
    # We can't draw a conclusion if the workstation's IP address is unknown.
    result = analyze_dhcp({})

    assert result["status"] == "inconclusive"


def test_invalid_address():
    # Invalid input should be handled without crashing.
    result = analyze_dhcp({"ip_address": "not-an-ip"})

    assert result["status"] == "inconclusive"

def test_apipa_with_missing_network_settings():
    result = analyze_dhcp({
        "ip_address": "169.254.12.34",
        "default_gateway": None,
        "dhcp_server": None,
    })

    assert result["status"] == "investigate"
    assert "APIPA" in result["finding"]
    assert "default gateway" in result["finding"]
    assert "DHCP server" in result["finding"]


def test_apipa_with_reported_network_settings():
    result = analyze_dhcp({
        "ip_address": "169.254.12.34",
        "default_gateway": "192.168.1.1",
        "dhcp_server": "192.168.1.10",
    })

    assert result["status"] == "investigate"
    assert "Verify" in result["finding"]
