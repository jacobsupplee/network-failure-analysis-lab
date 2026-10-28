from src.analyzers.dns import analyze_dns

def test_dns_failure():
    result = analyze_dns({
        "hostname": "example.com",
        "dns_server": "192.168.1.10",
        "resolution_result": "timeout",
    })

    assert result["status"] == "investigate"
    assert result["severity"] == "Needs investigation"

def test_dns_success():
    result = analyze_dns({
        "hostname": "example.com",
        "dns_server": "192.168.1.10",
        "resolution_result": "success",
    })

    assert result["status"] == "resolved"
    assert result["severity"] == "Informational"

def test_dns_missing_evidence():
    result = analyze_dns({"hostname": "example.com"})

    assert result["status"] == "inconclusive"

def test_dns_unknown_result():
    result = analyze_dns({
        "hostname": "example.com",
        "resolution_result": "unknown",
    })

    assert result["status"] == "inconclusive"

def test_dns_unavailable_is_inconclusive():
    result = analyze_dns(
        {
            "hostname": "example.com",
            "dns_server": None,
            "resolution_result": "unavailable",
        }
    )

    assert result["status"] == "inconclusive"
    assert "could not execute" in result["finding"]

