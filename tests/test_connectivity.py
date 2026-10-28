from src.analyzers.connectivity import analyze_connectivity

def test_gateway_and_external_target_reachable():
    result = analyze_connectivity(
        {
            "default_gateway": "192.168.1.1",
            "gateway_reachable": True,
            "external_target": "1.1.1.1",
            "external_reachable": True,
        }
    )

    assert result["status"] == "connected"

def test_gateway_unreachable():
    result = analyze_connectivity(
        {
            "default_gateway": "192.168.1.1",
            "gateway_reachable": False,
            "external_target": "1.1.1.1",
            "external_reachable": False,
        }
    )

    assert result["status"] == "investigate"
    assert "gateway" in result["finding"].lower()

def test_external_target_unreachable():
    result = analyze_connectivity(
        {
            "default_gateway": "192.168.1.1",
            "gateway_reachable": True,
            "external_target": "1.1.1.1",
            "external_reachable": False,
        }
    )

    assert result["status"] == "investigate"
    assert "external target" in result["finding"].lower()

def test_missing_reachability_evidence():
    result = analyze_connectivity(
        {
            "default_gateway": "192.168.1.1",
            "gateway_reachable": None,
            "external_target": "1.1.1.1",
            "external_reachable": True,
        }
    )

    assert result["status"] == "inconclusive"

def test_invalid_gateway_address():
    result = analyze_connectivity(
        {
            "default_gateway": "not-an-ip",
            "gateway_reachable": True,
            "external_target": "1.1.1.1",
            "external_reachable": True,
        }
    )

    assert result["status"] == "inconclusive"
