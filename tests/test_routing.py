from src.analyzers.routing import analyze_routing

def test_missing_routes_are_inconclusive():
    report = analyze_routing({"routes": []})

    assert report["status"] == "inconclusive"
    assert report["evidence"] == []
    assert report["next_tests"]

def test_missing_default_route_requires_investigation():
    report = analyze_routing(
        {
            "routes": [
                {
                    "destination": "192.168.1.0",
                    "netmask": "255.255.255.0",
                    "gateway": "0.0.0.0",
                    "interface": "192.168.1.25",
                    "metric": 25,
                }
            ],
            "default_gateway": "192.168.1.1",
        }
    )

    assert report["status"] == "investigate"
    assert report["hypotheses"][0]["cause"] == "Missing IPv4 default route"

def test_default_route_is_identified():
    report = analyze_routing(
        {
            "routes": [
                {
                    "destination": "0.0.0.0",
                    "netmask": "0.0.0.0",
                    "gateway": "192.168.1.1",
                    "interface": "192.168.1.25",
                    "metric": 25,
                }
            ],
            "default_gateway": "192.168.1.1",
            "destination": "1.1.1.1",
        }
    )

    assert report["status"] == "route_present"
    assert report["hypotheses"] == []
    assert any(
        item["observation"] == "Default route count" and item["result"] == 1
        for item in report["evidence"]
    )

def test_ipv4_cidr_default_route_is_identified():
    report = analyze_routing(
        {
            "routes": [
                {
                    "destination": "0.0.0.0/0",
                    "gateway": "192.168.1.1",
                    "interface": "192.168.1.25",
                    "metric": 25,
                }
            ]
        }
    )

    assert report["status"] == "route_present"

def test_unrelated_route_entries_are_ignored_when_counting_default_routes():
    report = analyze_routing(
        {
            "routes": [
                {
                    "destination": "192.168.1.0",
                    "netmask": "255.255.255.0",
                    "gateway": "0.0.0.0",
                    "interface": "192.168.1.25",
                    "metric": 25,
                },
                {
                    "destination": "10.0.0.0",
                    "netmask": "255.0.0.0",
                    "gateway": "0.0.0.0",
                    "interface": "10.0.0.2",
                    "metric": 10,
                },
                {
                    "destination": "0.0.0.0",
                    "netmask": "0.0.0.0",
                    "gateway": "192.168.1.1",
                    "interface": "192.168.1.25",
                    "metric": 25,
                },
            ]
        }
    )

    default_route_count = next(
        item["result"]
        for item in report["evidence"]
        if item["observation"] == "Default route count"
    )

    assert default_route_count == 1

def test_matching_default_gateway_is_reported():
    report = analyze_routing(
        {
            "routes": [
                {
                    "destination": "0.0.0.0",
                    "netmask": "0.0.0.0",
                    "gateway": "192.168.1.1",
                    "interface": "192.168.1.25",
                    "metric": 25,
                }
            ],
            "default_gateway": "192.168.1.1",
        }
    )

    assert report["status"] == "route_present"
    assert any(
        item["observation"] == "Default route gateway match"
        and item["result"] is True
        for item in report["evidence"]
    )

def test_mismatched_default_gateway_requires_investigation():
    report = analyze_routing(
        {
            "routes": [
                {
                    "destination": "0.0.0.0",
                    "netmask": "0.0.0.0",
                    "gateway": "192.168.1.1",
                    "interface": "192.168.1.25",
                    "metric": 25,
                }
            ],
            "default_gateway": "192.168.1.254",
        }
    )

    assert report["status"] == "investigate"
    assert report["hypotheses"][0]["cause"] == "Default gateway mismatch"

def test_multiple_default_routes_are_reported_without_automatic_failure():
    report = analyze_routing(
        {
            "routes": [
                {
                    "destination": "0.0.0.0",
                    "netmask": "0.0.0.0",
                    "gateway": "192.168.1.1",
                    "interface": "192.168.1.25",
                    "metric": 25,
                },
                {
                    "destination": "0.0.0.0",
                    "netmask": "0.0.0.0",
                    "gateway": "10.0.0.1",
                    "interface": "10.0.0.179",
                    "metric": 30,
                },
            ]
        }
    )

    assert report["status"] == "route_present"
    assert any(
        item["observation"] == "Default route count" and item["result"] == 2
        for item in report["evidence"]
    )
