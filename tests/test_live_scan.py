import application

def test_live_scan_continues_when_dns_collection_fails(monkeypatch):
    monkeypatch.setattr(
        application,
        "collect_network_configuration",
        lambda: {
            "primary_adapter": {
                "ip_address": "192.168.1.25",
                "default_gateway": "192.168.1.1",
                "dhcp_server": "192.168.1.1",
                "dns_servers": ["192.168.1.1"],
            }
        },
    )
    def fail_dns():
        raise RuntimeError("DNS collection failed")

    monkeypatch.setattr(application, "collect_dns_resolution", fail_dns)
    monkeypatch.setattr(
        application,
        "collect_connectivity",
        lambda gateway: {
            "default_gateway": gateway,
            "gateway_reachable": True,
            "external_target": "1.1.1.1",
            "external_reachable": True,
        },
    )
    monkeypatch.setattr(
        application,
        "collect_routing_table",
        lambda: {
            "source": "Windows route print -4",
            "routes": [
                {
                    "destination": "0.0.0.0",
                    "netmask": "0.0.0.0",
                    "gateway": "192.168.1.1",
                    "interface": "192.168.1.25",
                    "metric": 25,
                }
            ],
            "raw_output": "Mock routing table",
        },
    )
    monkeypatch.setattr(
        application,
        "collect_tcp_connection",
        lambda host, port: {
            "host": host,
            "port": port,
            "result": "connected",
            "error": None,
        },
    )

    scan = application.run_live_scan()
    results = scan["results"]
    correlation = scan["correlation"]

    assert len(results) == 5
    assert results[0]["scenario_id"] == "LIVE-DHCP"
    assert results[1]["analysis"]["status"] == "inconclusive"
    assert results[2]["analysis"]["status"] == "connected"
    assert results[3]["diagnostic_type"] == "routing"
    assert results[4]["diagnostic_type"] == "ports"
    assert correlation["status"] == "inconclusive"

def test_live_scan_continues_when_configuration_collection_fails(monkeypatch):
    def fail_configuration():
        raise RuntimeError("Configuration collection failed")

    monkeypatch.setattr(
        application,
        "collect_network_configuration",
        fail_configuration,
    )
    monkeypatch.setattr(
        application,
        "collect_dns_resolution",
        lambda: {
            "hostname": "example.com",
            "resolution_result": "success",
            "details": "Name resolved",
        },
    )
    monkeypatch.setattr(
        application,
        "collect_connectivity",
        lambda gateway: {
            "default_gateway": gateway,
            "gateway_reachable": None,
            "external_target": "1.1.1.1",
            "external_reachable": True,
        },
    )
    monkeypatch.setattr(
        application,
        "collect_routing_table",
        lambda: {
            "source": "Windows route print -4",
            "routes": [
                {
                    "destination": "0.0.0.0",
                    "netmask": "0.0.0.0",
                    "gateway": "192.168.1.1",
                    "interface": "192.168.1.25",
                    "metric": 25,
                }
            ],
            "raw_output": "Mock routing table",
        },
    )
    monkeypatch.setattr(
        application,
        "collect_tcp_connection",
        lambda host, port: {
            "host": host,
            "port": port,
            "result": "connected",
            "error": None,
        },
    )

    scan = application.run_live_scan()
    results = scan["results"]
    correlation = scan["correlation"]

    assert len(results) == 5
    assert results[0]["analysis"]["status"] == "inconclusive"
    assert results[1]["analysis"]["status"] == "resolved"
    assert results[2]["analysis"]["status"] == "inconclusive"
    assert results[3]["diagnostic_type"] == "routing"
    assert results[4]["diagnostic_type"] == "ports"
    assert correlation["status"] == "inconclusive"
