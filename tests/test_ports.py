from src.analyzers.ports import analyze_port

def test_successful_tcp_connection_is_reachable():
    report = analyze_port(
        {"host": "example.com", "port": 443, "result": "connected"}
    )

    assert report["status"] == "reachable"
    assert "succeeded" in report["finding"]

def test_refused_tcp_connection_requires_investigation():
    report = analyze_port(
        {"host": "192.0.2.10", "port": 443, "result": "refused"}
    )

    assert report["status"] == "investigate"
    assert report["hypotheses"][0]["cause"] == (
        "Service unavailable or connection actively rejected"
    )


def test_timeout_is_inconclusive():
    report = analyze_port(
        {"host": "192.0.2.10", "port": 443, "result": "timeout"}
    )

    assert report["status"] == "inconclusive"
    assert report["hypotheses"]

def test_invalid_port_is_inconclusive():
    report = analyze_port(
        {"host": "example.com", "port": 70000, "result": "connected"}
    )

    assert report["status"] == "inconclusive"

def test_missing_host_is_inconclusive():
    report = analyze_port(
        {"host": "", "port": 443, "result": "connected"}
    )

    assert report["status"] == "inconclusive"

def test_unknown_result_is_inconclusive():
    report = analyze_port(
        {"host": "example.com", "port": 443, "result": "unknown"}
    )

    assert report["status"] == "inconclusive"
