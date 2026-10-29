import pytest

from src.analyzers.firewall import (
    _address_filter_matches,
    _port_filter_matches,
    analyze_firewall_rules,
)


@pytest.mark.parametrize(
    ("value", "port", "expected"),
    [
        ("Any", 443, True),
        ("*", 53, True),
        ("443", 443, True),
        ("80,443", 443, True),
        ("80,443", 22, False),
        ("100-200", 150, True),
        ("100-200", 201, False),
        ("invalid", 443, False),
        ("100-200,443", 443, True),
    ],
)
def test_port_filter_matching(value, port, expected):
    assert _port_filter_matches(value, port) is expected


@pytest.mark.parametrize(
    ("value", "target", "expected"),
    [
        ("Any", "203.0.113.8", True),
        ("*", "203.0.113.8", True),
        ("203.0.113.8", "203.0.113.8", True),
        ("203.0.113.0/24", "203.0.113.8", True),
        ("203.0.113.0/24", "203.0.114.8", False),
        ("203.0.113.1-203.0.113.10", "203.0.113.8", True),
        ("203.0.113.1-203.0.113.10", "203.0.113.11", False),
        ("10.0.0.0/8,203.0.113.8", "203.0.113.8", True),
        ("not-an-address", "203.0.113.8", False),
        ("203.0.113.0/24", "not-an-address", False),
    ],
)
def test_address_filter_matching(value, target, expected):
    assert _address_filter_matches(value, target) is expected


def test_analyzer_reports_matching_outbound_tcp_block_rule():
    result = analyze_firewall_rules({
        "target_ip": "203.0.113.8",
        "target_port": 443,
        "candidate_rules": [{
            "display_name": "Block HTTPS",
            "action": "block",
            "protocol": "TCP",
            "remote_port": "443",
            "remote_address": "203.0.113.0/24",
        }],
    })

    assert result["status"] == "investigate"
    assert "1 enabled outbound block rule" in result["finding"]
    assert result["hypotheses"]
    assert "not proof" in result["hypotheses"][0]["reason"]


def test_analyzer_ignores_allow_rules_and_non_tcp_rules():
    result = analyze_firewall_rules({
        "target_ip": "203.0.113.8",
        "target_port": 443,
        "candidate_rules": [
            {"display_name": "Allow HTTPS", "action": "allow", "protocol": "TCP"},
            {"display_name": "Block DNS", "action": "block", "protocol": "UDP", "remote_port": "53"},
        ],
    })

    assert result["status"] == "healthy"
    assert "No matching outbound block rule" in result["finding"]


def test_analyzer_supports_port_and_address_ranges():
    result = analyze_firewall_rules({
        "target_ip": "203.0.113.8",
        "target_port": 8443,
        "candidate_rules": [{
            "display_name": "Block test range",
            "action": "block",
            "protocol": "6",
            "remote_port": "8000-9000",
            "remote_address": "203.0.113.1-203.0.113.20",
        }],
    })

    assert result["status"] == "investigate"


def test_analyzer_skips_malformed_rule_records():
    result = analyze_firewall_rules({
        "target_ip": "203.0.113.8",
        "target_port": 443,
        "candidate_rules": [None, "not a rule", {"action": "allow"}],
    })

    assert result["status"] == "healthy"


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"candidate_rules": [], "target_port": 0},
        {"candidate_rules": [], "target_port": True},
        {"candidate_rules": "not a list", "target_port": 443},
    ],
)
def test_analyzer_returns_inconclusive_for_invalid_input(data):
    result = analyze_firewall_rules(data)

    assert result["status"] == "inconclusive"
