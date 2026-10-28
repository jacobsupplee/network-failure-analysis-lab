import socket
from unittest.mock import MagicMock, patch
from src.evidence_collection import collect_tcp_connection

def test_successful_tcp_connection():
    with patch("src.evidence_collection.socket.create_connection") as mock_connect:
        mock_connect.return_value.__enter__.return_value = MagicMock()

        result = collect_tcp_connection("example.com", 443)

    assert result["result"] == "connected"
    assert result["host"] == "example.com"
    assert result["port"] == 443
    mock_connect.assert_called_once_with(("example.com", 443), timeout=3.0)

def test_refused_tcp_connection():
    with patch(
        "src.evidence_collection.socket.create_connection",
        side_effect=ConnectionRefusedError("Connection refused"),
    ):
        result = collect_tcp_connection("192.0.2.10", 443)

    assert result["result"] == "refused"
    assert "Connection refused" in result["error"]

def test_tcp_connection_timeout():
    with patch(
        "src.evidence_collection.socket.create_connection",
        side_effect=socket.timeout("Timed out"),
    ):
        result = collect_tcp_connection("192.0.2.10", 443)

    assert result["result"] == "timeout"

def test_unreachable_network():
    error = OSError(10065, "No route to host")

    with patch(
        "src.evidence_collection.socket.create_connection",
        side_effect=error,
    ):
        result = collect_tcp_connection("192.0.2.10", 443)

    assert result["result"] == "unreachable"

def test_invalid_host_is_rejected():
    result = collect_tcp_connection("", 443)

    assert result["result"] == "error"
    assert "hostname or IP address" in result["error"]

def test_invalid_port_is_rejected():
    result = collect_tcp_connection("example.com", 70000)

    assert result["result"] == "error"
    assert "Port must be an integer" in result["error"]

def test_boolean_port_is_rejected():
    result = collect_tcp_connection("example.com", True)

    assert result["result"] == "error"

def test_invalid_timeout_is_rejected():
    result = collect_tcp_connection("example.com", 443, timeout=0)

    assert result["result"] == "error"
    assert "Timeout must be greater than 0" in result["error"]
