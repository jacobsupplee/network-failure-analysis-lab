from src.diagnostics import build_report

def analyze_port(data: dict) -> dict:
    """Analyze the result of a TCP connection test."""
    host = data.get("host")
    port = data.get("port")
    result = data.get("result")
    error = data.get("error")

    evidence = [
        {"observation": "Target host", "result": host},
        {"observation": "Target port", "result": port},
        {"observation": "TCP connection result", "result": result},
    ]

    if error:
        evidence.append({"observation": "Connection error", "result": error})

    if not isinstance(host, str) or not host.strip():
        return build_report(
            status="inconclusive",
            finding="A valid target host was not provided.",
            next_step="Provide a hostname or IP address to test.",
            evidence=evidence,
            hypotheses=[],
            next_tests=[
                {
                    "test": "Verify the target host",
                    "purpose": "Confirm the hostname or IP address.",
                }
            ],
            verification=["Repeat the TCP connection test with a valid host."],
        )

    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        return build_report(
            status="inconclusive",
            finding="The TCP port must be an integer between 1 and 65535.",
            next_step="Provide a valid TCP port number.",
            evidence=evidence,
            hypotheses=[],
            next_tests=[
                {
                    "test": "Validate the target port",
                    "purpose": "Confirm the service's configured TCP port.",
                }
            ],
            verification=["Repeat the test with a valid TCP port."],
        )

    if result == "connected":
        return build_report(
            status="reachable",
            finding=f"TCP connection to {host}:{port} succeeded.",
            next_step="If the application still fails, investigate the service protocol or application configuration.",
            evidence=evidence,
            hypotheses=[],
            next_tests=[
                {
                    "test": "Validate the application protocol",
                    "purpose": "Confirm the service responds correctly after the TCP connection.",
                }
            ],
            verification=["Repeat the connection test and verify application-level behavior."],
        )

    if result == "refused":
        return build_report(
            status="investigate",
            finding=f"The TCP connection to {host}:{port} was refused.",
            next_step="Check whether the service is listening on the target port and whether a firewall is actively rejecting the connection.",
            evidence=evidence,
            hypotheses=[
                {
                    "cause": "Service unavailable or connection actively rejected",
                    "reason": "The connection was refused, which commonly indicates that no service is listening or that a device actively rejected the connection.",
                }
            ],
            next_tests=[
                {
                    "test": "Check the listening service",
                    "purpose": "Confirm that the target service is running and listening on the expected port.",
                }
            ],
            verification=["Repeat the TCP connection test after checking the service and filtering rules."],
        )

    if result == "timeout":
        return build_report(
            status="inconclusive",
            finding=f"The TCP connection to {host}:{port} timed out.",
            next_step="Check target reachability, routing, firewall filtering, and service availability.",
            evidence=evidence,
            hypotheses=[
                {
                    "cause": "Connection filtered or target not responding",
                    "reason": "A timeout does not distinguish packet filtering from an unavailable target or service.",
                }
            ],
            next_tests=[
                {
                    "test": "Check general target reachability",
                    "purpose": "Determine whether the host can be reached independently of this TCP port.",
                },
                {
                    "test": "Check service and firewall configuration",
                    "purpose": "Determine whether the port is listening or traffic is being filtered.",
                },
            ],
            verification=["Repeat the connection test and compare the result with independent reachability evidence."],
        )

    if result == "unreachable":
        return build_report(
            status="investigate",
            finding=f"The target host {host} was reported as unreachable during the TCP test.",
            next_step="Check host addressing, routing, and network reachability before drawing conclusions about the service.",
            evidence=evidence,
            hypotheses=[
                {
                    "cause": "Host or network path unavailable",
                    "reason": "The connection attempt reported a host-level reachability error.",
                }
            ],
            next_tests=[
                {
                    "test": "Check network reachability",
                    "purpose": "Verify whether the host is reachable through another diagnostic.",
                }
            ],
            verification=["Repeat the TCP test after checking the network path."],
        )

    return build_report(
        status="inconclusive",
        finding="The TCP connection result is missing or unrecognized.",
        next_step="Collect a valid TCP connection result and repeat the analysis.",
        evidence=evidence,
        hypotheses=[],
        next_tests=[
            {
                "test": "Repeat the TCP connection test",
                "purpose": "Collect a recognized connection outcome.",
            }
        ],
        verification=["Confirm that the collection layer returns a supported result."],
    )
