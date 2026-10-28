from ipaddress import IPv4Address, AddressValueError
from src.diagnostics import build_report

def analyze_routing(data: dict) -> dict:
    """Analyze routing evidence for a possible network path problem."""
    routes = data.get("routes")
    destination = data.get("destination")
    default_gateway = data.get("default_gateway")

    if not isinstance(routes, list) or not routes:
        return build_report(
            "inconclusive",
            "No routing table evidence was provided.",
            "Collect the routing table and retry the routing diagnostic.",
            [],
            [],
            [
                {
                    "test": "Collect routing table",
                    "purpose": "Identify available routes and the default gateway.",
                }
            ],
            ["Confirm that routing table collection completed successfully."],
        )

    evidence = [
        {
            "observation": "Route count",
            "result": len(routes),
        }
    ]

    default_routes = [
        route
        for route in routes
        if isinstance(route, dict)
        and route.get("destination") in {"0.0.0.0", "0.0.0.0/0"}
        and route.get("netmask", "0.0.0.0") == "0.0.0.0"
    ]

    if default_gateway:
        evidence.append(
            {
                "observation": "Reported default gateway",
                "result": default_gateway,
            }
        )

    evidence.append(
        {
            "observation": "Default route count",
            "result": len(default_routes),
        }
    )

    if not default_routes:
        return build_report(
            "investigate",
            "No IPv4 default route was identified in the supplied routing table.",
            "Verify the default gateway configuration and inspect the routing table.",
            evidence,
            [
                {
                    "cause": "Missing IPv4 default route",
                    "reason": (
                        "The supplied routing evidence contains no route "
                        "for destinations outside explicitly listed networks."
                    ),
                    "confidence": "Possible",
                }
            ],
            [
                {
                    "test": "Inspect IP configuration",
                    "purpose": "Confirm that the adapter has the expected gateway.",
                },
                {
                    "test": "Inspect routing table",
                    "purpose": "Check whether a default route exists on the active adapter.",
                },
            ],
            [
                "Confirm whether the active adapter requires an IPv4 default route.",
                "Repeat connectivity tests after any routing correction.",
            ],
        )

    if destination:
        evidence.append(
            {
                "observation": "Test destination",
                "result": destination,
            }
        )

    route_gateways = [
        route.get("gateway")
        for route in default_routes
        if route.get("gateway")
        and route.get("gateway") != "0.0.0.0"
    ]

    if default_gateway and route_gateways:
        try:
            reported_gateway = IPv4Address(default_gateway)
            parsed_route_gateways = [
                IPv4Address(gateway)
                for gateway in route_gateways
            ]
        except (AddressValueError, TypeError):
            evidence.append(
                {
                    "observation": "Gateway comparison",
                    "result": "Could not compare invalid IPv4 gateway data.",
                }
            )
        else:
            matching_gateway = any(
                gateway == reported_gateway
                for gateway in parsed_route_gateways
            )

            evidence.append(
                {
                    "observation": "Default route gateway match",
                    "result": matching_gateway,
                }
            )

            if not matching_gateway:
                return build_report(
                    "investigate",
                    (
                        "The reported default gateway does not match "
                        "the gateway in the supplied IPv4 default route."
                    ),
                    (
                        "Confirm the active adapter and determine whether "
                        "the reported gateway and routing table refer to "
                        "the same network interface."
                    ),
                    evidence,
                    [
                        {
                            "cause": "Default gateway mismatch",
                            "reason": (
                                "The reported gateway differs from the "
                                "gateway recorded in the default route."
                            ),
                            "confidence": "Possible",
                        }
                    ],
                    [
                        {
                            "test": "Compare adapter configuration",
                            "purpose": (
                                "Verify the gateway assigned to the active "
                                "network adapter."
                            ),
                        },
                        {
                            "test": "Inspect default route selection",
                            "purpose": (
                                "Determine which default route Windows "
                                "selects for the destination."
                            ),
                        },
                    ],
                    [
                        "Confirm that the adapter and route information are current.",
                        "Test destination reachability after verifying route selection.",
                    ],
                )

    return build_report(
        "route_present",
        "An IPv4 default route was identified in the supplied routing table.",
        "Test reachability to the destination and verify that the selected route is appropriate.",
        evidence,
        [],
        [
            {
                "test": "Test destination reachability",
                "purpose": "Determine whether the destination responds to a connectivity test.",
            },
            {
                "test": "Inspect route selection",
                "purpose": "Confirm which route and gateway would be used for the destination.",
            },
        ],
        [
            "Confirm that the default route belongs to the intended network adapter.",
            "Verify destination reachability using an appropriate protocol.",
        ],
    )
