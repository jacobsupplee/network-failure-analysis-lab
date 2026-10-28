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