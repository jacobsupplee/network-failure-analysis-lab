from ipaddress import AddressValueError, IPv4Address, IPv4Network, NetmaskValueError
from src.diagnostics import build_report

def parse_route_network(route: dict) -> IPv4Network | None:
    """Parse a route destination and netmask into an IPv4 network."""
    destination = route.get("destination")

    if not isinstance(destination, str):
        return None

    try:
        if "/" in destination:
            return IPv4Network(destination, strict=False)

        netmask = route.get("netmask", "0.0.0.0")
        return IPv4Network(f"{destination}/{netmask}", strict=False)
    except (AddressValueError, NetmaskValueError, TypeError, ValueError):
        return None

def valid_route_metric(route: dict) -> bool:
    """Return whether a route has a usable nonnegative numeric metric."""
    metric = route.get("metric")

    return (
        isinstance(metric, (int, float))
        and not isinstance(metric, bool)
        and metric >= 0
    )

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

    valid_routes = [
        (route, parse_route_network(route))
        for route in routes
        if isinstance(route, dict)
    ]
    valid_routes = [
        (route, network)
        for route, network in valid_routes
        if network is not None
    ]

    default_routes = [
        route
        for route, network in valid_routes
        if network.prefixlen == 0
    ]

    evidence = [
        {
            "observation": "Route count",
            "result": len(routes),
        },
        {
            "observation": "Default route count",
            "result": len(default_routes),
        },
    ]

    if default_gateway:
        evidence.append(
            {
                "observation": "Reported default gateway",
                "result": default_gateway,
            }
        )

    target_ip = None

    if destination:
        evidence.append(
            {
                "observation": "Test destination",
                "result": destination,
            }
        )

        try:
            target_ip = IPv4Address(destination)
        except (AddressValueError, TypeError):
            evidence.append(
                {
                    "observation": "Destination route analysis",
                    "result": "Skipped because the destination is not a valid IPv4 address.",
                }
            )

    matching_routes = []

    if target_ip is not None:
        matching_routes = [
            (route, network)
            for route, network in valid_routes
            if target_ip in network
        ]

    if not default_routes and not matching_routes:
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

    if target_ip is not None:
        if not matching_routes:
            evidence.append(
                {
                    "observation": "Destination route match",
                    "result": "No matching IPv4 route was found.",
                }
            )
        else:
            longest_prefix = max(
                network.prefixlen
                for _, network in matching_routes
            )
            best_prefix_routes = [
                (route, network)
                for route, network in matching_routes
                if network.prefixlen == longest_prefix
            ]

            evidence.append(
                {
                    "observation": "Longest matching prefix length",
                    "result": longest_prefix,
                }
            )
            evidence.append(
                {
                    "observation": "Routes matching destination",
                    "result": len(matching_routes),
                }
            )

            metric_routes = [
                (route, network)
                for route, network in best_prefix_routes
                if valid_route_metric(route)
            ]

            if metric_routes:
                lowest_metric = min(
                    route["metric"]
                    for route, _ in metric_routes
                )
                selected_candidates = [
                    (route, network)
                    for route, network in metric_routes
                    if route["metric"] == lowest_metric
                ]

                evidence.append(
                    {
                        "observation": "Lowest metric among longest-prefix routes",
                        "result": lowest_metric,
                    }
                )
            else:
                selected_candidates = best_prefix_routes
                evidence.append(
                    {
                        "observation": "Destination route metric analysis",
                        "result": (
                            "No valid metrics were available for the "
                            "longest matching routes."
                        ),
                    }
                )

            evidence.append(
                {
                    "observation": "Best matching route candidates",
                    "result": [
                        {
                            "network": str(network),
                            "gateway": route.get("gateway"),
                            "interface": route.get("interface"),
                            "metric": route.get("metric"),
                        }
                        for route, network in selected_candidates
                    ],
                }
            )

            if len(selected_candidates) > 1:
                evidence.append(
                    {
                        "observation": "Route selection certainty",
                        "result": (
                            "Multiple candidates remain. Interface metrics "
                            "or additional Windows route-selection details "
                            "may be needed to distinguish them."
                        ),
                    }
                )
            else:
                evidence.append(
                    {
                        "observation": "Route selection certainty",
                        "result": (
                            "One best candidate was identified from the "
                            "supplied prefix and metric data; actual "
                            "Windows route selection is not independently confirmed."
                        ),
                    }
                )

    valid_metric_routes = [
        route
        for route in default_routes
        if valid_route_metric(route)
    ]

    if valid_metric_routes:
        lowest_metric = min(
            route["metric"] for route in valid_metric_routes
        )
        lowest_metric_routes = [
            route
            for route in valid_metric_routes
            if route["metric"] == lowest_metric
        ]

        evidence.append(
            {
                "observation": "Lowest reported default-route metric",
                "result": lowest_metric,
            }
        )
        evidence.append(
            {
                "observation": "Routes with lowest reported metric",
                "result": len(lowest_metric_routes),
            }
        )

        for index, route in enumerate(lowest_metric_routes, start=1):
            evidence.append(
                {
                    "observation": f"Lowest-metric default route {index}",
                    "result": {
                        "gateway": route.get("gateway"),
                        "interface": route.get("interface"),
                        "metric": route["metric"],
                    },
                }
            )
    else:
        evidence.append(
            {
                "observation": "Route metric analysis",
                "result": "No valid default-route metrics were available.",
            }
        )

    if default_routes:
        status = "route_present"
        finding = "An IPv4 default route was identified in the supplied routing table."
        next_step = (
            "Review the matching route evidence and test destination reachability. "
            "Route metrics alone do not prove the route Windows selects."
        )
    else:
        status = "route_present"
        finding = (
            "No IPv4 default route was identified, but destination-specific "
            "route evidence was available for analysis."
        )
        next_step = (
            "Review the destination-specific route candidates and verify whether "
            "the available routes provide the required network reachability."
        )

    return build_report(
        status,
        finding,
        next_step,
        evidence,
        [],
        [
            {
                "test": "Test destination reachability",
                "purpose": "Determine whether the destination responds to a connectivity test.",
            },
            {
                "test": "Inspect route selection",
                "purpose": (
                    "Compare matching prefixes, route metrics, and interface "
                    "metrics to assess the likely route for the destination."
                ),
            },
        ],
        [
            "Confirm that the default route belongs to the intended network adapter.",
            "Verify destination reachability using an appropriate protocol.",
            "Compare the reported route with Windows route-selection behavior when necessary.",
        ],
    )
