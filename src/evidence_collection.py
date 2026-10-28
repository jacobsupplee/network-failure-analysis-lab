import re
import subprocess

def collect_network_configuration() -> dict:
    """Collect and parse network configuration reported by Windows."""

    result = subprocess.run(
        ["ipconfig", "/all"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=15,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"ipconfig failed with exit code {result.returncode}."
        )

    raw_output = result.stdout
    adapters = []
    current_adapter = None
    current_field = None

    for line in raw_output.splitlines():
        header = re.match(r"^(.+ adapter .+):\s*$", line, re.IGNORECASE)

        if header:
            if current_adapter:
                adapters.append(current_adapter)

            current_adapter = {
                "name": re.sub(
                    r"^.*?\badapter\s+", "", header.group(1).strip(), flags=re.IGNORECASE
                ),
                "ip_address": None,
                "subnet_mask": None,
                "default_gateway": None,
                "dhcp_enabled": None,
                "dhcp_server": None,
                "dns_servers": [],
            }
            current_field = None
            continue

        if current_adapter is None:
            continue

        field_match = re.match(r"^\s*([^:]+?)\s*\.\s*:\s*(.*)$", line)

        if not field_match:
            field_match = re.match(r"^\s*([^:]+?)\s*:\s*(.*)$", line)

        if field_match:
            label = field_match.group(1).strip().lower()
            value = field_match.group(2).strip()
            current_field = None

            if label.startswith("ipv4 address"):
                current_adapter["ip_address"] = re.sub(
                    r"\s*\(preferred\)$", "", value, flags=re.IGNORECASE
                )
            elif label.startswith("subnet mask"):
                current_adapter["subnet_mask"] = value or None
            elif label.startswith("default gateway"):
                current_field = "default_gateway"
                if value:
                    current_adapter["default_gateway"] = value
            elif label.startswith("dhcp enabled"):
                current_adapter["dhcp_enabled"] = value.lower() == "yes"
            elif label.startswith("dhcp server"):
                current_adapter["dhcp_server"] = value or None
            elif label.startswith("dns servers"):
                current_field = "dns_servers"
                if value:
                    current_adapter["dns_servers"].append(value)
            continue

        if current_field and line[:1].isspace():
            value = line.strip()

            if value:
                if current_field == "dns_servers":
                    current_adapter["dns_servers"].append(value)
                elif current_field == "default_gateway":
                    current_adapter["default_gateway"] = value

    if current_adapter:
        adapters.append(current_adapter)

    for adapter in adapters:
        adapter["dns_servers"] = list(dict.fromkeys(adapter["dns_servers"]))

    usable_adapters = [
        adapter for adapter in adapters
        if adapter["ip_address"]
    ]

    primary_adapter = next(
        (
            adapter for adapter in usable_adapters
            if adapter["default_gateway"]
        ),
        usable_adapters[0] if usable_adapters else None,
    )

    return {
        "source": "Windows ipconfig /all",
        "adapters": adapters,
        "primary_adapter": primary_adapter,
        "raw_output": raw_output,
    }

def collect_dns_resolution(hostname: str = "example.com") -> dict:
    """Test hostname resolution using the Windows DNS resolver."""

    try:
        result = subprocess.run(
            ["nslookup", hostname],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "hostname": hostname,
            "resolution_result": "timeout",
            "details": "The DNS lookup exceeded 10 seconds.",
        }
    except OSError as error:
        return {
            "hostname": hostname,
            "resolution_result": "unavailable",
            "details": str(error),
        }

    output = result.stdout + result.stderr
    normalized_output = output.lower()

    if "non-existent domain" in normalized_output or "nxdomain" in normalized_output:
        status = "nxdomain"
    elif "timed out" in normalized_output or "timeout" in normalized_output:
        status = "timeout"
    elif result.returncode == 0 and result.stdout.strip():
        status = "success"
    else:
        status = "failed"

    return {
        "hostname": hostname,
        "resolution_result": status,
        "details": output.strip(),
    }

def collect_connectivity(
    gateway_ip: str | None,
    external_target: str = "1.1.1.1",
) -> dict:
    """Test gateway and external reachability using bounded ping requests."""

    def ping(target: str) -> bool | None:
        try:
            result = subprocess.run(
                ["ping", "-n", "1", "-w", "2000", target],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return None
        except OSError:
            return None

        output = (result.stdout + result.stderr).lower()

        if "could not find host" in output or "bad value" in output:
            return None

        return result.returncode == 0

    gateway_reachable = ping(gateway_ip) if gateway_ip else None
    external_reachable = ping(external_target)

    return {
        "default_gateway": gateway_ip,
        "gateway_reachable": gateway_reachable,
        "external_target": external_target,
        "external_reachable": external_reachable,
    }

def collect_routing_table() -> dict:
    """Collect and parse the Windows IPv4 routing table."""
    try:
        result = subprocess.run(
            ["route", "print", "-4"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("Routing table collection timed out.") from error
    except OSError as error:
        raise RuntimeError(f"Could not run the route command: {error}") from error

    if result.returncode != 0:
        raise RuntimeError(
            f"route print failed with exit code {result.returncode}."
        )

    routes = []
    in_active_routes = False

    for line in result.stdout.splitlines():
        if line.strip().startswith("IPv4 Route Table"):
            continue

        if line.strip().startswith("Active Routes:"):
            in_active_routes = True
            continue

        if line.strip().startswith("Persistent Routes:"):
            in_active_routes = False

        if not in_active_routes:
            continue

        fields = line.split()

        if len(fields) < 5:
            continue

        destination, netmask, gateway, interface, metric = fields[:5]

        if not re.fullmatch(r"\d+", metric):
            continue

        routes.append(
            {
                "destination": destination,
                "netmask": netmask,
                "gateway": gateway,
                "interface": interface,
                "metric": int(metric),
            }
        )

    return {
        "source": "Windows route print -4",
        "routes": routes,
        "raw_output": result.stdout,
    }
