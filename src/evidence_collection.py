import json
import re
import socket
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
                    r"^.*?\badapter\s+",
                    "",
                    header.group(1).strip(),
                    flags=re.IGNORECASE,
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


def collect_tcp_connection(
    host: str,
    port: int,
    timeout: float = 3.0,
) -> dict:
    """Test a TCP connection with a bounded connection timeout."""
    evidence = {
        "host": host,
        "port": port,
        "result": "error",
        "error": None,
    }

    if not isinstance(host, str) or not host.strip():
        evidence["error"] = "A non-empty hostname or IP address is required."
        return evidence

    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        evidence["error"] = "Port must be an integer between 1 and 65535."
        return evidence

    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not 0 < timeout <= 30
    ):
        evidence["error"] = "Timeout must be greater than 0 and no more than 30 seconds."
        return evidence

    evidence["host"] = host.strip()

    try:
        with socket.create_connection(
            (evidence["host"], port),
            timeout=timeout,
        ):
            evidence["result"] = "connected"
    except ConnectionRefusedError as error:
        evidence["result"] = "refused"
        evidence["error"] = str(error)
    except (socket.timeout, TimeoutError) as error:
        evidence["result"] = "timeout"
        evidence["error"] = str(error) or "The TCP connection attempt timed out."
    except OSError as error:
        evidence["error"] = str(error)

        if getattr(error, "errno", None) in {10051, 10065, 101, 113}:
            evidence["result"] = "unreachable"
        else:
            evidence["result"] = "error"

    return evidence



def collect_firewall_profiles() -> dict:
    """Read the enabled state of Windows Firewall's three network profiles."""
    command = (
        "Get-NetFirewallProfile | "
        "Select-Object Name, Enabled | ConvertTo-Json -Compress"
    )

    try:
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                command,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("Windows Firewall profile inspection timed out.") from error
    except OSError as error:
        raise RuntimeError(f"Could not run PowerShell to inspect Windows Firewall: {error}") from error

    if result.returncode != 0:
        message = result.stderr.strip() or f"exit code {result.returncode}"
        raise RuntimeError(f"Windows Firewall profile inspection failed: {message}")

    try:
        profiles = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("Windows Firewall returned invalid or empty JSON.") from error

    if isinstance(profiles, dict):
        profiles = [profiles]

    if not isinstance(profiles, list) or not profiles:
        raise RuntimeError("Windows Firewall returned no profile data.")

    normalized_profiles = []
    for profile in profiles:
        if not isinstance(profile, dict) or not isinstance(profile.get("Name"), str):
            raise RuntimeError("Windows Firewall returned an invalid profile record.")

        enabled = profile.get("Enabled")
        if isinstance(enabled, bool):
            pass
        elif isinstance(enabled, int) and enabled in (0, 1):
            enabled = bool(enabled)
        elif isinstance(enabled, str):
            value = enabled.strip().lower()
            enabled = value == "true" if value in {"true", "false"} else None
        else:
            enabled = None

        normalized_profiles.append({
            "name": profile["Name"],
            "enabled": enabled,
        })

    return {
        "source": "Windows Get-NetFirewallProfile",
        "profiles": normalized_profiles,
        "raw_output": result.stdout.strip(),
    }



def collect_firewall_rules(target_host: str, target_port: int) -> dict:
    """Collect enabled outbound firewall rules for cautious target-specific review."""
    if not isinstance(target_host, str) or not target_host.strip():
        raise ValueError("A non-empty target hostname or IP address is required.")
    if isinstance(target_port, bool) or not isinstance(target_port, int) or not 1 <= target_port <= 65535:
        raise ValueError("Target port must be an integer between 1 and 65535.")

    command = r"""
    Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Outbound |
      ForEach-Object {
        $rule = $_
        $portFilter = $rule | Get-NetFirewallPortFilter
        $addressFilter = $rule | Get-NetFirewallAddressFilter
        $appFilter = $rule | Get-NetFirewallApplicationFilter
        $serviceFilter = $rule | Get-NetFirewallServiceFilter
        [PSCustomObject]@{
          DisplayName = $rule.DisplayName
          Action = [string]$rule.Action
          Profile = [string]$rule.Profile
          Protocol = [string]$portFilter.Protocol
          LocalPort = (@($portFilter.LocalPort) -join ',')
          RemotePort = (@($portFilter.RemotePort) -join ',')
          LocalAddress = (@($addressFilter.LocalAddress) -join ',')
          RemoteAddress = (@($addressFilter.RemoteAddress) -join ',')
          Program = $appFilter.Program
          Service = $serviceFilter.Service
        }
      } | ConvertTo-Json -Compress -Depth 4
    """
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=20, check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("Windows Firewall rule inspection timed out.") from error
    except OSError as error:
        raise RuntimeError(f"Could not run PowerShell to inspect Windows Firewall rules: {error}") from error

    if result.returncode != 0:
        message = result.stderr.strip() or f"exit code {result.returncode}"
        raise RuntimeError(f"Windows Firewall rule inspection failed: {message}")
    try:
        rules = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("Windows Firewall returned invalid or empty rule JSON.") from error
    if isinstance(rules, dict):
        rules = [rules]
    if not isinstance(rules, list):
        raise RuntimeError("Windows Firewall returned invalid rule data.")

    target_addresses = set()
    try:
        target_addresses.add(str(socket.gethostbyname(target_host.strip())))
    except OSError:
        target_addresses.add(target_host.strip())

    def values(value):
        if value is None:
            return ["Any"]
        if isinstance(value, list):
            return [str(item).strip() for item in value]
        return [part.strip() for part in str(value).split(",") if part.strip()]

    def port_matches(value):
        for item in values(value):
            if item.lower() in {"any", "*"}:
                return True
            try:
                if int(item) == target_port:
                    return True
            except ValueError:
                bounds = item.split("-", 1)
                if len(bounds) == 2:
                    try:
                        if int(bounds[0]) <= target_port <= int(bounds[1]):
                            return True
                    except ValueError:
                        pass
        return False

    def address_matches(value):
        import ipaddress
        for item in values(value):
            if item.lower() in {"any", "*", "0.0.0.0/0", "::/0", "internet"}:
                return True
            for target in target_addresses:
                if item.lower() == target.lower():
                    return True
                try:
                    if "/" in item and ipaddress.ip_address(target) in ipaddress.ip_network(item, strict=False):
                        return True
                except ValueError:
                    continue
        return False

    candidates = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        protocol = str(rule.get("Protocol", "Any")).strip().lower()
        if protocol not in {"6", "tcp", "any", "256"}:
            continue
        if port_matches(rule.get("RemotePort")) and address_matches(rule.get("RemoteAddress")):
            candidates.append({
                "display_name": rule.get("DisplayName") or "(unnamed rule)",
                "action": str(rule.get("Action", "Unknown")),
                "profile": rule.get("Profile"),
                "protocol": protocol,
                "local_port": rule.get("LocalPort"),
                "remote_port": rule.get("RemotePort"),
                "local_address": rule.get("LocalAddress"),
                "remote_address": rule.get("RemoteAddress"),
                "program": rule.get("Program"),
                "service": rule.get("Service"),
            })

    return {
        "source": "Windows Get-NetFirewallRule (ActiveStore)",
        "target_host": target_host.strip(),
        "target_port": target_port,
        "target_addresses": sorted(target_addresses),
        "candidate_rules": candidates,
        "rules_collected": len(rules),
        "raw_output": result.stdout.strip(),
    }
