import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

BASELINE_PATH = Path("data/network_baseline.json")

FIELD_LABELS = {
    "adapter_name": "Network adapter",
    "ip_address": "IPv4 address",
    "subnet_mask": "Subnet mask",
    "default_gateway": "Default gateway",
    "dhcp_enabled": "DHCP enabled",
    "dhcp_server": "DHCP server",
    "dns_servers": "DNS servers",
    "default_routes": "IPv4 default routes",
    "firewall_profiles": "Windows Firewall profiles",
    "tcp_target": "TCP test target",
    "tcp_result": "TCP connectivity result",
}


def load_baseline(baseline_path: Path = BASELINE_PATH) -> dict | None:
    """Load the saved network baseline, returning None when it does not exist."""
    if not baseline_path.exists():
        return None

    try:
        with baseline_path.open("r", encoding="utf-8") as baseline_file:
            baseline = json.load(baseline_file)
    except json.JSONDecodeError as error:
        raise ValueError("Network baseline contains invalid JSON.") from error

    if not isinstance(baseline, dict) or not isinstance(
        baseline.get("configuration_snapshot"), dict
    ):
        raise ValueError("Network baseline has an invalid format.")

    return baseline


def save_baseline(scan: dict, baseline_path: Path = BASELINE_PATH) -> dict:
    """Save a scan's configuration snapshot as the known-good baseline."""
    snapshot = scan.get("configuration_snapshot") if isinstance(scan, dict) else None
    if not isinstance(snapshot, dict) or not snapshot:
        raise ValueError("The selected scan does not contain a configuration snapshot.")

    baseline = {
        "baseline_id": str(uuid4()),
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "source_scan_id": scan.get("scan_id"),
        "source_scan_timestamp": scan.get("timestamp"),
        "source_overall_status": scan.get("overall_status", "unknown"),
        "configuration_snapshot": snapshot,
    }

    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = baseline_path.with_suffix(baseline_path.suffix + ".tmp")

    try:
        with temporary_path.open("w", encoding="utf-8") as baseline_file:
            json.dump(baseline, baseline_file, indent=2, ensure_ascii=False)
            baseline_file.write("\n")
        temporary_path.replace(baseline_path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()

    return baseline


def clear_baseline(baseline_path: Path = BASELINE_PATH) -> None:
    """Remove the saved network baseline if it exists."""
    if baseline_path.exists():
        baseline_path.unlink()


def compare_configuration(
    baseline_snapshot: dict,
    current_snapshot: dict,
) -> list[dict]:
    """Compare available configuration values without treating missing evidence as drift."""
    if not isinstance(baseline_snapshot, dict) or not isinstance(current_snapshot, dict):
        raise ValueError("Both configuration snapshots must be dictionaries.")

    changes = []
    for field, label in FIELD_LABELS.items():
        if field not in baseline_snapshot or field not in current_snapshot:
            continue

        previous = baseline_snapshot[field]
        current = current_snapshot[field]

        if previous is None or current is None or previous == current:
            continue

        if field == "tcp_result":
            if previous == "connected" and current != "connected":
                assessment = "Connectivity regression"
            elif previous != "connected" and current == "connected":
                assessment = "Connectivity improvement"
            else:
                assessment = "Connectivity result changed"
        elif field == "tcp_target":
            assessment = "Test target changed"
        elif field in {"default_gateway", "dns_servers", "default_routes"}:
            assessment = "Review network path"
        elif field == "firewall_profiles":
            assessment = "Review firewall configuration"
        else:
            assessment = "Configuration changed"

        changes.append({
            "field": field,
            "label": label,
            "baseline_value": previous,
            "current_value": current,
            "assessment": assessment,
        })

    target_change = any(change["field"] == "tcp_target" for change in changes)
    if target_change:
        changes = [
            change for change in changes
            if change["field"] != "tcp_result"
        ]

    return changes
