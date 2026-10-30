import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

HISTORY_PATH = Path("data/scan_history.json")


def load_scan_history(history_path: Path = HISTORY_PATH) -> list[dict]:
    """Load saved live scans, returning an empty list when no history exists."""
    if not history_path.exists():
        return []

    try:
        with history_path.open("r", encoding="utf-8") as history_file:
            history = json.load(history_file)
    except json.JSONDecodeError as error:
        raise ValueError("Scan history contains invalid JSON.") from error

    if not isinstance(history, list):
        raise ValueError("Scan history must contain a JSON list.")

    return history


def save_scan(scan: dict, history_path: Path = HISTORY_PATH) -> dict:
    """Save a completed live scan and return its history record."""
    if not isinstance(scan, dict) or not isinstance(scan.get("results"), list):
        raise ValueError("A scan must contain a results list.")

    correlation = scan.get("correlation")
    if not isinstance(correlation, dict):
        raise ValueError("A scan must contain a correlation result.")

    record = {
        "scan_id": str(uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "overall_status": correlation.get("status", "inconclusive"),
        "overall_finding": correlation.get("finding", "No overall finding was provided."),
        "correlation": correlation,
        "results": scan["results"],
    }

    if isinstance(scan.get("configuration_snapshot"), dict):
        record["configuration_snapshot"] = scan["configuration_snapshot"]

    history = load_scan_history(history_path)
    history.append(record)

    history_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = history_path.with_suffix(history_path.suffix + ".tmp")

    try:
        with temporary_path.open("w", encoding="utf-8") as history_file:
            json.dump(history, history_file, indent=2, ensure_ascii=False)
            history_file.write("\n")
        temporary_path.replace(history_path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()

    return record


def clear_scan_history(history_path: Path = HISTORY_PATH) -> None:
    """Remove the local scan history file if it exists."""
    if history_path.exists():
        history_path.unlink()


def compare_scans(older_scan: dict, newer_scan: dict) -> dict:
    """Compare diagnostic statuses between two saved scans."""
    older_results = {
        result.get("diagnostic_type"): result
        for result in older_scan.get("results", [])
        if result.get("diagnostic_type")
    }
    newer_results = {
        result.get("diagnostic_type"): result
        for result in newer_scan.get("results", [])
        if result.get("diagnostic_type")
    }

    changes = []
    for diagnostic_type in sorted(set(older_results) | set(newer_results)):
        older_result = older_results.get(diagnostic_type)
        newer_result = newer_results.get(diagnostic_type)
        old_status = (
            older_result.get("analysis", {}).get("status")
            if older_result else None
        )
        new_status = (
            newer_result.get("analysis", {}).get("status")
            if newer_result else None
        )

        if old_status != new_status:
            changes.append({
                "diagnostic_type": diagnostic_type,
                "previous_status": old_status or "Not present",
                "current_status": new_status or "Not present",
                "previous_finding": (
                    older_result.get("analysis", {}).get("finding")
                    if older_result else None
                ),
                "current_finding": (
                    newer_result.get("analysis", {}).get("finding")
                    if newer_result else None
                ),
            })

    old_overall = older_scan.get("overall_status", "inconclusive")
    new_overall = newer_scan.get("overall_status", "inconclusive")

    return {
        "overall_changed": old_overall != new_overall,
        "previous_overall_status": old_overall,
        "current_overall_status": new_overall,
        "changes": changes,
    }
