import json

import pytest

from src.diagnostic_report import (
    build_diagnostic_report_html,
    build_diagnostic_report_json,
)


def sample_scan():
    return {
        "scan_id": "scan-001",
        "timestamp": "2026-10-30T12:00:00+00:00",
        "overall_status": "investigate",
        "overall_finding": "DNS resolution failed.",
        "correlation": {
            "status": "investigate",
            "finding": "DNS resolution failed.",
            "next_step": "Check the configured resolver.",
            "likely_causes": [{
                "cause": "DNS server unavailable",
                "reason": "The query timed out.",
                "confidence": "Moderate",
                "priority_score": 72,
                "supporting_evidence": ["DNS query timed out."],
                "evidence_references": [{"diagnostic": "dns"}],
            }],
            "supporting_findings": [{
                "diagnostic": "dns",
                "status": "investigate",
                "finding": "Query timed out.",
            }],
            "conflicts": [],
        },
        "configuration_snapshot": {
            "ip_address": "192.168.1.20",
            "dns_servers": ["192.168.1.1"],
        },
        "results": [{
            "title": "DNS Resolution",
            "analysis": {
                "status": "investigate",
                "severity": "Needs investigation",
                "finding": "DNS query timed out.",
                "evidence": [{"query": "example.com"}],
                "hypotheses": [{"cause": "Resolver unavailable"}],
                "next_tests": [{"test": "Query resolver"}],
                "verification": ["Repeat lookup."],
            },
            "details": "resolver output",
        }],
    }


def test_html_report_includes_summary_findings_and_evidence():
    report = build_diagnostic_report_html(sample_scan())

    assert "Network Diagnostic Report" in report
    assert "DNS resolution failed." in report
    assert "DNS server unavailable" in report
    assert "192.168.1.20" in report
    assert "resolver output" in report
    assert "Recommended next step" in report


def test_html_report_escapes_untrusted_scan_content():
    scan = sample_scan()
    scan["overall_finding"] = "<script>alert('xss')</script>"
    scan["results"][0]["details"] = "<img src=x onerror=alert(1)>"

    report = build_diagnostic_report_html(scan)

    assert "<script>" not in report
    assert "&lt;script&gt;" in report
    assert "<img src=x" not in report
    assert "&lt;img src=x" in report


def test_html_report_handles_missing_optional_sections():
    scan = {
        "results": [],
        "correlation": {},
    }

    report = build_diagnostic_report_html(scan)

    assert "No likely causes" in report
    assert "No configuration snapshot" in report
    assert "No diagnostic results" in report


def test_json_report_preserves_full_scan_record():
    scan = sample_scan()

    report = json.loads(build_diagnostic_report_json(scan))

    assert report == scan
    assert report["results"][0]["analysis"]["evidence"][0]["query"] == "example.com"


@pytest.mark.parametrize("invalid_scan", [{}, {"results": None}, None])
def test_report_builders_reject_invalid_scan(invalid_scan):
    with pytest.raises(ValueError, match="results list"):
        build_diagnostic_report_html(invalid_scan)
    with pytest.raises(ValueError, match="results list"):
        build_diagnostic_report_json(invalid_scan)
