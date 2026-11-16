from soc_triage.graph import route_after_triage


def test_low_severity_skips_enrichment():
    assert route_after_triage({"severity": "low"}) == "write_report"


def test_other_severities_go_to_enrichment():
    for sev in ["medium", "high", "critical"]:
        assert route_after_triage({"severity": sev}) == "enrich"