from soc_triage.agents import report_node


class FakeLLM:
    def invoke(self, messages):
        class Reply:
            content = "Fake summary."

        return Reply()


def test_low_severity_report_never_invents_a_verdict(monkeypatch):
    monkeypatch.setattr("soc_triage.agents.get_llm", lambda: FakeLLM())
    state = {"alert": {"id": "T-1", "type": "failed_login"}, "severity": "low"}
    report = report_node(state)["report"]
    assert "Not assessed" in report
    assert "Confidence" not in report


def test_assessed_report_copies_verdict_and_confidence(monkeypatch):
    monkeypatch.setattr("soc_triage.agents.get_llm", lambda: FakeLLM())
    state = {
        "alert": {"id": "T-2", "type": "suspicious_login"},
        "severity": "high",
        "verdict": "true_positive",
        "confidence": 90,
        "reasoning": "Because.",
        "iocs": [{"type": "ip", "value": "1.2.3.4"}],
        "recommended_actions": ["Block IP"],
        "enrichment": [
            {"tool": "lookup_ip", "input": {"ip": "1.2.3.4"}, "result": {"reputation": "malicious"}}
        ],
    }
    report = report_node(state)["report"]
    assert "True Positive" in report
    assert "90%" in report
    assert "Block IP" in report