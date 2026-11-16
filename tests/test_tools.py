import httpx

from soc_triage.tools import lookup_ip


class FakeResponse:
    def __init__(self, status_code, data):
        self.status_code = status_code
        self._data = data

    def json(self):
        return self._data


def test_lookup_found(monkeypatch):
    monkeypatch.setattr(
        "soc_triage.tools.httpx.get",
        lambda *a, **k: FakeResponse(200, {"reputation": "malicious"}),
    )
    assert lookup_ip.invoke({"ip": "1.2.3.4"}) == {"reputation": "malicious"}


def test_lookup_not_found(monkeypatch):
    monkeypatch.setattr(
        "soc_triage.tools.httpx.get",
        lambda *a, **k: FakeResponse(404, {}),
    )
    result = lookup_ip.invoke({"ip": "9.9.9.9"})
    assert result["result"] == "no intel found"


def test_feed_unreachable(monkeypatch):
    def boom(*a, **k):
        raise httpx.ConnectError("down")

    monkeypatch.setattr("soc_triage.tools.httpx.get", boom)
    assert "error" in lookup_ip.invoke({"ip": "1.2.3.4"})