from typing import TypedDict


class TriageState(TypedDict, total=False):
    """Shared notebook that every agent reads from and writes to."""

    alert: dict          #  raw alert from  API
    severity: str        # low / medium / high / critical
    category: str        # ex. brute force, malware, phishing
    iocs: list           # indicators found
    triage_summary: str  # one-line summary
    enrichment: list     # threat-intel results
    verdict: str         # final decision
    confidence: int      # 0-100
    report: str          # incident report