from typing import TypedDict


class TriageState(TypedDict, total=False):
    """Shared notebook that every agent reads from and writes to."""

    alert: dict               # the raw alert from the API
    severity: str             # low / medium / high / critical
    category: str             # e.g. "brute force login"
    iocs: list                # indicators found in the alert
    triage_summary: str       # one-line summary from triage
    enrichment: list          # raw threat-intel results
    enrichment_notes: str     # enrichment agent's written findings
    verdict: str              # true_positive / false_positive / needs_human_review
    confidence: int           # 0-100
    reasoning: str            # why the analyst decided this
    recommended_actions: list # next steps for a human
    report: str               # the final incident report (Markdown)