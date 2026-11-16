from langgraph.graph import END, START, StateGraph

from soc_triage.agents import analyst_node, enrich_node, report_node, triage_node
from soc_triage.state import TriageState


def route_after_triage(state: TriageState) -> str:
    """Low-severity alerts skip enrichment and analysis."""
    if state.get("severity") == "low":
        return "write_report"
    return "enrich"


def build_graph():
    g = StateGraph(TriageState)

    g.add_node("triage", triage_node)
    g.add_node("enrich", enrich_node)
    g.add_node("analyze", analyst_node)
    g.add_node("write_report", report_node)

    g.add_edge(START, "triage")
    g.add_conditional_edges(
        "triage",
        route_after_triage,
        {"enrich": "enrich", "write_report": "write_report"},
    )
    g.add_edge("enrich", "analyze")
    g.add_edge("analyze", "write_report")
    g.add_edge("write_report", END)

    return g.compile()