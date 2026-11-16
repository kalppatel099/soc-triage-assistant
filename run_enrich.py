import json
import time

import httpx

from soc_triage.agents import enrich_node, triage_node
from soc_triage.config import MOCK_API_URL

alerts = httpx.get(f"{MOCK_API_URL}/alerts", timeout=10).json()

for alert in alerts:
    print(f"\n=== {alert['id']} ({alert['type']}) ===")
    state = {"alert": alert}
    state.update(triage_node(state))
    print("severity:", state["severity"], "| iocs:", state["iocs"])
    time.sleep(3)

    state.update(enrich_node(state))
    print("tools the model chose to call:")
    for e in state["enrichment"]:
        print("  ", e["tool"], e["input"], "->", json.dumps(e["result"]))
    print("notes:", state["enrichment_notes"])
    time.sleep(3)