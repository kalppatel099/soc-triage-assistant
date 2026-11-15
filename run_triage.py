import time

import httpx

from soc_triage.agents import triage_node
from soc_triage.config import MOCK_API_URL

alerts = httpx.get(f"{MOCK_API_URL}/alerts", timeout=10).json()

for alert in alerts:
    print(f"\n=== {alert['id']} ({alert['type']}) ===")
    result = triage_node({"alert": alert})
    for key, value in result.items():
        print(f"{key}: {value}")
    time.sleep(4)  # stay under the free-tier rate limit