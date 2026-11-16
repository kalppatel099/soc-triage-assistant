import time
from pathlib import Path

import httpx

from soc_triage.config import MOCK_API_URL
from soc_triage.graph import build_graph

REPORTS_DIR = Path("reports")


def run_with_retry(app, alert, attempts=3):
    """Free-tier rate limits (429) are normal, so wait and retry."""
    for attempt in range(1, attempts + 1):
        try:
            return app.invoke({"alert": alert})
        except Exception as e:
            if attempt == attempts:
                raise
            print(f"  error ({type(e).__name__}); waiting 30s then retrying...")
            time.sleep(30)


def main():
    REPORTS_DIR.mkdir(exist_ok=True)
    app = build_graph()
    alerts = httpx.get(f"{MOCK_API_URL}/alerts", timeout=10).json()

    for alert in alerts:
        print(f"Processing {alert['id']} ...")
        result = run_with_retry(app, alert)
        path = REPORTS_DIR / f"{alert['id']}.md"
        path.write_text(result["report"], encoding="utf-8")
        print(
            f"  severity={result.get('severity')} "
            f"verdict={result.get('verdict', 'n/a')} "
            f"confidence={result.get('confidence', 'n/a')} -> {path}"
        )
        time.sleep(3)


if __name__ == "__main__":
    main()