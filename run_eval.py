import time
from pathlib import Path
import json

import httpx

from main import run_with_retry
from soc_triage.config import MOCK_API_URL
from soc_triage.graph import build_graph

expected = json.loads(Path("eval/expected.json").read_text(encoding="utf-8"))
alerts = httpx.get(f"{MOCK_API_URL}/alerts", timeout=10).json()
app = build_graph()

rows = []
for alert in alerts:
    exp = expected.get(alert["id"])
    if exp is None:
        continue
    print(f"Running {alert['id']} ...")
    result = run_with_retry(app, alert)

    severity = result.get("severity")
    verdict = result.get("verdict", "none")
    report = result.get("report", "")
    problems = []

    if "severity_in" in exp and severity not in exp["severity_in"]:
        problems.append(f"severity '{severity}' not in {exp['severity_in']}")
    if "verdict_in" in exp and verdict not in exp["verdict_in"]:
        problems.append(f"verdict '{verdict}' not in {exp['verdict_in']}")
    if exp.get("must_call_tool") and not result.get("enrichment"):
        problems.append("no threat-intel tool was called")
    for phrase in exp.get("forbidden_in_report", []):
        if phrase.lower() in report.lower():
            problems.append(f"report leaked: '{phrase}'")

    rows.append((alert["id"], alert["type"], severity, verdict, problems))
    time.sleep(3)

lines = ["| Alert | Type | Severity | Verdict | Result |", "|---|---|---|---|---|"]
for alert_id, kind, sev, ver, problems in rows:
    status = "PASS" if not problems else "FAIL: " + "; ".join(problems)
    lines.append(f"| {alert_id} | {kind} | {sev} | {ver} | {status} |")

passed = sum(1 for r in rows if not r[4])
lines.append("")
lines.append(f"**{passed}/{len(rows)} passed**")

output = "\n".join(lines)
print("\n" + output)
Path("eval/results.md").write_text(output + "\n", encoding="utf-8")