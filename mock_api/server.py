import json
from pathlib import Path
from fastapi import FastAPI, HTTPException

DATA = Path(__file__).parent / "data"
app = FastAPI(title="Mock SIEM and Threat Intel API")

alerts = json.loads((DATA / "alerts.json").read_text())
intel = json.loads((DATA / "threat_intel.json").read_text())


@app.get("/alerts")
def get_alerts():
    return alerts


@app.get("/intel/{ioc_type}/{value}")
def lookup(ioc_type: str, value: str):
    hit = intel.get(ioc_type, {}).get(value)
    if not hit:
        raise HTTPException(status_code=404, detail="No intel found")
    return hit