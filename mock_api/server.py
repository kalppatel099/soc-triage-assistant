import json
from pathlib import Path
from fastapi import FastAPI, HTTPException

DATA = Path(__file__).parent / "data"
app = FastAPI(title="Mock SIEM and Threat Intel API")


def load_json(name):
    # utf-8-sig tolerates the invisible BOM that Windows editors add
    return json.loads((DATA / name).read_text(encoding="utf-8-sig"))


alerts = load_json("alerts.json")
intel = load_json("threat_intel.json")


@app.get("/alerts")
def get_alerts():
    return alerts


@app.get("/intel/{ioc_type}/{value}")
def lookup(ioc_type: str, value: str):
    hit = intel.get(ioc_type, {}).get(value)
    if not hit:
        raise HTTPException(status_code=404, detail="No intel found")
    return hit
