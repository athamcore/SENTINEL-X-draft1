"""
main.py — SENTINEL-X API layer.

Three endpoints, matching the pipeline exactly:
  POST /ingest   feed traffic-flow records in from the passive mirror/diode
  GET  /alerts   read the latest generated alerts (dashboard feed)
  GET  /metrics  basic throughput / detection counters

No auth, no DB, no background workers — this is a local prototype. State is
one ThreatDetector instance held in process memory (see detector.py).

Run it with:
    uvicorn main:app --reload
"""
import time
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from detector import ThreatDetector
from schemas import Alert, ThreatClass, TrafficFlow

app = FastAPI(
    title="SENTINEL-X",
    description="Passive, AI-assisted network threat-intelligence engine (SIH26145). "
    "Read-only by design: it watches mirrored/diode traffic and emits alerts — "
    "it never talks back to the monitored network.",
    version="0.1.0",
)

# Permissive CORS so a local dashboard can call this API during a demo. This
# only affects who may READ from the API over HTTP; it has no bearing on the
# passive network tap itself, which remains strictly one-way.
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)

detector = ThreatDetector()
START_TIME = time.time()


@app.get("/")
def health() -> dict:
    return {"status": "SENTINEL-X online", "mode": "passive-monitor"}


@app.post("/ingest")
def ingest(flows: List[TrafficFlow]) -> dict:
    """Accept a batch of traffic-flow records and run them through the
    detection engine. Always send a JSON list — even a single flow should be
    a one-item list — so the endpoint has one consistent, streaming-friendly
    shape regardless of batch size."""
    if not flows:
        raise HTTPException(status_code=400, detail="Empty flow batch")

    generated = 0
    for flow in flows:
        generated += len(detector.process(flow))

    return {"received": len(flows), "alerts_generated": generated}


@app.get("/alerts", response_model=List[Alert])
def get_alerts(
    limit: int = Query(50, ge=1, le=500, description="Max alerts to return"),
    threat_class: Optional[ThreatClass] = Query(None, description="Filter by threat class"),
) -> List[Alert]:
    """Latest alerts, newest first — this is what the dashboard polls."""
    alerts = list(detector.alerts)[::-1]
    if threat_class is not None:
        alerts = [a for a in alerts if a.threat_class == threat_class]
    return alerts[:limit]


@app.get("/metrics")
def get_metrics() -> dict:
    """Basic operational counters for the dashboard header / health panel."""
    uptime = max(time.time() - START_TIME, 1e-6)
    return {
        "uptime_seconds": round(uptime, 1),
        "flows_processed": detector.flow_count,
        "flows_per_second": round(detector.flow_count / uptime, 2),
        "total_alerts": len(detector.alerts),
        "alerts_by_class": dict(detector.alerts_by_class),
        "tracked_source_hosts": len(detector.by_src),
    }
