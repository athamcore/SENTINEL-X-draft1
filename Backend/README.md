# SENTINEL-X

Passive, AI-assisted network threat-intelligence engine (SIH26145).

Watches mirrored/diode traffic metadata, scores it against an adaptive
per-host baseline with a hybrid rule + IsolationForest engine, and emits
structured alerts. **Read-only by design** — it never sends a packet back
onto the monitored network.

## Project layout

```
sentinel-x/
├── main.py                    # FastAPI app: /ingest, /alerts, /metrics
├── schemas.py                 # TrafficFlow (in) / Alert (out) — Pydantic models
├── detector.py                # ThreatDetector — baselines + rule engine (the brain)
├── anomaly.py                 # IsolationForest wrapper — the "AI layer"
├── demo_traffic_generator.py  # optional: posts synthetic attack traffic for a live demo
└── requirements.txt
```

No ORM, no external database — state is plain Python `dict`/`deque` objects
in `ThreatDetector`, which *is* the in-memory database for this prototype.
Every rolling window is time-pruned and length-capped, so memory stays
bounded no matter how long the stream runs.

## Run it

```bash
pip install -r requirements.txt
uvicorn main:app --reload
```

API docs at `http://127.0.0.1:8000/docs`.

In a second terminal, fire synthetic attack traffic at it and watch alerts
appear:

```bash
python demo_traffic_generator.py
```

## Pipeline

1. **Ingestion** — `POST /ingest` accepts a JSON list of `TrafficFlow`
   records (flow ID, timestamps, IPs, port, protocol, duration, packets,
   bytes) — the shape of a mirrored NetFlow feed.
2. **Feature extraction** — for every flow, `RollingWindow` (a 60s
   self-pruning sliding window per IP) computes rate, port/IP diversity,
   average payload size, and total bytes in O(1) amortized time.
3. **Adaptive baseline** — `ThreatDetector.by_src` / `by_dst` hold one
   `RollingWindow` per host, built lazily as traffic arrives; a
   `beacon_history` dict tracks per-(src,dst) timestamps for periodicity.
   `AnomalyScorer` periodically refits its IsolationForest on a rolling
   buffer of recent feature vectors, so the "normal" baseline drifts with
   real traffic instead of staying fixed.
4. **Hybrid detection** — six rule-based detectors (below) each emit a
   0–100 rule score; an IsolationForest anomaly score (0–100) is computed
   once per flow from the same feature vector.
5. **Evidence correlation** — `confidence = 0.65 × rule_score + 0.35 ×
   ml_score`, capped at 100. Alerts below 50% confidence are dropped as
   noise. Repeat matches on the same (src, dst, class) within 30s are
   deduplicated so an ongoing attack doesn't flood the feed.
6. **Alert generation** — a standardized `Alert`: threat class, confidence,
   src/dst, and a short evidence trail (which rule fired + the ML score).

## Detected threat classes

| Class | Core signal |
|---|---|
| **Recon/Port Scanning** | one source, ≥15 distinct dst ports in 60s, tiny avg packet size |
| **DDoS** | flow rate or distinct-source count converging on one destination exceeds threshold |
| **C2 Beaconing** | connections to the same *external* host at low-variance (CV ≤ 0.15) intervals |
| **Encrypted Malware** | same beacon regularity, but on a TLS-family port (443/8443/993/995/465) |
| **DGA/DNS Tunnelling** | oversized DNS payloads and/or high fan-out to distinct resolvers on port 53 |
| **Data Exfiltration** | a single flow or cumulative window volume from one host crosses a byte threshold |

Beaconing/encrypted-malware checks are scoped to **external (non-RFC1918)**
destinations — regular timing to internal infrastructure (health checks,
monitoring agents) is normal and would otherwise look identical to a beacon.
This is a known limitation of timing-only beacon detection worth calling out
in a demo: it reduces false positives but doesn't eliminate them, since
some internal-facing "benign" tools also poll on a fixed clock. Thresholds
in `detector.py` are grouped at the top of the file for easy retuning.

## API

### `POST /ingest`
```bash
curl -X POST http://127.0.0.1:8000/ingest \
  -H "Content-Type: application/json" \
  -d '[{
        "flow_id": "f1",
        "timestamp": "2026-09-05T10:00:00Z",
        "src_ip": "10.0.0.5",
        "dst_ip": "203.0.113.10",
        "dst_port": 443,
        "protocol": "TCP",
        "duration_ms": 120,
        "packet_count": 6,
        "byte_count": 900
      }]'
```
Always send a JSON list, even for one flow — keeps the endpoint's shape
consistent for streaming/batch callers alike.

### `GET /alerts?limit=50&threat_class=DDoS`
Latest alerts, newest first. `threat_class` is optional (values match the
table above, e.g. `Recon/Port Scanning`, `Data Exfiltration`).

### `GET /metrics`
```json
{
  "uptime_seconds": 42.1,
  "flows_processed": 218,
  "flows_per_second": 5.18,
  "total_alerts": 6,
  "alerts_by_class": {"DDoS": 2, "Recon/Port Scanning": 1},
  "tracked_source_hosts": 14
}
```

## Notes for extending this prototype

- **Scaling out**: state currently lives in one process. For a real
  deployment, swap the in-memory dicts for Redis (rolling windows) and a
  time-series/alert store — the `ThreatDetector` interface (`process(flow)
  -> List[Alert]`) wouldn't need to change.
- **Retuning**: all thresholds live at the top of `detector.py`;
  `RULE_WEIGHT`/`ML_WEIGHT` control how much the ML layer can move the
  needle vs. the rules.
- **Calibration**: `AnomalyScorer`'s raw→0-100 mapping is a simple linear
  heuristic for demo purposes — see the note in `anomaly.py` for how you'd
  calibrate it against real traffic (percentile ranking instead of a fixed
  scale).
