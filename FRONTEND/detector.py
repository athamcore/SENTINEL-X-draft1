"""
detector.py — The brain of SENTINEL-X.

ThreatDetector.process(flow) is the single entry point: it updates the
in-memory adaptive baseline, runs the rule engine + ML anomaly scorer, and
returns any Alerts triggered by this one flow. Everything is O(1) amortized
per flow — bounded deques (time-windowed + maxlen) mean memory never grows
unboundedly no matter how long the stream runs.

State lives in plain dicts/deques (no ORM, no DB) — this is the "in-memory
database" for the prototype: fast, dependency-free, and easy to reason about.
"""
import ipaddress
import statistics
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Deque, Dict, List, NamedTuple, Set, Tuple

from anomaly import AnomalyScorer
from schemas import Alert, ThreatClass, TrafficFlow

# ---------------------------------------------------------------------------
# Tunable thresholds — the "rule" half of the hybrid engine. Grouped here so
# a demo/judge can retune sensitivity without hunting through logic.
# ---------------------------------------------------------------------------
WINDOW_SECONDS = 60          # sliding window for rate/diversity baselines
MAX_RECORDS_PER_KEY = 1000   # hard cap so one noisy IP can't grow memory unbounded

PORT_SCAN_PORT_THRESHOLD = 15    # distinct dst ports from one src in the window
PORT_SCAN_MAX_AVG_BYTES = 150    # scans use tiny probe packets

DDOS_RATE_THRESHOLD = 50.0       # flows/sec converging on one destination
DDOS_SRC_THRESHOLD = 20          # distinct sources hitting one destination

BEACON_MIN_SAMPLES = 5           # connections needed before judging regularity
BEACON_CV_THRESHOLD = 0.15       # coefficient of variation (stdev/mean) = "regular"
BEACON_MIN_INTERVAL_S = 3
BEACON_MAX_INTERVAL_S = 3600
BEACON_HISTORY_LEN = 20

DNS_PORT = 53
DNS_TUNNEL_AVG_BYTES = 350        # ordinary DNS queries are small; tunneling isn't
DNS_TUNNEL_UNIQUE_DST_THRESHOLD = 10

ENCRYPTED_PORTS: Set[int] = {443, 8443, 993, 995, 465}

EXFIL_SINGLE_FLOW_BYTES = 50_000_000     # 50 MB in one flow
EXFIL_WINDOW_BYTES = 100_000_000         # 100 MB cumulative from one src in the window

ALERT_CONFIDENCE_THRESHOLD = 50.0  # below this, too weak to surface as an alert
RULE_WEIGHT = 0.65                 # evidence correlation: rules lead, ML corroborates
ML_WEIGHT = 0.35

ALERT_COOLDOWN_SECONDS = 30  # suppress duplicate alerts for the same (src,dst,class)


def _is_private(ip: str) -> bool:
    """True for RFC1918/loopback/link-local addresses. Used to keep beacon
    detection focused on egress to the outside world — regular heartbeats to
    internal infra (monitoring agents, health checks) are normal and would
    otherwise be indistinguishable from C2 by timing alone."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False  # malformed/unparseable -> treat as external, safer default


class FlowRecord(NamedTuple):
    """Lightweight, hashable-free record kept in rolling windows — cheaper
    than storing full TrafficFlow/pydantic objects in hot-path deques."""
    timestamp: datetime
    src_ip: str
    dst_ip: str
    dst_port: int
    byte_count: int
    packet_count: int
    duration_ms: float


class RollingWindow:
    """Fixed-time sliding window of FlowRecords for one key (an IP, in or out).
    Self-pruning on every add, so stats always reflect the last WINDOW_SECONDS
    regardless of how bursty traffic is."""

    __slots__ = ("records", "window_seconds")

    def __init__(self, window_seconds: int = WINDOW_SECONDS):
        self.records: Deque[FlowRecord] = deque(maxlen=MAX_RECORDS_PER_KEY)
        self.window_seconds = window_seconds

    def add(self, record: FlowRecord) -> None:
        self.records.append(record)
        cutoff = record.timestamp - timedelta(seconds=self.window_seconds)
        while self.records and self.records[0].timestamp < cutoff:
            self.records.popleft()

    @property
    def rate(self) -> float:
        return len(self.records) / self.window_seconds

    def unique(self, attr: str) -> int:
        return len({getattr(r, attr) for r in self.records})

    def mean(self, attr: str) -> float:
        vals = [getattr(r, attr) for r in self.records]
        return statistics.fmean(vals) if vals else 0.0

    def total(self, attr: str) -> int:
        return sum(getattr(r, attr) for r in self.records)


class ThreatDetector:
    """Hybrid detection engine: rule triggers -> confidence, corroborated by
    an IsolationForest anomaly score, correlated into one final Alert."""

    def __init__(self) -> None:
        self.by_src: Dict[str, RollingWindow] = defaultdict(RollingWindow)
        self.by_dst: Dict[str, RollingWindow] = defaultdict(RollingWindow)
        self.beacon_history: Dict[Tuple[str, str], Deque[datetime]] = defaultdict(
            lambda: deque(maxlen=BEACON_HISTORY_LEN)
        )
        self.anomaly_scorer = AnomalyScorer()

        self.alerts: Deque[Alert] = deque(maxlen=2000)  # recent alerts for the dashboard
        self.flow_count = 0
        self.alerts_by_class: Dict[str, int] = defaultdict(int)
        self._last_alert_time: Dict[Tuple[str, str, str], datetime] = {}

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------
    def process(self, flow: TrafficFlow) -> List[Alert]:
        record = FlowRecord(
            timestamp=flow.timestamp,
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            dst_port=flow.dst_port,
            byte_count=flow.byte_count,
            packet_count=flow.packet_count,
            duration_ms=flow.duration_ms,
        )

        src_window = self.by_src[record.src_ip]
        dst_window = self.by_dst[record.dst_ip]
        src_window.add(record)
        dst_window.add(record)

        # Beaconing regularity is computed once per flow and reused for both
        # "C2 Beaconing" (plaintext/odd ports) and "Encrypted Malware" (TLS
        # ports) so we never double-count the same timestamp.
        beacon_key = (record.src_ip, record.dst_ip)
        is_regular, beacon_score, beacon_evidence = self._detect_beaconing(beacon_key, record)

        # --- ML anomaly score: one feature vector describing this src's
        # current behaviour, scored against the adaptive baseline. ---
        features = [
            src_window.rate,
            float(src_window.unique("dst_port")),
            float(src_window.unique("dst_ip")),
            src_window.mean("byte_count"),
            record.duration_ms,
            float(record.packet_count),
        ]
        ml_score = self.anomaly_scorer.score(features)

        # --- Rule engine: each detector returns (triggered, rule_score, evidence) ---
        findings: List[Tuple[ThreatClass, float, str]] = []

        ok, score, ev = self._detect_port_scan(src_window)
        if ok:
            findings.append((ThreatClass.PORT_SCAN, score, ev))

        ok, score, ev = self._detect_ddos(dst_window, record)
        if ok:
            findings.append((ThreatClass.DDOS, score, ev))

        if is_regular:
            if record.dst_port in ENCRYPTED_PORTS:
                findings.append((
                    ThreatClass.ENCRYPTED_MALWARE, beacon_score,
                    f"Regular beacon over encrypted channel: {beacon_evidence}",
                ))
            else:
                findings.append((ThreatClass.C2_BEACONING, beacon_score, beacon_evidence))

        ok, score, ev = self._detect_dns_tunneling(src_window, record)
        if ok:
            findings.append((ThreatClass.DGA_DNS_TUNNELING, score, ev))

        ok, score, ev = self._detect_exfiltration(src_window, record)
        if ok:
            findings.append((ThreatClass.DATA_EXFILTRATION, score, ev))

        # --- Evidence correlation: rules + ML -> one confidence per finding ---
        new_alerts: List[Alert] = []
        for threat_class, rule_score, evidence in findings:
            confidence = round(min(100.0, RULE_WEIGHT * rule_score + ML_WEIGHT * ml_score), 1)
            if confidence < ALERT_CONFIDENCE_THRESHOLD:
                continue

            # Cooldown: an ongoing scan/flood/beacon matches on every flow —
            # without this, one attack burst floods the dashboard with near-
            # duplicate alerts instead of one alert that stays current.
            # DDoS is destination-centric (many sources, one victim), so it's
            # deduped per-destination rather than per-(src,dst) like the rest.
            if threat_class is ThreatClass.DDOS:
                dedup_key = ("*", record.dst_ip, threat_class.value)
            else:
                dedup_key = (record.src_ip, record.dst_ip, threat_class.value)
            last_seen = self._last_alert_time.get(dedup_key)
            if last_seen and (record.timestamp - last_seen).total_seconds() < ALERT_COOLDOWN_SECONDS:
                continue
            self._last_alert_time[dedup_key] = record.timestamp

            alert = Alert(
                alert_id=str(uuid.uuid4()),
                timestamp=record.timestamp,
                threat_class=threat_class,
                confidence=confidence,
                src_ip=record.src_ip,
                dst_ip=record.dst_ip,
                dst_port=record.dst_port,
                evidence=[evidence, f"ML anomaly score: {ml_score:.1f}/100"],
                rule_score=round(rule_score, 1),
                ml_anomaly_score=round(ml_score, 1),
            )
            new_alerts.append(alert)
            self.alerts.append(alert)
            self.alerts_by_class[threat_class.value] += 1

        self.flow_count += 1
        return new_alerts

    # ------------------------------------------------------------------
    # Individual detectors — each is intentionally small and self-contained.
    # ------------------------------------------------------------------
    def _detect_port_scan(self, src_window: RollingWindow) -> Tuple[bool, float, str]:
        unique_ports = src_window.unique("dst_port")
        unique_dsts = src_window.unique("dst_ip")
        avg_bytes = src_window.mean("byte_count")
        if unique_ports >= PORT_SCAN_PORT_THRESHOLD and avg_bytes <= PORT_SCAN_MAX_AVG_BYTES:
            excess = (unique_ports - PORT_SCAN_PORT_THRESHOLD) / PORT_SCAN_PORT_THRESHOLD
            score = min(100.0, 55 + excess * 45)
            evidence = (
                f"{unique_ports} distinct ports probed across {unique_dsts} hosts "
                f"in {WINDOW_SECONDS}s, avg {avg_bytes:.0f}B/flow (probe-sized packets)"
            )
            return True, score, evidence
        return False, 0.0, ""

    def _detect_ddos(self, dst_window: RollingWindow, flow: FlowRecord) -> Tuple[bool, float, str]:
        rate = dst_window.rate
        unique_srcs = dst_window.unique("src_ip")
        if rate >= DDOS_RATE_THRESHOLD or unique_srcs >= DDOS_SRC_THRESHOLD:
            excess = max(rate / DDOS_RATE_THRESHOLD, unique_srcs / DDOS_SRC_THRESHOLD) - 1
            score = min(100.0, 55 + max(0.0, excess) * 45)
            evidence = (
                f"{rate:.1f} flows/sec from {unique_srcs} distinct sources converging on "
                f"{flow.dst_ip}:{flow.dst_port}"
            )
            return True, score, evidence
        return False, 0.0, ""

    def _detect_beaconing(
        self, key: Tuple[str, str], flow: FlowRecord
    ) -> Tuple[bool, float, str]:
        hist = self.beacon_history[key]
        hist.append(flow.timestamp)
        if len(hist) < BEACON_MIN_SAMPLES:
            return False, 0.0, ""

        intervals = [(hist[i + 1] - hist[i]).total_seconds() for i in range(len(hist) - 1)]
        mean_iv = statistics.fmean(intervals)
        if mean_iv < BEACON_MIN_INTERVAL_S or mean_iv > BEACON_MAX_INTERVAL_S:
            return False, 0.0, ""

        stdev_iv = statistics.pstdev(intervals)
        cv = (stdev_iv / mean_iv) if mean_iv else 1.0
        if cv <= BEACON_CV_THRESHOLD and not _is_private(key[1]):
            regularity = max(0.0, 1 - cv / BEACON_CV_THRESHOLD)
            score = min(100.0, 60 + regularity * 40)
            evidence = (
                f"{len(hist)} connections {key[0]}->{key[1]} every ~{mean_iv:.1f}s "
                f"(CV={cv:.2f}, near-perfect regularity)"
            )
            return True, score, evidence
        return False, 0.0, ""

    def _detect_dns_tunneling(
        self, src_window: RollingWindow, flow: FlowRecord
    ) -> Tuple[bool, float, str]:
        if flow.dst_port != DNS_PORT:
            return False, 0.0, ""
        dns_records = [r for r in src_window.records if r.dst_port == DNS_PORT]
        if not dns_records:
            return False, 0.0, ""

        avg_bytes = statistics.fmean(r.byte_count for r in dns_records)
        unique_dsts = len({r.dst_ip for r in dns_records})
        if avg_bytes >= DNS_TUNNEL_AVG_BYTES or unique_dsts >= DNS_TUNNEL_UNIQUE_DST_THRESHOLD:
            score = min(100.0, 50 + (avg_bytes / DNS_TUNNEL_AVG_BYTES) * 10 + unique_dsts * 2)
            evidence = (
                f"DNS traffic averaging {avg_bytes:.0f}B/flow to {unique_dsts} distinct "
                f"resolvers — oversized or high-fan-out queries typical of tunneling/DGA"
            )
            return True, score, evidence
        return False, 0.0, ""

    def _detect_exfiltration(
        self, src_window: RollingWindow, flow: FlowRecord
    ) -> Tuple[bool, float, str]:
        cumulative = src_window.total("byte_count")
        if flow.byte_count >= EXFIL_SINGLE_FLOW_BYTES or cumulative >= EXFIL_WINDOW_BYTES:
            ratio = max(flow.byte_count / EXFIL_SINGLE_FLOW_BYTES, cumulative / EXFIL_WINDOW_BYTES)
            score = min(100.0, 55 + max(0.0, ratio - 1) * 45)
            evidence = (
                f"{flow.byte_count / 1e6:.1f}MB in one flow, {cumulative / 1e6:.1f}MB total "
                f"from {flow.src_ip} within {WINDOW_SECONDS}s — abnormal outbound volume"
            )
            return True, score, evidence
        return False, 0.0, ""
