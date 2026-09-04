"""
anomaly.py — The "AI layer".

A single IsolationForest scores each flow's feature vector for how anomalous
it looks against a rolling baseline of recently seen traffic. This is
intentionally small: one model, one job — produce a 0-100 anomaly score to
feed into the correlation step alongside the rule engine. No training
pipeline, no persistence — it bootstraps on synthetic "ordinary traffic" at
startup and adapts by periodically refitting on a rolling buffer of real
flows, which stands in for the "Adaptive Baseline" requirement without
needing an offline training job.
"""
import random
from collections import deque
from typing import Deque, List

from sklearn.ensemble import IsolationForest

# feature order every caller must respect:
# [rate, unique_dst_ports, unique_dst_ips, avg_bytes_per_flow, duration_ms, packet_count]
FEATURE_NAMES = ["rate", "unique_ports", "unique_dsts", "avg_bytes", "duration_ms", "packet_count"]


class AnomalyScorer:
    def __init__(self, retrain_every: int = 300, buffer_size: int = 1000, seed: int = 42):
        self.model = IsolationForest(n_estimators=64, contamination=0.05, random_state=seed)
        self.buffer: Deque[List[float]] = deque(maxlen=buffer_size)
        self.retrain_every = retrain_every
        self._seen_since_fit = 0
        self._rng = random.Random(seed)
        self._bootstrap()

    def _bootstrap(self) -> None:
        """Seed the model with synthetic 'ordinary' flows so it scores sensibly
        from the very first real flow, before any adaptive refit has happened."""
        seed_data = [
            [
                max(0.0, self._rng.gauss(2, 1)),     # rate (flows/sec)
                max(0, self._rng.gauss(3, 2)),        # unique dst ports
                max(0, self._rng.gauss(3, 2)),        # unique dst ips
                max(0.0, self._rng.gauss(500, 300)),  # avg bytes/flow
                max(0.0, self._rng.gauss(200, 150)),  # duration ms
                max(0.0, self._rng.gauss(10, 5)),     # packet count
            ]
            for _ in range(200)
        ]
        self.model.fit(seed_data)
        self.buffer.extend(seed_data)

    def score(self, features: List[float]) -> float:
        """Return an anomaly score in [0, 100]; higher = more anomalous.

        NOTE: the -raw*100 normalization is a simple, cheap heuristic tuned for
        demo-scale traffic. For production you'd calibrate this against a real
        traffic sample (e.g. percentile-rank the raw scores) rather than a
        fixed linear scale.
        """
        raw = self.model.score_samples([features])[0]  # higher raw -> more "normal"
        anomaly = max(0.0, min(100.0, -raw * 100))

        self.buffer.append(features)
        self._seen_since_fit += 1
        if self._seen_since_fit >= self.retrain_every:
            self.model.fit(list(self.buffer))  # cheap: a few hundred x 6 floats
            self._seen_since_fit = 0

        return anomaly
