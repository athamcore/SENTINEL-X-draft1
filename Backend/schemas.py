"""
schemas.py — Wire formats for SENTINEL-X.

Two shapes only: what comes IN (TrafficFlow, off the mirror/diode feed) and
what goes OUT (Alert, to the analyst dashboard). Kept deliberately small —
this is a passive sensor, not a general data model.
"""
from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class Protocol(str, Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"


class TrafficFlow(BaseModel):
    """One NetFlow-style record. Metadata only — SENTINEL-X never sees payload,
    consistent with operating behind a one-way data diode."""

    flow_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    src_ip: str
    dst_ip: str
    dst_port: int = Field(ge=0, le=65535)
    protocol: Protocol
    duration_ms: float = Field(ge=0)
    packet_count: int = Field(ge=0)
    byte_count: int = Field(ge=0)


class ThreatClass(str, Enum):
    DDOS = "DDoS"
    PORT_SCAN = "Recon/Port Scanning"
    C2_BEACONING = "C2 Beaconing"
    DGA_DNS_TUNNELING = "DGA/DNS Tunnelling"
    ENCRYPTED_MALWARE = "Encrypted Malware"
    DATA_EXFILTRATION = "Data Exfiltration"


class Alert(BaseModel):
    """Standardized output alert — rule findings + ML anomaly score, correlated
    into a single confidence figure the dashboard can sort/filter on."""

    alert_id: str
    timestamp: datetime
    threat_class: ThreatClass
    confidence: float = Field(ge=0, le=100)
    src_ip: str
    dst_ip: str
    dst_port: Optional[int] = None
    evidence: List[str]
    rule_score: float
    ml_anomaly_score: float
