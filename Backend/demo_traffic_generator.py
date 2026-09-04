"""
demo_traffic_generator.py — Optional demo helper, not part of the core service.

Posts a mix of benign and attack-pattern traffic to a running SENTINEL-X
instance so you can watch alerts appear live. Run the API first:

    uvicorn main:app --reload

...then in another terminal:

    python demo_traffic_generator.py
"""
import time
from datetime import datetime, timedelta, timezone

import httpx

API = "http://127.0.0.1:8000"


def flow(fid, t, src, dst, port, proto="TCP", dur=50, pkts=5, byt=500):
    return {
        "flow_id": fid,
        "timestamp": t.isoformat(),
        "src_ip": src,
        "dst_ip": dst,
        "dst_port": port,
        "protocol": proto,
        "duration_ms": dur,
        "packet_count": pkts,
        "byte_count": byt,
    }


def build_batches():
    base = datetime.now(timezone.utc)
    batches = []

    # 1. Benign background traffic — regular internal chatter, should stay clean
    batches.append(("benign browsing", [
        flow(f"norm{i}", base + timedelta(seconds=i * 3.7), "10.0.0.200", "10.0.0.1", 443,
             dur=120, pkts=8, byt=1400)
        for i in range(6)
    ]))

    # 2. Port scan — one host probing many ports with tiny packets
    batches.append(("port scan", [
        flow(f"ps{i}", base + timedelta(milliseconds=i * 20), "10.0.0.5", "10.0.0.9", 2000 + i,
             dur=1, pkts=1, byt=60)
        for i in range(25)
    ]))

    # 3. DDoS — many sources flooding one destination
    batches.append(("ddos flood", [
        flow(f"ddos{i}", base + timedelta(milliseconds=i * 10), f"172.16.0.{i % 60}",
             "203.0.113.10", 80, dur=5, pkts=3, byt=200)
        for i in range(80)
    ]))

    # 4. C2 beaconing — regular external callbacks
    batches.append(("c2 beaconing", [
        flow(f"c2{i}", base + timedelta(seconds=30 * i), "10.0.0.42", "185.220.101.45", 8080,
             dur=50, pkts=4, byt=180)
        for i in range(8)
    ]))

    # 5. DNS tunneling — oversized queries fanned out to many resolvers
    batches.append(("dns tunneling", [
        flow(f"dns{i}", base + timedelta(milliseconds=i * 100), "10.0.0.15",
             f"45.33.{i % 20}.{i % 250}", 53, proto="UDP", dur=10, pkts=1, byt=420)
        for i in range(15)
    ]))

    # 6. Data exfiltration — one abnormally large outbound flow
    batches.append(("data exfiltration", [
        flow("exfil1", base, "10.0.0.88", "203.0.113.55", 443,
             dur=4000, pkts=50000, byt=80_000_000)
    ]))

    return batches


def main():
    with httpx.Client(timeout=10) as client:
        try:
            client.get(f"{API}/")
        except httpx.ConnectError:
            print(f"Could not reach {API} — start the server first: uvicorn main:app --reload")
            return

        for label, flows in build_batches():
            resp = client.post(f"{API}/ingest", json=flows)
            resp.raise_for_status()
            result = resp.json()
            print(f"[{label:18}] sent {result['received']:3} flows -> "
                  f"{result['alerts_generated']} alert(s)")
            time.sleep(0.3)

        print("\n--- latest alerts ---")
        alerts = client.get(f"{API}/alerts", params={"limit": 10}).json()
        for a in alerts:
            print(f"  [{a['confidence']:5.1f}%] {a['threat_class']:22} "
                  f"{a['src_ip']:>15} -> {a['dst_ip']}")

        print("\n--- metrics ---")
        print(client.get(f"{API}/metrics").json())


if __name__ == "__main__":
    main()
