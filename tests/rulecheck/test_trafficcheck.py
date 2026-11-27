"""The 7-day traffic finding Keeps Getting Blocked (D-1088) on made-up rows.
Run: python tests/rulecheck/test_trafficcheck.py app"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "app")))
from trafficcheck import traffic_findings  # noqa: E402

NOW = 1795800000.0
DAY = 86400
fails, checks = [], 0


def check(name, cond):
    global checks
    checks += 1
    if not cond:
        fails.append(name)


side = lambda mac, name, ip: {"mac": mac, "name": name, "ips": [ip]}
SIDES = {s["mac"]: s for s in [side("NAS", "NAS 1", "192.168.1.254"), side("CAM1", "Camera 1", "192.168.1.11"),
                               side("CAM2", "Camera 2", "192.168.1.12"), side("CAM3", "Camera 3", "192.168.1.13"),
                               side("SPK", "Speaker 1", "192.168.1.50"), side("FAN", "Fan 1", "192.168.1.43"),
                               side("TV", "TV 1", "192.168.1.60"), side("PC", "PC 1", "192.168.1.10")]}
row = lambda src, dst, outcome, proto, port, days_ago, n=5, allowed_by="", blocked_by="", size=1000: (
    src, dst, outcome, proto, port, n, n, size, NOW - days_ago * DAY, allowed_by, blocked_by)
OLD = row("PC", "NAS", "allowed", "tcp", "445", 6.8)   # makes the rows hold a week

rows = [OLD,
        row("NAS", "CAM1", "allowed", "tcp", "554", 1, allowed_by="955"), row("NAS", "CAM1", "allowed", "tcp", "2020", 2, allowed_by="955"),
        row("NAS", "CAM2", "allowed", "tcp", "554", 1, allowed_by="955,12"),
        row("NAS", "CAM3", "allowed", "tcp", "40000", 1, allowed_by="955")] \
    + [row("NAS", "PC", "allowed", "tcp", str(p), 1, allowed_by="960") for p in range(1, 10)] \
    + [row("SPK", "FAN", "blocked", "tcp", "9999", d, blocked_by="961") for d in (0.2, 1.2, 2.2, 3.2)] \
    + [row("SPK", "FAN", "blocked", "udp", "1900", d) for d in (0.2, 1.2)] \
    + [row("TV", "PC", "blocked", "tcp", "8009", d) for d in (0.2, 1.2, 2.2, 4.2)] \
    + [row("TV", "PC", "unanswered", "tcp", "8010", d) for d in (0.2, 1.2, 2.2)] \
    + [row("TV", "NAS", "blocked", "udp", "50000", d) for d in (0.2, 1.2, 2.2)]     + [row("PC", "CAM1", "blocked", "udp", "20002", d, n=16, size=0) for d in (0.2, 1.2, 2.2, 3.2)]     + [row("PC", "CAM2", "blocked", "udp", "20002", d, n=16, size=0) for d in (0.2, 1.2, 2.2, 3.2)]
# What the rules say (Policy's verdict): PC may reach Camera 1 (the tries were a camera not
# answering, D-906), Camera 2 is unclear; everything else here is blocked.
SAY = {("PC", "CAM1"): "allowed", ("PC", "CAM2"): "unclear"}
say = lambda src, dst, protocol, port: SAY.get((src, dst), "blocked")
found = traffic_findings(rows, SIDES, {"TV|PC|tcp 8009"}, say, NOW)
by = {f["id"]: f for f in found}
check("a week: findings made", found is not None)
b = by.get("traffic|blocked|SPK|FAN")
check("Speaker -> Fan blocked on 4 days: found", b is not None)
check("only the port tried on 3+ days", b and b["sig"] == "tcp:9999")
check("kept blocked on Policy: not found", "traffic|blocked|TV|PC" not in by)
check("high ports never count", "traffic|blocked|TV|NAS" not in by)
check("rules allow the pair: not a block (D-906)", "traffic|blocked|PC|CAM1" not in by)
check("rules unclear: not claimed", "traffic|blocked|PC|CAM2" not in by)
check("each says what it rests on", all(any(k == "Rests On" for k, _ in f["facts"]) for f in found))
check("steps numbered text", all(f["steps"] and all(isinstance(s, str) for s in f["steps"]) for f in found))

short = [r for r in rows if r is not OLD]
check("under a week: waits (None)", traffic_findings(short, SIDES, set(), say, NOW) is None)
check("no rows: waits (None)", traffic_findings([], SIDES, set(), say, NOW) is None)
print("\n".join(fails) or f"all {checks} pass")
sys.exit(1 if fails else 0)
