# TRAFFIC FINDINGS (Network Assessment, the 7-day tier of D-1072; chosen by
# the owner 27 Nov 2026, D-1088). Made from a full week of your own local
# traffic (local_traffic_hourly keeps 7 days), and only once it holds one:
#   keeps_blocked    one client's tries at another, blocked by your rules on
#                    TRAFFIC_BLOCKED_DAYS or more of the 7 days, on the same
#                    port: it needs an Allow, or the device should stop
#                    trying. Tries at a client not answering never count
#                    (D-913); nor do pairs you decided to keep blocking on
#                    Policy, nor random high ports. Only where your rules
#                    block that pair on that port, asked as Policy asks
#                    them: a try the router couldn't deliver (no rule
#                    named, nothing sent) where your rules allow the pair
#                    is a client not answering, not a block (D-906; 27 Nov
#                    2026: a phone -> two cameras on UDP 20002 was
#                    reported before this, Policy rightly left it out).
# Ports a rule opens wider than used are not checked here: Open But Unused
# does that (Partly Used, Narrow It) and the assessment lists its rows
# (D-1072: it feeds the assessment rather than a second checker).
from datetime import datetime

TRAFFIC_DAYS = 7
TRAFFIC_COVER_SECONDS = 6.5 * 86400   # the oldest row must be this old: a week, give or take the hour rows
TRAFFIC_BLOCKED_DAYS = 3
TRAFFIC_ORDER = ("keeps_blocked",)


def traffic_covered(rows, now):
    """Whole days of traffic the rows rest on (0 when there are none)."""
    oldest = min((r[8] for r in rows if r[8]), default=None)
    return 0 if oldest is None else int((now - oldest) // 86400)


def traffic_findings(rows, sides, blocked_keys, rules_say, now):
    """rows: access_local_rows(7 days); sides: access_sides()[0];
    blocked_keys: Policy's "src|dst|port_key" pairs you decided to keep blocking;
    rules_say(src, dst, protocol, port): "allowed", "blocked", "unclear" or
    "unknown" for that pair and port (Policy's check_local_access verdict).
    -> ({id, kind, tone, title, facts, steps, sig}, ...), or None while the
    rows don't hold a full week yet."""
    if not rows or now - min((r[8] for r in rows if r[8]), default=now) < TRAFFIC_COVER_SECONDS:
        return None
    rests = f"{TRAFFIC_DAYS} days of your traffic"   # a full week, whatever minute the hour rows start at
    name = lambda mac: (sides.get(mac) or {}).get("name") or mac
    out = []

    # Keeps Getting Blocked: one finding per pair, with the ports tried.
    tried = {}
    for src, dst, outcome, protocol, port, n, _rec, _size, last, _ab, _bb in rows:
        if outcome != "blocked" or not port or not str(port).isdigit() or int(port) >= 32768 or not last:
            continue
        protocol = str(protocol or "").lower()
        if f"{src}|{dst}|{protocol} {port}" in blocked_keys:
            continue
        x = tried.setdefault((src, dst), {}).setdefault((protocol, int(port)), {"days": set(), "tries": 0})
        x["days"].add(datetime.fromtimestamp(last).date())
        x["tries"] += n or 0
    for (src, dst), ports in sorted(tried.items(), key=lambda t: (name(t[0][0]).lower(), name(t[0][1]).lower())):
        often = sorted(p for p, x in ports.items() if len(x["days"]) >= TRAFFIC_BLOCKED_DAYS and rules_say(src, dst, *p) == "blocked")
        if not often:
            continue
        words = ", ".join(f"{p[0].upper()} {p[1]} ({len(ports[p]['days'])} days, {ports[p]['tries']:,} tries)" for p in often)
        a, b = name(src), name(dst)
        out.append({"id": f"traffic|blocked|{src}|{dst}", "kind": "keeps_blocked", "tone": "warn",
                    "title": f"{a} keeps getting blocked trying {b}",
                    "facts": [["Tries", words], ["Rests On", rests],
                              ["Why It Matters", f"Your rules block it, and {a} tries again day after day: either it needs this to work (then it needs an Allow), or something on {a} is set to reach {b} and should be switched off."],
                              ["What To Do", f"Decide on New Connections Review: Allow (it gives the exact steps) or Keep Blocking (this finding then goes)."]],
                    "steps": [f"Open New Connections Review and find {a} → {b} on {', '.join(f'{p[0].upper()} {p[1]}' for p in often)}",
                              f"If {a} should reach {b}: press Allow and follow its Show Me How steps",
                              f"If not: press Keep Blocking there; if the tries bother you, switch off the feature on {a} that makes them (casting, discovery, a linked device in its app)",
                              "Check this page again: this goes once it is decided or the tries stop"],
                    "sig": ",".join(f"{p[0]}:{p[1]}" for p in often)})

    return out
