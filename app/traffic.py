# Internet pages: Outbound, Internet, Firewalla MSP, Alarms, Test A Website,
# Destinations, Traffic and Device Activity.

import hashlib
import ipaddress
import json
import os
import re
import threading
import time
import traceback
from collections import Counter
from datetime import datetime
import requests
from fastapi import Body, Request
import core

from core import (
    FLOW_HISTORY_HOURS, Fields, StateFileError, app, claude_load, claude_lock, claude_public, msp,
    policy_read_json, public_error, router_ready, state, wan_networks,
)
from router import (
    access_device_protect, compact_policy_rule_for_flow, feature_settings, internet_interface_name,
    policy_rule_for_pid,
)
import router
from flows import (
    INTERNET_TRAFFIC_HOURLY_SECONDS,
    FLOW_METRICS_SQL, INTERNET_TRAFFIC_KEY, flow_history_reader, flow_metrics,
    flush_internet_traffic, flush_local_traffic, internet_day, internet_traffic_connection,
    LOCAL_CONNECTION_GAP, local_connections_open, local_no_port, local_traffic_stats,
    local_traffic_connection, past_days_written, recent_flow_device_name, shared_result,
)
from equipment import (
    EH_WAN_SLOW_MS, eh_wan_events, equipment_health_router_version, fmt_duration_short,
)
from status import (
    api_status_page, wan_peaks_summary, wan_uptime_summary,
)
from access import (
    access_covers, access_local_rules, access_peer_sides, access_rule_text, access_sides, howto_app, howto_fit, howto_reserved, howto_seen,
)
from connections import connections_details, connections_guess, details_load
from policy import (
    LOCAL_PORT_SERVICES, local_block_kind, local_no_client, local_port_label, policy_blocked_text,
)


# ============================================================
# OUTBOUND PAGE: what your devices' internet traffic needs a look at
#
# Built every 5 minutes from the internet traffic totals (agreed flow,
# 13 Nov 2026). Each device's internet traffic goes through, in order:
# 1 Threat lists (dshield, Tor, log4j, newly registered and lookalike
#   domains): To Review once over the threshold for the device type
#   (IoT/cameras/NAS: 1 hit; phones/PCs: Tor/log4j/dshield 5 in 24 h,
#   newly registered 3 domains or 20 hits, lookalike 1), or at once if the
#   same destination was also reached through an allowed route. Below the
#   threshold: counted for the digest.
# 2 Ads, trackers and DoH lists: counted only (DoH from an IoT device is
#   flagged: it hides its lookups).
# 3 Device Active Protect devices: a block of a destination it never used
#   before, or a day with 3x its usual blocks, goes to To Triage.
# 4 Other devices: scored once 14 days are learned (new destination, new
#   country, unusual port, bare IP, upload 10x its usual; IoT weighs more).
#   At the threshold: To Triage, at most 5 a day; below: the Watched log.
# Claude on the NAS assesses each open item by itself (advice shown on
# the item; you decide). Items end as Needs
# Attention (flagged on Status until you mark it handled) or Normal
# (recorded with the reason and learned: the same thing doesn't come back
# unless it grows 10x or, for threat lists, reaches a new destination).
# Each item is tagged with whether Firewalla also alarmed on it; Firewalla
# alarms nothing here matched are listed too. Blocked countries reached
# stay on the Policy page. Kept in /data/outbound_state.json.
# ============================================================

OUTBOUND_STATE_FILE = os.environ.get("FIREWALLA_OUTBOUND_STATE_FILE", "/data/outbound_state.json")
OUTBOUND_CHECK_SECONDS = 300
OUTBOUND_LEARNING_SECONDS = 14 * 86400
OUTBOUND_DAILY_CAP = 5
OUTBOUND_SCORE_THRESHOLD = 4
OUTBOUND_GROWTH_FACTOR = 10
OUTBOUND_ALARM_WINDOW = 3600
OUTBOUND_THREAT_LISTS = {"dshield": "DShield (attack sources)", "tor_full": "Tor network", "tor_exit": "Tor exit nodes",
                         "log4j": "Log4j exploit servers", "nrd": "Newly registered domains",
                         "lookalike_domain": "Lookalike domains"}
OUTBOUND_NOISE_LISTS = {"oisd", "msp-prod-oisd-big-prod", "hagezi-multipro", "msp-prod-goodbye-ads", "doh"}
OUTBOUND_COMMON_PORTS = {"tcp 80", "tcp 443", "udp 443", "udp 53", "tcp 53", "dns 53", "udp 123", "tcp 853",
                         "tcp 5228", "tcp 8883", "udp 3478", "tcp 993", "tcp 587", "tcp 465"}
# Signal -> (weight for IoT, weight for other devices).
OUTBOUND_WEIGHTS = {"new destination": (3, 0.5), "new country": (3, 1.5), "unusual port": (2, 1),
                    "bare IP address": (1, 0.5), "upload 10x its usual": (4, 4)}
OUTBOUND_IOT_WORDS = ("iot", "camera", "nas", "printer", "thermostat")
outbound_lock = threading.RLock()
outbound_cache = {"at": 0, "data": None}


def outbound_state_load():
    """{since, items, flagged}. since: when monitoring started (the 14-day
    learning counts from it). items: id -> item (status open |
    needs_attention | normal | handled). flagged: day -> new triage items."""
    st = policy_read_json(OUTBOUND_STATE_FILE)
    fresh = not st or "since" not in st
    if fresh:
        st = {"since": time.time()}
    st.setdefault("items", {})
    st.setdefault("flagged", {})
    if fresh:
        outbound_state_save(st)
    return st


def outbound_state_save(st):
    temporary = OUTBOUND_STATE_FILE + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(st, handle, indent=1)
    os.replace(temporary, OUTBOUND_STATE_FILE)


def outbound_base(destination):
    """api.eu.example.co.uk -> example.co.uk; an IP stays as it is."""
    d = str(destination or "").lower().rstrip(".")
    labels = d.split(".")
    if not d or d.replace(".", "").isdigit() or ":" in d or len(labels) < 3:
        return d
    if labels[-2] in ("co", "com", "net", "org", "gov", "ac", "edu") and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def outbound_rules():
    """The rules the checks need: threat lists, noise lists and each Device
    Active Protect device's block rule, by rule number."""
    threat, noise, dap = {}, {}, {}
    for r in (state.get("policy_rules") or {}).get("rules") or []:
        if r.get("disabled") is True:
            continue
        target, pid = str(r.get("target") or ""), str(r.get("pid") or "")
        if r.get("action") == "block" and target in OUTBOUND_THREAT_LISTS:
            threat[pid] = target
        elif r.get("action") == "block" and target in OUTBOUND_NOISE_LISTS:
            noise[pid] = target
        elif r.get("purpose") == "dap" and r.get("type") == "mac":
            dap[pid] = target.upper()
    return threat, noise, dap


def outbound_device(mac, ip, network, groups, dap_macs):
    names = {str(g.get("id")): g.get("name") for g in (state.get("groups") or {}).get("groups") or []}
    group_names = [names.get(str(g)) or str(g) for g in groups or []]
    words = " ".join([network or ""] + group_names).lower()
    iot = mac in dap_macs or any(w in words for w in OUTBOUND_IOT_WORDS)
    out = {"mac": mac, "ip": ip, "name": recent_flow_device_name(mac, ip), "network": network,
           "groups": group_names, "class": "iot" if iot else "personal", "dap": mac in dap_macs}
    return outbound_gone(out)


def outbound_gone(device):
    """A client the router no longer lists (deleted, or a private address it
    dropped) keeps the last name Firewalla's alarms gave it, marked gone
    (owner, 23 Nov 2026, D-960). device: {mac, name, ...}, changed in place."""
    mac = str(device.get("mac") or "").upper()
    if not mac or any(str(d.get("mac") or "").upper() == mac for d in state.get("devices") or []):
        return device
    device["gone"] = True
    if not device.get("name") or device["name"] in (mac, device.get("ip")):
        device["name"] = next((str(a["device"]["name"]) for a in sorted(msp.get("alarms") or [], key=lambda a: -(a.get("ts") or 0))
                               if str((a.get("device") or {}).get("mac") or "").upper() == mac and (a.get("device") or {}).get("name")),
                              device.get("name") or mac)
    return device


def outbound_query(connection, sql, args=()):
    return connection.execute(sql, args).fetchall()


outbound_past = {"stamp": None, "history": None, "uploads": None}   # the days before today, as outbound_build read them


def outbound_build(now=None):
    now = now or time.time()
    st = outbound_state_load()
    threat_pids, noise_pids, dap_pids = outbound_rules()
    dap_macs = set(dap_pids.values())
    learned = now - st["since"] >= OUTBOUND_LEARNING_SECONDS
    today = internet_day(now)
    day_key = time.strftime("%Y-%m-%d", time.localtime(now))
    since_24h = int((now - 86400) // 3600 * 3600)
    flush_internet_traffic()
    with internet_traffic_connection() as connection:
        recent = outbound_query(connection, f"""
            SELECT {INTERNET_TRAFFIC_KEY}, MAX(device_ip), MAX(remote_ip), MAX(network), MAX(groups),
                   SUM(bytes_up), SUM(COALESCE(starts, flows)), MIN(first_ts), MAX(last_ts)
            FROM internet_traffic_hourly WHERE hour >= ? GROUP BY {INTERNET_TRAFFIC_KEY}""", (since_24h,))
        # The days before today (up to a year of them) are read once a day,
        # and again only when a save added to one of them: they were read
        # whole every 5 minutes and on every Decide.
        stamp = (today, past_days_written["internet"])
        if outbound_past["stamp"] != stamp:
            history = outbound_query(connection, """
                SELECT device_mac, destination, country, protocol, port, outcome, MIN(day)
                FROM internet_traffic_daily WHERE day < ? GROUP BY device_mac, destination, country, protocol, port, outcome""",
                (today,))
            uploads = outbound_query(connection, """
                SELECT device_mac, day, SUM(bytes_up) FROM internet_traffic_daily
                WHERE day < ? AND direction = 'out' GROUP BY device_mac, day""", (today,))
            outbound_past.update(stamp=stamp, history=history, uploads=uploads)
        else:
            history, uploads = outbound_past["history"], outbound_past["uploads"]
        dap_days = outbound_query(connection, f"""
            SELECT device_mac, day, SUM(COALESCE(starts, flows)) FROM internet_traffic_daily
            WHERE day >= ? AND outcome = 'blocked' AND rule IN ({','.join('?' * len(dap_pids)) or "''"})
            GROUP BY device_mac, day""", (internet_day(now - 15 * 86400), *[f"rule:{p}" for p in dap_pids]))
        first_seen = dict(outbound_query(connection, "SELECT device_mac, MIN(day) FROM internet_traffic_daily GROUP BY device_mac"))
    known = {}
    for mac, dest, country, protocol, port, outcome, _ in history:
        k = known.setdefault(mac, {"bases": set(), "countries": set(), "ports": set()})
        k["bases"].add(outbound_base(dest))
        if country:
            k["countries"].add(country)
        k["ports"].add(f"{protocol} {port}")
    usual_upload = {}
    for mac, _, total in uploads:
        usual_upload.setdefault(mac, []).append(total or 0)
    usual_upload = {mac: sorted(v)[len(v) // 2] for mac, v in usual_upload.items() if len(v) >= 3}

    devices, found = {}, {}          # found: id -> fresh facts
    threat_below, noise, watched = {}, {}, []
    allowed_pairs = {(r[0], r[1]) for r in recent if r[6] == "allowed"}
    scoring = {}

    def device_of(r):
        mac = r[0]
        if mac not in devices:
            devices[mac] = outbound_device(mac, r[8], r[10], json.loads(r[11] or "[]"), dap_macs)
        return devices[mac]

    def add(item_id, kind, tab, device, title, r, reasons=()):
        f = found.setdefault(item_id, {"kind": kind, "tab": tab, "device": device, "title": title, "reasons": set(),
                                       "flows": 0, "first_at": r[14], "last_at": r[15], "destinations": {}})
        f["reasons"].update(reasons)
        f["flows"] += r[13] or 0
        f["first_at"], f["last_at"] = min(f["first_at"], r[14]), max(f["last_at"], r[15])
        d = f["destinations"].setdefault(r[1], {"name": r[1], "ip": r[9], "country": r[2], "port": f"{r[3]} {r[4]}",
                                                "flows": 0, "bytes_up": 0, "last_at": 0, "outcome": r[6]})
        d["flows"] += r[13] or 0
        d["bytes_up"] += r[12] or 0
        d["last_at"] = max(d["last_at"], r[15])

    by_threat = {}
    for r in recent:
        mac, dest, country, protocol, port, direction, outcome, rule = r[:8]
        pid = rule.removeprefix("rule:") if rule.startswith("rule:") else None
        if outcome == "blocked" and pid in threat_pids:
            by_threat.setdefault((mac, threat_pids[pid]), []).append(r)
        elif outcome == "blocked" and pid in noise_pids:
            dev = device_of(r)
            n = noise.setdefault(mac, {"device": dev, "flows": 0, "doh": 0})
            n["flows"] += r[13] or 0
            if noise_pids[pid] == "doh":
                n["doh"] += r[13] or 0
                if dev["class"] == "iot":
                    add(f"doh|{mac}", "doh", "triage", dev, "Encrypted DNS (DoH) from an IoT client", r,
                        ["an IoT client tried to hide its lookups"])
        elif outcome == "blocked" and pid in dap_pids:
            dev = device_of(r)
            if outbound_base(dest) not in known.get(mac, {}).get("bases", set()):
                add(f"dap|{mac}|{outbound_base(dest)}", "dap", "triage", dev,
                    f"Device Active Protect blocked a new destination: {outbound_base(dest)}", r,
                    ["blocked: not on the destinations this client learned"])
        elif outcome == "allowed" and direction == "out" and mac not in dap_macs:
            scoring.setdefault((mac, outbound_base(dest)), []).append(r)

    # 1 Threat lists, with the thresholds for the device type.
    for (mac, target), rows in by_threat.items():
        dev = device_of(rows[0])
        hits = sum(r[13] or 0 for r in rows)
        bases = {outbound_base(r[1]) for r in rows}
        also_allowed = any((mac, r[1]) in allowed_pairs for r in rows)
        if dev["class"] == "iot" or target == "lookalike_domain":
            over = True
        elif target == "nrd":
            over = len(bases) >= 3 or hits >= 20
        else:
            over = hits >= 5
        if over or also_allowed:
            reasons = [f"{hits} hit{'s' if hits != 1 else ''} in 24 h on {OUTBOUND_THREAT_LISTS[target]}"]
            if also_allowed:
                reasons.append("the same destination was also reached through an allowed route")
            for r in rows:
                add(f"threat|{mac}|{target}", "threat", "review", dev, f"{OUTBOUND_THREAT_LISTS[target]}", r, reasons)
        else:
            threat_below.setdefault(target, {"list": OUTBOUND_THREAT_LISTS[target], "hits": 0, "devices": set()})
            threat_below[target]["hits"] += hits
            threat_below[target]["devices"].add(dev["name"])

    # 3 Device Active Protect: a day with 3x the usual blocks.
    per_day = {}
    for mac, day, flows in dap_days:
        per_day.setdefault(mac, {})[day] = flows or 0
    for mac, days in per_day.items():
        before = [v for d, v in days.items() if d < today]
        if len(before) >= 3 and days.get(today, 0) >= max(10, 3 * sum(before) / len(before)):
            rows = [r for r in recent if r[0] == mac and r[6] == "blocked" and r[7].removeprefix("rule:") in dap_pids]
            if rows:
                dev = device_of(rows[0])
                for r in rows:
                    add(f"dap_spike|{mac}|{day_key}", "dap_spike", "triage", dev,
                        "Device Active Protect blocks spiked today", r,
                        [f"{days[today]} blocks today, usually {round(sum(before) / len(before))} a day"])

    # 4 Scoring, once learned (and the device has a week of history).
    uploads_today = {}
    for r in recent:
        if r[6] == "allowed" and r[5] == "out":
            uploads_today[r[0]] = uploads_today.get(r[0], 0) + (r[12] or 0)
    for (mac, base), rows in scoring.items():
        dev = device_of(rows[0])
        k = known.get(mac, {"bases": set(), "countries": set(), "ports": set()})
        signals = []
        if base not in k["bases"]:
            signals.append("new destination")
        if any(r[2] and r[2] not in k["countries"] for r in rows):
            signals.append("new country")
        if any(f"{r[3]} {r[4]}" not in OUTBOUND_COMMON_PORTS and f"{r[3]} {r[4]}" not in k["ports"] for r in rows):
            signals.append("unusual port")
        if base.replace(".", "").isdigit() or ":" in base:
            signals.append("bare IP address")
        usual = usual_upload.get(mac)
        if usual is not None and uploads_today.get(mac, 0) >= max(50e6, 10 * usual) \
                and sum(r[12] or 0 for r in rows) >= 0.5 * uploads_today[mac]:
            signals.append("upload 10x its usual")
        score = sum(OUTBOUND_WEIGHTS[s][0 if dev["class"] == "iot" else 1] for s in signals)
        if not signals:
            continue
        ready = learned and first_seen.get(mac, today) <= today - 7 * 86400
        if ready and score >= OUTBOUND_SCORE_THRESHOLD:
            for r in rows:
                add(f"score|{mac}|{base}", "score", "triage", dev, f"New behaviour: {base}", r,
                    [f"{s} (+{OUTBOUND_WEIGHTS[s][0 if dev['class'] == 'iot' else 1]})" for s in signals])
            found[f"score|{mac}|{base}"]["score"] = score
        else:
            watched.append({"device": dev, "destination": base, "signals": signals, "score": score,
                            "flows": sum(r[13] or 0 for r in rows), "last_at": max(r[15] for r in rows),
                            "why": "still learning" if not ready else "below the threshold"})

    # Fold what was found into the saved items.
    dirty = False
    flagged_today = st["flagged"].get(day_key, 0)
    for item_id, f in sorted(found.items(), key=lambda kv: -kv[1].get("score", 0)):
        f["reasons"] = sorted(f["reasons"])
        f["destinations"] = sorted(f["destinations"].values(), key=lambda d: -d["flows"])[:12]
        item = st["items"].get(item_id)
        reopened = False
        if item and item["status"] in ("normal", "handled"):
            at_close = item.get("closed_flows") or 0
            new_dest = item["kind"] == "threat" and {d["name"] for d in f["destinations"]} - set(item.get("closed_destinations") or [])
            if not (f["flows"] >= OUTBOUND_GROWTH_FACTOR * max(1, at_close) or new_dest):
                continue
            item, reopened = None, True
        if item is None:
            # The daily limit holds back new items, not ones that came back.
            if f["tab"] == "triage" and f["kind"] != "doh" and not reopened:
                if flagged_today >= OUTBOUND_DAILY_CAP:
                    watched.append({"device": f["device"], "destination": f["title"], "signals": f["reasons"],
                                    "score": f.get("score"), "flows": f["flows"], "last_at": f["last_at"],
                                    "why": f"today's limit of {OUTBOUND_DAILY_CAP} new items reached"})
                    continue
                flagged_today += 1
            item = st["items"][item_id] = {"id": item_id, "status": "open", "created_at": now, "outcome": None}
        item.update({k: v for k, v in f.items()})
        item["device"] = f["device"]
        dirty = True
    dirty = outbound_apply_hidden(st, traffic_hidden(), now) or dirty
    st["flagged"][day_key] = flagged_today
    for day in [d for d in st["flagged"] if d < time.strftime("%Y-%m-%d", time.localtime(now - 7 * 86400))]:
        del st["flagged"][day]
    for item_id in [i for i, it in st["items"].items()
                    if it["status"] in ("normal", "handled") and now - (it.get("outcome") or {}).get("at", now) > 365 * 86400]:
        del st["items"][item_id]

    # Did Firewalla alarm on it too? Same device, same destination (or a
    # device-wide alarm) within an hour of the traffic.
    alarms = msp.get("alarms") or []
    matched = set()
    for item in st["items"].values():
        if item["status"] in ("normal", "handled") and item.get("firewalla") is not None:
            continue
        names = {d["name"] for d in item.get("destinations") or []} | {d.get("ip") for d in item.get("destinations") or []}
        hits = [a for a in alarms if (a.get("device") or {}).get("mac") == item["device"]["mac"]
                and item["first_at"] - OUTBOUND_ALARM_WINDOW <= (a.get("ts") or 0) <= item["last_at"] + OUTBOUND_ALARM_WINDOW
                and (not a.get("remote") or a["remote"].get("name") in names or a["remote"].get("ip") in names
                     or outbound_base(a["remote"].get("name")) in {outbound_base(n) for n in names if n})]
        item["firewalla"] = [{"aid": a.get("aid"), "kind": a["kind"], "ts": a["ts"], "message": a.get("message")} for a in hits]
        matched.update(a.get("aid") for a in hits)
    # (Only alarms since monitoring started: older traffic was never seen.)
    missed = [{**a, "device": outbound_gone(dict(a["device"]))} for a in alarms
              if a.get("device") and a.get("remote") and now - (a.get("ts") or 0) < 7 * 86400
              and (a.get("ts") or 0) >= st["since"] and a.get("aid") not in matched]
    if dirty:
        outbound_state_save(st)

    items = sorted(st["items"].values(), key=lambda i: -i["last_at"])
    lists = {
        "triage": [i for i in items if i["status"] == "open" and i["tab"] == "triage"],
        "review": [i for i in items if i["status"] == "open" and i["tab"] == "review"],
        "needs_attention": [i for i in items if i["status"] == "needs_attention"],
        "normal": [i for i in items if i["status"] in ("normal", "handled")][:100],
    }
    counts = {"triage": len(lists["triage"]), "review": len(lists["review"]),
              "needs_attention": len(lists["needs_attention"]),
              "noise_24h": sum(n["flows"] for n in noise.values()),
              "threat_below": sum(t["hits"] for t in threat_below.values()),
              "watched": len(watched), "firewalla_missed": len(missed)}
    state["outbound"] = {**counts, "updated_at": now, "learning_ready": learned,
                         "newest_at": max([i.get("created_at") or 0 for k in ("triage", "review", "needs_attention") for i in lists[k]] or [0]),
                         "learning_day": max(1, int((now - st["since"]) // 86400) + 1)}
    return {
        "updated_at": now, "counts": counts, **lists,
        "learning": {"since": st["since"], "days": max(0, round((now - st["since"]) / 86400, 1)),
                     "ready": learned, "needed_days": OUTBOUND_LEARNING_SECONDS // 86400},
        "watched": sorted(watched, key=lambda w: -(w["score"] or 0))[:200],
        "threat_below": [{**t, "devices": sorted(t["devices"])} for t in threat_below.values()],
        "noise": sorted(noise.values(), key=lambda n: -n["flows"])[:30],
        "firewalla_missed": missed[:50],
    }


def outbound_data(fresh=False):
    if fresh or not outbound_cache["data"] or time.time() - outbound_cache["at"] > OUTBOUND_CHECK_SECONDS:
        with outbound_lock:
            outbound_cache["data"] = outbound_build()
            outbound_cache["at"] = time.time()
    return outbound_cache["data"]


def outbound_worker():
    time.sleep(90)   # let the rules, groups and alarms arrive first
    while True:
        try:
            outbound_data(fresh=True)
        except Exception as exc:
            print("Outbound page error:", exc)
            traceback.print_exc()
        time.sleep(OUTBOUND_CHECK_SECONDS)


def outbound_apply_hidden(st, hidden, now):
    """A To Triage item whose destinations you all hid on Traffic is filed
    as Normal, "hidden by you" (the user, 15 Nov 2026). Threat-list hits
    (To Review) and Needs Attention still ask for you. True if any changed."""
    changed = False
    hidden = traffic_hidden_resolve(hidden) if hidden else {}
    for item in st["items"].values():
        dests = item.get("destinations") or []
        if not (hidden and dests and item["status"] == "open" and item.get("tab") == "triage" and item.get("kind") != "threat"):
            continue
        mac = (item.get("device") or {}).get("mac")
        if all(traffic_is_hidden(hidden, mac, d.get("name"), d.get("ip")) for d in dests):
            item["status"] = "normal"
            item["outcome"] = {"by": "hidden", "at": now, "reason": "You hid this destination on Traffic for this client's groups."}
            item["closed_flows"] = item.get("flows") or 0
            item["closed_destinations"] = [d["name"] for d in dests]
            changed = True
    return changed


@app.get("/api/outbound")
def api_outbound():
    """The Outbound page: To Triage, To Review, Needs Attention, Normal,
    the Watched log and what was only counted, with Claude's answers."""
    page = outbound_data()
    with claude_lock:
        claude = claude_public(claude_load(), "outbound")
    return {**outbound_owners(page), "claude": claude}


def outbound_owners(page):
    """The page with who runs each destination (copies: the saved items
    stay as they are)."""
    who = lambda name, ip=None: {k: v for k, v in dest_classify(name, ip).items() if k in ("owner", "what") and v}
    item = lambda i: {**i, "destinations": [{**d, **who(d.get("name"), d.get("ip"))} for d in i.get("destinations") or []]}
    out = {**page, **{k: [item(i) for i in page.get(k) or []] for k in ("triage", "review", "needs_attention", "normal")}}
    out["watched"] = [{**w, **who(w.get("destination"))} for w in page.get("watched") or []]
    out["firewalla_missed"] = [{**a, "owner": who((a.get("remote") or {}).get("name") or (a.get("remote") or {}).get("ip"),
                                                    (a.get("remote") or {}).get("ip")).get("owner", "")}
                               for a in page.get("firewalla_missed") or []]
    return out


@app.post("/api/outbound/decide")
def api_outbound_decide(payload: dict = Body(default={})):
    """outcome: needs_attention | normal (needs a reason) | handled (after
    Needs Attention) | reopen. by: "you" or "claude"."""
    fields = Fields(payload)
    item_id, outcome = fields.text("id", 300, strip=False), fields.choice("outcome", ("needs_attention", "normal", "handled", "reopen"))
    reason = fields.text("reason", 500)
    if not outcome:
        return {"ok": False, "error": "unknown outcome"}
    if outcome == "normal" and not reason:
        return {"ok": False, "error": "say why it's normal"}
    with outbound_lock:
        st = outbound_state_load()
        item = st["items"].get(item_id)
        if not item:
            return {"ok": False, "error": "no such item"}
        now = time.time()
        if outcome == "reopen":
            item["status"], item["outcome"] = "open", None
        else:
            item["status"] = outcome
            item["outcome"] = {"by": "claude" if payload.get("by") == "claude" else "you", "at": now, "reason": reason}
            if outcome in ("normal", "handled"):
                item["closed_flows"] = item.get("flows") or 0
                item["closed_destinations"] = [d["name"] for d in item.get("destinations") or []]
        outbound_state_save(st)
        outbound_cache["data"] = None
    return {"ok": True, "page": outbound_data(fresh=True)}


# ============================================================
# INTERNET PAGE: both WANs, and what the internet does to you
#
# Per WAN: state, public IP, link, live rates, this month's use, 7-day
# uptime with outages and failovers, speed tests (a test under 80% of the
# WAN's usual download is flagged). Inbound, blocked: what the internet
# tried at each WAN in 24 hours (hourly, the ports aimed at, countries,
# busiest sources), a spike = an hour at 3x the usual (and 100+) shown here
# and on Status; hourly counts are kept 30 days (/data/inbound_hourly.json)
# for the daily trend. Inbound, allowed: connections the internet started
# that reached a device (from the internet traffic totals, direction "in").
# Internet Paths: which network goes out which WAN (last 5 minutes).
# Ports aimed at are known from 13 Nov 2026 on (see normalize_recent_flow).
# ============================================================

INBOUND_HOURLY_FILE = os.environ.get("FIREWALLA_INBOUND_HOURLY_FILE", "/data/inbound_hourly.json")
INBOUND_KEEP_SECONDS = 30 * 86400
INBOUND_SPIKE_FACTOR = 3
INBOUND_SPIKE_MIN = 100
SPEEDTEST_SLOW_SHARE = 0.8
# A slow speed test you acknowledged (owner, 20 Nov 2026) stays on the
# Internet page but no longer needs a look; the next slow test does again.
# {WAN key: the acknowledged test's time}.
SPEEDTEST_ACK_FILE = os.environ.get("FIREWALLA_SPEEDTEST_ACK_FILE", "/data/speedtest_ack.json")
# Speed-test history (owner, 22 Nov 2026: Max Speed Test beside Peak
# Throughput). The router keeps only its last 50 results (about 6 days for
# both WANs), so each result is kept here 31 days: {timestamp: result in
# the router's own shape, trimmed}.
SPEEDTEST_HISTORY_FILE = os.environ.get("FIREWALLA_SPEEDTEST_HISTORY_FILE", "/data/speedtest_history.json")
SPEEDTEST_KEEP_SECONDS = 31 * 86400
SPEEDTEST_PEAK_WINDOWS = (1, 3, 7, 14, 30)   # days, as Peak Throughput
INTERNET_PAGE_SECONDS = 60
internet_page_cache = {"at": 0, "data": None}
internet_page_lock = threading.Lock()

# What a port the internet aims at is usually for (inbound scans).
# (LOCAL_PORT_SERVICES, further down, covers the rest.)
INBOUND_PORT_SERVICES = {
    "tcp 21": "FTP", "tcp 23": "Telnet", "tcp 25": "Mail (SMTP)", "tcp 110": "Mail (POP3)", "tcp 143": "Mail (IMAP)",
    "tcp 1433": "SQL Server", "tcp 1723": "PPTP VPN", "tcp 2375": "Docker API", "tcp 3306": "MySQL",
    "tcp 5432": "PostgreSQL", "tcp 5900": "VNC remote desktop", "tcp 6379": "Redis", "tcp 7547": "Router remote management (TR-069)",
    "tcp 8000": "Web (alternate)", "tcp 8080": "Web (alternate)", "tcp 8443": "Web (HTTPS alternate)", "tcp 8888": "Web (alternate)",
    "tcp 9200": "Elasticsearch", "tcp 27017": "MongoDB", "tcp 49152": "UPnP", "udp 500": "IPsec VPN", "udp 4500": "IPsec VPN",
    "udp 51820": "WireGuard VPN", "udp 1194": "OpenVPN", "udp 5060": "Internet phone (SIP)", "udp 161": "SNMP", "udp 123": "Time (NTP)",
}


def inbound_service(port_key):
    return INBOUND_PORT_SERVICES.get(port_key) or LOCAL_PORT_SERVICES.get(port_key)


def inbound_hourly_update(wans, now):
    """Merge the router's last 24 hourly counts per WAN into the 30-day
    file; returns {wan uuid: {hour: count}}."""
    kept = policy_read_json(INBOUND_HOURLY_FILE) or {}
    cutoff = now - INBOUND_KEEP_SECONDS
    changed = False
    for w in wans:
        hours = kept.setdefault(w.get("wan_uuid") or w.get("wan"), {})
        for b in w.get("buckets") or []:
            if b.get("available") and not b.get("current"):
                key = str(int(b["hour_start"]))
                if hours.get(key) != b.get("attempt_count", 0):
                    hours[key] = b.get("attempt_count", 0)
                    changed = True
        for key in [k for k in hours if int(k) < cutoff]:
            del hours[key]
            changed = True
    if changed:
        temporary = INBOUND_HOURLY_FILE + ".tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump(kept, handle)
        os.replace(temporary, INBOUND_HOURLY_FILE)
    return kept


def speedtest_history_update(tests, now):
    """Merge the router's latest speed-test results into the 31-day file;
    returns every kept result, oldest first. Each carries "wan": the
    router's id of the WAN that ran it (the result's uuid)."""
    kept = policy_read_json(SPEEDTEST_HISTORY_FILE) or {}
    changed = False
    for t in tests or []:
        try:
            at = float(t.get("timestamp"))
        except (TypeError, ValueError, AttributeError):
            continue
        key = f"{at:.3f}"
        if key not in kept:
            result, client, server = t.get("result") or {}, t.get("client") or {}, t.get("server") or {}
            kept[key] = {"timestamp": at, "wan": t.get("uuid"),
                         "result": {k: result.get(k) for k in ("download", "upload", "latency")},
                         "client": {k: client.get(k) for k in ("publicIp", "isp")},
                         "server": {"sponsor": server.get("sponsor")}}
            changed = True
        elif t.get("uuid") and not kept[key].get("wan"):
            kept[key]["wan"] = t["uuid"]   # kept before 24 Nov 2026, still in the router's list
            changed = True
    for key in [k for k, t in kept.items() if (t.get("timestamp") or 0) < now - SPEEDTEST_KEEP_SECONDS]:
        del kept[key]
        changed = True
    if changed:
        temporary = SPEEDTEST_HISTORY_FILE + ".tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump(kept, handle)
        os.replace(temporary, SPEEDTEST_HISTORY_FILE)
    return sorted(kept.values(), key=lambda t: t.get("timestamp") or 0)


def speedtest_peaks(tests, now):
    """{since, windows: [{days, down, up}]}: the fastest speed-test result
    down and up in the last 1, 3, 7, 14 and 30 days (each its own test's
    figure), or None with no tests."""
    if not tests:
        return None
    windows = []
    for days in SPEEDTEST_PEAK_WINDOWS:
        inside = [t for t in tests if (t["at"] or 0) > now - days * 86400]
        windows.append({"days": days, "down": round(max((t["down"] or 0 for t in inside), default=0.0), 2),
                        "up": round(max((t["up"] or 0 for t in inside), default=0.0), 2)})
    return {"since": min(t["at"] or now for t in tests), "windows": windows}


# One connection's History on the Internet page (owner, 23 Nov 2026, the
# unit history's last step): outages and traffic moving (the WAN uptime
# recorder), packet-loss and slow spells (the equipment health database),
# and speed tests (the speed-test history; a slow one is an event), last 7
# days: summary lines, then every event newest first (the page shows 10,
# Show All the rest). Nothing here raises an item.
WAN_HISTORY_DAYS = 7


def wan_history(key, uptime, tests, now):
    since = now - WAN_HISTORY_DAYS * 86400
    when = lambda t: datetime.fromtimestamp(t).strftime("%d %b %H:%M")
    times = lambda n: f"{n} time{'s' if n != 1 else ''}"
    mins = lambda m: f"{m / 60:.1f} h" if m >= 90 else f"{max(1, round(m))} m"
    events, lines = [], []
    # Outages (not working: link down or failing the router's tests) and
    # traffic moving to or from it.
    changes = (uptime or {}).get("events") or []
    for i, e in enumerate(changes):
        if e["at"] < since:
            continue
        if e["to"] == "down":
            end = changes[i + 1]["at"] if i + 1 < len(changes) else None
            events.append({"at": e["at"], "kind": "outage", "minutes": ((end or now) - e["at"]) / 60, "ongoing": end is None})
        elif e["from"] == "standby" and e["to"] == "active":
            events.append({"at": e["at"], "kind": "took_over"})
        elif e["from"] == "active" and e["to"] == "standby":
            events.append({"at": e["at"], "kind": "handed_over"})
    outs = [e for e in events if e["kind"] == "outage"]
    if outs:
        day = sum(e["at"] >= now - 86400 for e in outs)
        lines.append(f"stopped working {times(len(outs))} in 7 days ({day} in 24 h), {mins(sum(e['minutes'] for e in outs))} in all, last {when(outs[-1]['at'])}")
    else:
        lines.append("no outages in 7 days")
    took, gave = sum(e["kind"] == "took_over" for e in events), sum(e["kind"] == "handed_over" for e in events)
    if took or gave:
        lines.append(", ".join(x for x in (f"took over the traffic {times(took)}" if took else "", f"handed it over {times(gave)}" if gave else "") if x))
    # Packet loss and slow answers.
    try:
        spells, began = eh_wan_events(key, since)
    except Exception:
        spells, began = [], None
    for s in spells:
        events.append({"at": s.get("start") or s["at"], "kind": s["kind"], "worst": s["worst"], "minutes": s.get("minutes") or 1})
    for kind, what, unit in (("loss", "packet loss", "%"), ("latency", f"slow answers ({EH_WAN_SLOW_MS} ms or more)", " ms")):
        mine = [s for s in spells if s["kind"] == kind]
        if mine:
            day = sum(s["at"] >= now - 86400 for s in mine)
            lines.append(f"{what} {times(len(mine))} ({day} in 24 h), worst {max(s['worst'] for s in mine):.0f}{unit}, longest {mins(max(s.get('minutes') or 1 for s in mine))}")
    if not spells and began:
        lines.append(f"no packet loss or slow answers since {when(max(began, since))}")
    # Speed tests: each against the usual of the 10 before it (as the slow test on Status).
    week = [t for t in tests if (t["at"] or 0) >= since and t["down"]]
    for t in week:
        before = sorted(x["down"] for x in [x for x in tests if x["down"] and (x["at"] or 0) < t["at"]][-10:])
        usual = before[len(before) // 2] if before else None
        if usual and t["down"] < SPEEDTEST_SLOW_SHARE * usual:
            events.append({"at": t["at"], "kind": "slow_test", "down": t["down"], "up": t["up"], "usual": usual})
    if week:
        downs, ups = sorted(t["down"] for t in week), sorted(t["up"] or 0 for t in week)
        low = min(week, key=lambda t: t["down"])
        slow = sum(e["kind"] == "slow_test" for e in events)
        lines.append(f"{len(week)} speed tests, typical ↓ {downs[len(downs) // 2]:,.0f} / ↑ {ups[len(ups) // 2]:,.0f} Mb/s, slowest ↓ {low['down']:,.0f} on {when(low['at'])}"
                     + (f", {slow} under 80% of the usual" if slow else ""))
    events.sort(key=lambda e: e["at"], reverse=True)
    return {"lines": lines, "events": events, "since": began}


def internet_inbound_detail(since):
    """Top ports aimed at (only records from after the port fix), countries
    and sources of blocked attempts at the WANs, per WAN uuid."""
    # Each list is its top 8; "<key>_rest" is everything after them (owner,
    # 23 Nov 2026, D-966: the ports listed added up to a tenth of the tries).
    out = {"ports": {}, "countries": {}, "sources": {}, "ports_rest": {}, "countries_rest": {}, "sources_rest": {}, "total": {}}
    with flow_history_reader() as connection:
        for key, column, extra in (("ports", "LOWER(protocol) || ' ' || CAST(port AS TEXT)",
                                    "AND json_extract(payload_json, '$.remote_port') IS NOT NULL"),
                                   ("countries", "COALESCE(country, '--')", ""),
                                   ("sources", "COALESCE(remote_ip, '--')", "")):
            rows = connection.execute(f"""
                SELECT source_uuid, {column}, SUM(COALESCE(starts, count)), MAX(country) FROM flow_records
                WHERE kind = 'blocked' AND device_mac LIKE 'IF:%' AND event_at >= ? {extra}
                GROUP BY source_uuid, {column} ORDER BY SUM(COALESCE(starts, count)) DESC""", (since,)).fetchall()
            for wan, value, count, country in rows:
                if key == "countries":   # every record has a country (or --): its sum is the total (D-968)
                    out["total"][wan] = out["total"].get(wan, 0) + (count or 0)
                bucket = out[key].setdefault(wan, [])
                if len(bucket) >= 8:
                    rest = out[key + "_rest"].setdefault(wan, {"values": 0, "count": 0})
                    rest["values"] += 1
                    rest["count"] += count or 0
                    continue
                entry = {"value": value, "count": count}
                if key == "ports":
                    entry["service"] = inbound_service(value)
                if key == "sources":
                    entry["country"] = country
                bucket.append(entry)
    return out


def speedtest_on_wan(test, wan):
    """Whether this WAN ran this kept speed test: by the WAN's id. A test kept
    before 24 Nov 2026 has no id: by the public address it ran from, or the
    provider's name (which stopped matching once the ISP changed the address
    or the WAN was renamed). That part can go after 25 Dec 2026, when the last
    such test has aged out."""
    if test.get("wan"):
        return test["wan"] == wan.get("uuid")
    client = test.get("client") or {}
    return client.get("publicIp") == wan.get("public_ip") or client.get("isp") == wan.get("provider")


def internet_page_build(now=None):
    now = now or time.time()
    inet = state.get("internet") or {}
    link = {p.get("name"): p.get("speed") for p in state.get("ports") or []}
    rates = {i.get("name"): i for i in state.get("interfaces") or []}
    uptime = {u["wan"]: u for u in wan_uptime_summary(now)["wans"]}
    peaks = wan_peaks_summary(now)
    blocked = list(((state.get("blocked_wan_hourly") or {}).get("wans") or {}).values())
    kept = inbound_hourly_update(blocked, now)
    try:
        # The same hours as the headline's total: its 24 hourly buckets (D-967).
        starts = [x.get("hour_start") for w in blocked for x in w.get("buckets") or [] if x.get("hour_start")]
        detail = internet_inbound_detail(min(starts) if starts else now - 86400)
    except Exception as exc:
        detail = {"ports": {}, "countries": {}, "sources": {}, "error": public_error("Inbound detail", exc)}
    tests = speedtest_history_update(state.get("internet_speedtest_results"), now)
    acks = policy_read_json(SPEEDTEST_ACK_FILE) or {}
    wans, slow_tests = [], []
    uptime_day = {u["wan"]: u for u in wan_uptime_summary(now, days=1)["wans"]}
    for name, w in sorted((inet.get("wans") or {}).items()):
        mine = sorted(({"at": t.get("timestamp"), "down": (t.get("result") or {}).get("download"),
                        "up": (t.get("result") or {}).get("upload"), "latency": (t.get("result") or {}).get("latency"),
                        "server": ((t.get("server") or {}).get("sponsor"))}
                       for t in tests if speedtest_on_wan(t, w)), key=lambda t: t["at"] or 0)
        test_peaks = speedtest_peaks(mine, now)
        # Each test of the last 24 hours against the usual of the 10 before it:
        # a slow one turns its half hour yellow on Status's Last 24 Hours.
        for i, t in enumerate(mine):
            if t["at"] and now - t["at"] <= 86400 and t["down"]:
                before = sorted(x["down"] for x in mine[max(0, i - 10):i] if x["down"])
                if before and t["down"] < SPEEDTEST_SLOW_SHARE * before[len(before) // 2]:
                    slow_tests.append({"at": t["at"], "wan": name})
        history = wan_history(name, uptime.get(name), mine, now)
        mine = mine[-20:]
        downs = sorted(t["down"] for t in mine[-10:] if t["down"])
        usual = downs[len(downs) // 2] if downs else None
        latest = mine[-1] if mine else None
        slow = bool(latest and usual and latest["down"] and latest["down"] < SPEEDTEST_SLOW_SHARE * usual)
        slow_acked = bool(slow and acks.get(name) == latest["at"])
        b = next((x for x in blocked if x.get("wan_uuid") == w.get("uuid")), {})
        hourly = [x.get("attempt_count", 0) for x in b.get("buckets") or []]
        done = [x.get("attempt_count", 0) for x in b.get("buckets") or [] if x.get("available") and not x.get("current")]
        usual_hour = sorted(done[:-1])[len(done[:-1]) // 2] if len(done) > 2 else None
        spike = bool(done and usual_hour is not None and done[-1] >= max(INBOUND_SPIKE_MIN, INBOUND_SPIKE_FACTOR * usual_hour))
        # Hourly counts, 30 days: the page adds them up per day in the
        # viewer's own time zone (the container runs on UTC).
        hours_kept = sorted([int(hour), count] for hour, count in (kept.get(w.get("uuid")) or {}).items())
        r = rates.get(name) or {}
        wans.append({
            "key": name, "name": w.get("provider") or name, "uuid": w.get("uuid"), "role": w.get("role"),
            "active": bool(w.get("in_use") or w.get("active")), "ready": w.get("ready"), "public_ip": w.get("public_ip"),
            "link_mbps": link.get(name), "rx_mbps": r.get("rx_mbps"), "tx_mbps": r.get("tx_mbps"),
            "plan": {"down": w.get("configured_download_mbps"), "up": w.get("configured_upload_mbps")},
            "month": {"down": w.get("monthly_download_bytes"), "up": w.get("monthly_upload_bytes"),
                      "since": w.get("monthly_begin_ts")},
            "checks": {k: w.get(k) for k in ("carrier", "ping", "dns", "http")}, "failures": w.get("failures") or [],
            "uptime": uptime.get(name), "history": history, "uptime_24h": uptime_day.get(name), "peaks": peaks.get(name), "test_peaks": test_peaks,
            "tests": mine, "usual_down": usual, "slow": slow, "slow_acked": slow_acked,
            # The 24-hour total from the same records as the top lists, so they
            # add up exactly (owner, 23 Nov 2026, D-968); the hourly chart and the
            # 30 days keep the WAN feed, which goes back further.
            "inbound": {"total_24h": detail["total"].get(w.get("uuid"), b.get("total_24h", 0)) if "total" in detail else b.get("total_24h", 0),
                        "hourly": hourly,
                        "hour_starts": [x.get("hour_start") for x in b.get("buckets") or []],
                        "usual_hour": usual_hour, "spike": spike,
                        "busiest": b.get("peak_completed_hour"),
                        "hours_30d": hours_kept,
                        "ports": detail["ports"].get(w.get("uuid"), []),
                        "countries": detail["countries"].get(w.get("uuid"), []),
                        "sources": detail["sources"].get(w.get("uuid"), []),
                        "rest": {k: detail.get(k + "_rest", {}).get(w.get("uuid")) for k in ("ports", "countries", "sources")}},
        })
    flush_internet_traffic()
    with internet_traffic_connection() as connection:
        allowed = connection.execute("""
            SELECT device_mac, MAX(device_ip), destination, country, protocol, port, rule, SUM(COALESCE(starts, flows)),
                   SUM(bytes_up), SUM(bytes_down), MAX(last_ts), MAX(remote_ip)
            FROM internet_traffic_hourly WHERE hour >= ? AND direction = 'in' AND outcome = 'allowed'
            GROUP BY device_mac, destination, country, protocol, port, rule
            ORDER BY MAX(last_ts) DESC LIMIT 200""", (int((now - 86400) // 3600 * 3600),)).fetchall()
    inbound_allowed = []
    for mac, ip, dest, country, protocol, port, rule, flows, up, down, last, remote_ip in allowed:
        pid = rule.removeprefix("rule:") if rule.startswith("rule:") else None
        r = policy_rule_for_pid(pid) if pid else None
        inbound_allowed.append({
            "device": {"mac": mac, "ip": ip, "name": recent_flow_device_name(mac, ip)},
            "from": dest, "remote_ip": remote_ip, "country": country, "port": f"{protocol} {port}",
            "service": inbound_service(f"{protocol} {port}"),
            "rule": {"pid": pid, "text": access_rule_text(r) if r else f"Rule {pid}"} if pid else None,
            "flows": flows, "bytes_up": up, "bytes_down": down, "last_at": last,
        })
    unexplained = sum(a["flows"] or 0 for a in inbound_allowed if not a["rule"])   # connections, as the total (D-969)
    up_all = all(w["ready"] for w in wans) if wans else False
    counts = {
        "wans": len(wans), "wans_up": sum(1 for w in wans if w["ready"]),
        "outages": sum((w["uptime"] or {}).get("outages") or 0 for w in wans),
        "failovers": sum((w["uptime"] or {}).get("failovers") or 0 for w in wans),
        "inbound_blocked": sum(w["inbound"]["total_24h"] for w in wans),
        "inbound_allowed": sum(a["flows"] or 0 for a in inbound_allowed),
        "inbound_unexplained": unexplained,
        "spikes": [w["name"] for w in wans if w["inbound"]["spike"]],
        "slow_tests": [w["name"] for w in wans if w["slow"] and not w["slow_acked"]],
    }
    state["slow_speed_tests"] = slow_tests   # Status's Last 24 Hours reads them
    try:   # Internet Access, 24 Hours: the same half hours as Status's Last 24 Hours
        access = api_status_page().get("access_24h")
    except Exception as exc:
        access = {"level": "none", "error": public_error("Internet access", exc)}
    # What Status, Needs You and the menu read from this page (slow speed
    # tests, inbound spikes, inbound let in without an allow rule). From
    # 21 Nov to 23 Nov 2026 this sat inside the except above, so it was set
    # only when Internet Access failed (D-902).
    state["internet_page"] = {**counts, "all_up": up_all, "updated_at": now,
                              "wan_list": [{"name": w["name"], "active": w["active"], "ready": w["ready"],
                                            "last_down": (w["tests"][-1]["down"] if w["tests"] else None)} for w in wans]}
    return {"updated_at": now, "counts": counts, "all_up": up_all, "mode": inet.get("mode"), "access_24h": access,
            "connected": inet.get("connected"), "wans": wans, "inbound_allowed": inbound_allowed,
            "paths": (state.get("internet_flow_activity") or {}).get("paths") or [],
            "detail_error": detail.get("error")}


def internet_page_data():
    with internet_page_lock:
        if not internet_page_cache["data"] or time.time() - internet_page_cache["at"] > INTERNET_PAGE_SECONDS:
            internet_page_cache["data"] = internet_page_build()
            internet_page_cache["at"] = time.time()
        return internet_page_cache["data"]


def internet_page_worker():
    time.sleep(75)   # let the WANs, speed tests and blocked counts arrive
    while True:
        try:
            with internet_page_lock:
                internet_page_cache["data"] = internet_page_build()
                internet_page_cache["at"] = time.time()
        except Exception as exc:
            print("Internet page error:", exc)
            traceback.print_exc()
        time.sleep(INTERNET_PAGE_SECONDS)


# The Status page (Status and Overview merged, owner 22 Nov 2026): the status
# page's data, plus the last hour's top data users (kept a minute: the page
# refreshes every 10 s) and Claude's use today.
status_users_cache = {"at": 0, "value": None}


@app.get("/api/status-full")
def api_status_full(digest: str = None):
    page = api_status_page(digest)
    now = time.time()
    if status_users_cache["value"] is None or now - status_users_cache["at"] > 60:
        try:
            usage = api_client_usage(hours=1)
        except Exception as exc:
            usage = {"clients": [], "error": public_error("Client usage", exc)}
        status_users_cache.update(at=now, value={"top_users": (usage.get("clients") or [])[:6], "usage_error": usage.get("error")})
    return {**page, **status_users_cache["value"], "claude": overview_claude()}


def overview_claude():
    """Status's Claude Today box: today's use and whether the worker runs."""
    with claude_lock:
        c = claude_public(claude_load(), "overview")   # no items have this kind: totals only
    c.pop("items", None)
    return c


@app.get("/api/client/{mac}")
def api_client(mac: str):
    """The Clients page's device popup: everything known about one device:
    identity, connection, groups and their VqLAN / Isolation, Device Active
    Protect, the rules that name it or its groups, internet use (24 h),
    local connections, open Outbound items, Firewalla alarms."""
    mac = str(mac or "").upper()
    device = next((d for d in state.get("devices") or [] if str(d.get("mac") or "").upper() == mac), None)
    if not device:
        return {"error": f"No client {mac}"}
    now = time.time()
    first_octet = int(mac[:2], 16) if re.match(r"^[0-9A-F]{2}:", mac) else 0
    groups = [g for g in (state.get("groups") or {}).get("groups") or []
              if mac in {str(m).upper() for m in g.get("members") or []}]
    group_info = []
    for g in groups:
        info = api_group("g" + str(g.get("id")))
        group_info.append({"id": str(g.get("id")), "name": g.get("name"), "vqlan": info.get("vqlan"),
                           "isolation": info.get("isolation"), "allowed": len(info.get("allowed") or [])})
    group_ids = {g["id"] for g in group_info}
    rules, dap = [], False
    for r in (state.get("policy_rules") or {}).get("rules") or []:
        if r.get("disabled") is True:
            continue
        on = r.get("applies_on") or {}
        match = r.get("matching") or {}
        mine = (on.get("kind") == "device" and str(on.get("id") or "").upper() == mac) \
            or (on.get("kind") == "group" and str(on.get("id")) in group_ids) \
            or (match.get("kind") == "device" and str(match.get("id") or "").upper() == mac)
        if r.get("purpose") == "dap" and str(r.get("target") or "").upper() == mac:
            dap = True
        if mine and r.get("purpose") != "dap":
            rules.append({"pid": str(r.get("pid")), "action": r.get("action"), "text": access_rule_text(r)})
    usage = next((c for c in (api_client_usage(hours=24).get("clients") or []) if str(c.get("mac") or "").upper() == mac), {})
    since = int((now - 86400) // 3600 * 3600)
    flush_internet_traffic()
    with internet_traffic_connection() as connection:
        blocked = connection.execute("""SELECT COALESCE(SUM(COALESCE(starts, flows)), 0) FROM internet_traffic_hourly
            WHERE hour >= ? AND device_mac = ? AND outcome = 'blocked'""", (since, mac)).fetchone()[0]
    flush_local_traffic()
    with local_traffic_connection() as connection:
        rows = connection.execute("""
            SELECT src_mac, dst_mac, protocol, port, outcome, blocked_by, bytes_sent + bytes_received, first_ts, last_ts, COALESCE(starts, flows)
            FROM local_traffic_hourly WHERE hour >= ? AND (src_mac = ? OR dst_mac = ?)""", (since, mac, mac)).fetchall()
    # Connections started (D-883), and "some blocked" only for a real block
    # (D-913): a try nobody answered isn't one (24 Nov 2026: every blocked
    # row counted, and the figure was the router's records).
    partners = {}
    for src, dst, protocol, port, outcome, blocked_by, nbytes, first, last, n in rows:
        entry = partners.setdefault(dst if src == mac else src, [0, False])
        entry[0] += n or 0
        entry[1] = entry[1] or (outcome == "blocked" and local_block_kind(src, dst, protocol, port, blocked_by, nbytes, first, last) == "real")
    local = sorted(((m, n, hit) for m, (n, hit) in partners.items()), key=lambda x: -x[1])[:6]
    outbound = [{"id": i["id"], "title": i.get("title"), "status": i.get("status")}
                for i in outbound_state_load()["items"].values()
                if (i.get("device") or {}).get("mac") == mac and i.get("status") in ("open", "needs_attention")]
    alarms = [{"kind": a.get("kind"), "ts": a.get("ts"), "status": a.get("status"), "message": a.get("message")}
              for a in msp.get("alarms") or [] if (a.get("device") or {}).get("mac") == mac][:10]
    return {
        "mac": mac, "name": device.get("name"), "ip": device.get("ip"), "vendor": device.get("vendor"),
        "model": device.get("model"), "online": device.get("online"), "last_active": device.get("last_active"),
        "first_found": device.get("first_found"), "private_mac": bool(first_octet & 2),
        "network": next((i.get("display_name") or i.get("name") for i in state.get("interfaces") or []
                         if i.get("target") == device.get("interface_uuid")), None),
        "wifi": (state.get("wifi_stations") or {}).get(mac), "wired": (state.get("wired_clients") or {}).get(mac),
        "groups": group_info, "dap": dap, "rules": rules[:20],
        "usage_24h": {"down": usage.get("download_bytes") or 0, "up": usage.get("upload_bytes") or 0},
        "blocked_24h": blocked,
        "local": [{"mac": m, "name": recent_flow_device_name(m if ":" in m else "", m), "flows": f, "blocked": bool(b)} for m, f, b in local],
        "outbound": outbound, "alarms": alarms,
    }


@app.get("/api/internet-page")
def api_internet_page():
    """The Internet page: both WANs, inbound blocked and allowed, paths."""
    return internet_page_data()


@app.post("/api/internet/speedtest-ack")
def api_internet_speedtest_ack(payload: dict = Body(default={})):
    """Acknowledge a WAN's latest (slow) speed test: wan = the WAN key."""
    key = str(payload.get("wan") or "")[:40]
    wan = next((w for w in (internet_page_cache["data"] or internet_page_data()).get("wans") or [] if w["key"] == key), None)
    if not wan or not wan["tests"]:
        return {"ok": False, "error": "No speed test for that connection"}
    with internet_page_lock:
        acks = policy_read_json(SPEEDTEST_ACK_FILE) or {}
        acks[key] = wan["tests"][-1]["at"]
        temporary = SPEEDTEST_ACK_FILE + ".tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump(acks, handle)
        os.replace(temporary, SPEEDTEST_ACK_FILE)
        # Rebuilt now, so Overview's Needs a Look drops it at once.
        internet_page_cache["data"] = internet_page_build()
        internet_page_cache["at"] = time.time()
    return {"ok": True}


# ============================================================
# FIREWALLA MSP (read only): what the router doesn't send
#
# Read with a READ-ONLY MSP access token: /run/secrets/msp_api_token,
# mounted from ssh\msp_api_token.txt; FIREWALLA_MSP_URL is the MSP address.
# Only this router's box is used (the MSP box whose devices match the
# router's; another box in the MSP is left out). Every 5 minutes:
#   your own target lists (ids "TL-...") with their entries, for the rule
#   popup (an entry is "address" or "address,tcp:554,2020");
#   the alarms of the last 30 days (the MSP keeps 30), for the Alarms page.
# The dashboard never changes anything in the MSP. The last read is kept
# in /data/msp_cache.json and loaded at start, so target lists and alarms
# are there at once after a restart, and while the internet is down (shown
# with when they were read).
# /api/rule/<pid>: a rule, both its sides with the devices they cover
# (target-list entries matched to devices by address) and its last hit.
# ============================================================

MSP_URL = os.environ.get("FIREWALLA_MSP_URL", "").rstrip("/")
MSP_TOKEN_FILE = os.environ.get("FIREWALLA_MSP_TOKEN_FILE", "/run/secrets/msp_api_token")
MSP_SECONDS = 300
MSP_CACHE_FILE = os.environ.get("FIREWALLA_MSP_CACHE_FILE", "/data/msp_cache.json")
# Alarm type numbers (MSP data model); the "_type" name is used first.
MSP_ALARM_TYPES = {1: "Security Activity", 2: "Abnormal Upload", 3: "Large Bandwidth Usage", 4: "Monthly Data Plan",
                   5: "New Device", 6: "Device Back Online", 7: "Device Offline", 8: "Video Activity",
                   9: "Gaming Activity", 10: "Porn Activity", 11: "VPN Activity", 12: "VPN Connection Restored",
                   13: "VPN Connection Error", 14: "Open Port", 15: "Internet Connectivity Update", 16: "Large Upload"}
MSP_WORDS = {"VPN": "VPN", "WAN": "WAN", "DUAL": "Dual"}


def msp_get(path, token):
    response = requests.get(f"{MSP_URL}{path}", headers={"Authorization": f"Token {token}"}, timeout=30)
    response.raise_for_status()
    return response.json()


def msp_box(token):
    """This router's box in the MSP: the one most of whose devices the router knows."""
    if msp["box"]:
        return msp["box"]
    known = {str(d.get("mac") or "").upper() for d in state.get("devices") or []}
    if not known:
        raise RuntimeError("waiting for the router's client list")
    votes = Counter(d.get("gid") for d in msp_get("/v2/devices", token) if str(d.get("mac") or "").upper() in known)
    if not votes:
        raise RuntimeError("no MSP box has this router's clients")
    msp["box"] = votes.most_common(1)[0][0]
    return msp["box"]


def time_24h(text):
    """Firewalla's "at about 09:03 PM" in 24-hour form ("21:03")."""
    def to24(m):
        h, mm, half = int(m.group(1)), m.group(2), m.group(3).upper()
        return f"{(h % 12) + (12 if half == 'PM' else 0):02d}:{mm}"
    return re.sub(r"\b(\d{1,2}):(\d{2})\s*([AaPp][Mm])\b", to24, str(text or ""))


def msp_alarm(a):
    """An MSP alarm in the few fields the Alarms page shows (times in
    messages in 24-hour form)."""
    kind = str(a.get("_type") or "")
    name = (" ".join(MSP_WORDS.get(w, w.capitalize()) for w in kind.removeprefix("ALARM_").split("_"))
            if kind.startswith("ALARM_") else MSP_ALARM_TYPES.get(a.get("type"), f"Type {a.get('type')}"))
    device, remote, transfer = a.get("device") or {}, a.get("remote") or {}, a.get("transfer") or {}
    return {
        "aid": a.get("aid"), "ts": a.get("ts"), "kind": name, "status": "active" if a.get("status") == 1 else "archived",
        "message": time_24h(a.get("message")), "direction": a.get("direction"),
        "device": {"mac": str(device.get("id") or "").upper(), "name": device.get("name"), "ip": device.get("ip"),
                   "group": (device.get("group") or {}).get("name"), "network": (device.get("network") or {}).get("name")}
                  if device.get("id") else None,
        "remote": {"name": remote.get("domain") or remote.get("ip"), "ip": remote.get("ip"),
                   "country": remote.get("country") or remote.get("region")} if remote else None,
        "bytes": sum(v for k, v in transfer.items() if k in ("upload", "download") and isinstance(v, (int, float))) or None,
    }


def msp_alarm_summary(alarms, at):
    """Counts for Status and the Overview: active, total, last 24 hours and
    the most common kinds still active."""
    kinds = {}
    for a in alarms:
        if a["status"] == "active":
            kinds[a["kind"]] = kinds.get(a["kind"], 0) + 1
    return {"active": sum(kinds.values()), "total": len(alarms), "at": at,
            "last_24h": sum(1 for a in alarms if time.time() - (a.get("ts") or 0) < 86400),
            "top_active": sorted(kinds.items(), key=lambda kv: -kv[1])[:3]}


def msp_cache_load():
    try:
        with open(MSP_CACHE_FILE, encoding="utf-8") as handle:
            saved = json.load(handle)
        msp.update({k: saved[k] for k in ("at", "box", "lists", "alarms", "alarms_at") if k in saved})
        state["msp_alarms"] = msp_alarm_summary(msp["alarms"], msp["alarms_at"])
    except (OSError, ValueError, KeyError, TypeError):
        pass


def msp_cache_save():
    temporary = MSP_CACHE_FILE + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump({k: msp[k] for k in ("at", "box", "lists", "alarms", "alarms_at")}, handle)
    os.replace(temporary, MSP_CACHE_FILE)


def msp_lists_read(token):
    """Your own target lists (ids "TL-..."), read from the MSP now."""
    msp["lists"] = {
        str(t["id"]): {"name": t.get("name"), "notes": t.get("notes") or "", "targets": t.get("targets") or [],
                       "count": t.get("count"), "last_updated": t.get("lastUpdated")}
        for t in msp_get("/v2/target-lists", token) if str(t.get("id") or "").startswith("TL-")}
    msp["lists_at"] = time.time()


def msp_lists_now():
    """List Check's Check Now (24 Nov 2026, D-1063): the lists again, so a change
    just made on the MSP counts (the worker reads them every 5 minutes). Not
    more than once in 15 seconds. -> None, or why they couldn't be read."""
    if not MSP_URL or time.time() - (msp.get("lists_at") or 0) < 15:
        return None
    try:
        with open(MSP_TOKEN_FILE, encoding="utf-8") as handle:
            msp_lists_read(handle.read().strip())
        msp["at"] = time.time()
        return None
    except Exception as exc:
        return public_error("Firewalla MSP", exc)


def msp_worker():
    msp_cache_load()
    time.sleep(30)   # let the router's device list arrive first
    while True:
        try:
            if not MSP_URL:
                raise RuntimeError("FIREWALLA_MSP_URL is not set")
            with open(MSP_TOKEN_FILE, encoding="utf-8") as handle:
                token = handle.read().strip()
            box = msp_box(token)
            try:   # the router's Firewalla version, for Equipment Health
                info = next((b for b in msp_get("/v2/boxes", token) if b.get("gid") == box), None) or {}
                equipment_health_router_version(info.get("version"))
                # Firewalla's cloud's view of the router (Equipment Health's
                # Router table, 22 Nov 2026): online, and when it last heard it.
                seen = info.get("lastSeen")
                state["msp_box"] = {"online": info.get("online"), "version": info.get("version"), "at": time.time(),
                                    "last_seen": (seen / 1000 if isinstance(seen, (int, float)) and seen > 1e12 else seen)}
            except Exception as exc:
                print("MSP box version error:", exc)
            msp_lists_read(token)
            alarms, cursor = [], None
            for _ in range(5):   # 500 a page; the MSP keeps 30 days
                page = msp_get("/v2/alarms?limit=500&query=" + requests.utils.quote(f"box.id:{box}")
                               + (f"&cursor={requests.utils.quote(cursor)}" if cursor else ""), token)
                alarms += [msp_alarm(a) for a in page.get("results") or [] if a.get("gid") == box]
                cursor = page.get("next_cursor")
                if not cursor:
                    break
            msp.update({"alarms": sorted(alarms, key=lambda a: -(a["ts"] or 0)), "alarms_at": time.time(),
                        "at": time.time(), "error": None})
            # Keep the page's counts (needs a look...) until it rebuilds them just below, so Needs You
            # never falls back to every active alarm in between (26 Nov 2026).
            state["msp_alarms"] = {**(state.get("msp_alarms") or {}), **msp_alarm_summary(alarms, msp["alarms_at"])}
            msp_cache_save()
            try:
                with alarm_lock:
                    # Severity, dismissed and learned counts for Status and Overview; kept for the page too.
                    alarms_page_cache.update(page=alarms_page_build(), at=time.time())
            except Exception as exc:
                print("Alarms page error:", exc)
        except Exception as exc:
            msp["error"] = f"{type(exc).__name__}: {exc}"
            print("MSP error:", msp["error"])
        time.sleep(MSP_SECONDS)


# ============================================================
# ALARMS PAGE: Firewalla's alarms, handled in the dashboard
#
# Agreed 14 Nov 2026: the dashboard is where alarms are handled day to
# day; the app and MSP only to change Firewalla itself (the MSP key is
# read-only). Each alarm gets a severity:
#   critical  never normal: security / intel, open port, a VPN connection
#             from a peer that isn't set up, every WAN down. Red on Status.
#   high      unusual for the device: an IoT device's (or camera's) big
#             upload to somewhere that isn't its learned normal; a new
#             device on a wired or admin network (not a private MAC).
#   normal    the rest (a PC or phone using its cloud, a camera its relay,
#             a WAN failover). A repeat (3+ alike in 7 days) drops a level.
# Needs a Look = active, not dismissed and not learned. Dismiss = that
# alarm only; Mark Normal = learn its pattern (kind, device, destination's
# base domain, size): later alarms alike are filed as Learned unless 10x
# bigger, somewhere else or another device. Critical can't be learned.
# Suggestions = repeats (2+ alike in 7 days) not learned or declined.
# Nothing is written to Firewalla. Kept in /data/alarm_state.json.
# ============================================================

ALARM_STATE_FILE = os.environ.get("FIREWALLA_ALARM_STATE_FILE", "/data/alarm_state.json")
ALARM_SEVERITY = {"critical": 3, "high": 2, "normal": 1}
ALARM_CRITICAL_KINDS = ("security", "intel", "open port", "malware")
ALARM_UPLOAD_KINDS = ("Large Upload", "Abnormal Upload", "Abnormal Bandwidth Usage", "Large Bandwidth Usage")
ALARM_GROWTH_FACTOR = 10
# A device's own maker's cloud is normal for it: maker word -> the words
# its cloud domains contain.
ALARM_MAKER_CLOUDS = {"tp-link": ("tplink", "tapo", "kasa"), "anker": ("eufy", "anker"), "amazon": ("amazon", "a2z", "amazonaws"),
                      "google": ("google", "nest", "gstatic"), "ring": ("ring.com", "amazon"), "espressif": ("birdbuddy", "mybirdbuddy"),
                      "lg": ("lge.com", "lgthinq"), "roborock": ("roborock",), "chamberlain": ("myq", "chamberlain")}
# Phones, tablets and computers are judged as personal devices on any network.
ALARM_PERSONAL_WORDS = ("phone", "iphone", "ipad", "tab", "pc ", "laptop", "macbook", "android")


def alarm_maker_cloud(vendor, remote):
    vendor, remote = str(vendor or "").lower(), str(remote or "").lower()
    return any(maker in vendor and any(word in remote for word in words) for maker, words in ALARM_MAKER_CLOUDS.items())
alarm_lock = threading.Lock()


def alarm_state_load():
    st = policy_read_json(ALARM_STATE_FILE) or {}
    for key in ("dismissed", "learned", "declined", "pinned"):
        st.setdefault(key, {})
    return st


def alarm_state_save(st):
    temporary = ALARM_STATE_FILE + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(st, handle, indent=1)
    os.replace(temporary, ALARM_STATE_FILE)


def alarm_pattern(a):
    """What makes two alarms alike: kind, device and destination's base
    domain (a WAN alarm: its kind alone)."""
    device = (a.get("device") or {}).get("mac") or ""
    remote = (a.get("remote") or {}).get("name") or ""
    base = outbound_base(remote) if remote else ""
    # Bare addresses (cloud servers that change every time) count as one
    # destination, so repeats and Mark Normal cover them.
    if base and (base.replace(".", "").isdigit() or ":" in base):
        base = "any IP address"
    return "|".join([a.get("kind") or "", device, base])


def alarm_learned_match(a, learned):
    rule = learned.get(alarm_pattern(a))
    if not rule:
        return None
    if a.get("bytes") and rule.get("max_bytes") and a["bytes"] > ALARM_GROWTH_FACTOR * rule["max_bytes"]:
        return None
    return rule


def alarm_severity(a, history, iot_macs, peers, wans_down, vendors=None):
    """(severity, why) for one alarm."""
    kind = str(a.get("kind") or "")
    low = kind.lower()
    device = a.get("device") or {}
    mac = str(device.get("mac") or "")
    if any(w in low for w in ALARM_CRITICAL_KINDS):
        return "critical", "a security alarm is never normal"
    if kind == "VPN Client Connection":
        if device.get("name") and device.get("name") in peers:
            sev, why = "normal", f"{device.get('name')} is one of your VPN peers"
        else:
            return "critical", "a VPN connection from a peer that isn't set up"
    elif kind == "Dual WAN":
        if wans_down:
            return "critical", "no WAN is up"
        sev, why = "normal", "a WAN change; the other WAN carried the traffic"
    elif kind == "New Device":
        network = str(device.get("network") or "").lower()
        private = re.match(r"^[0-9A-F]{2}:", mac.upper()) and int(mac[:2], 16) & 2
        if not private and ("wired" in network or "admin" in network):
            sev, why = "high", "a new client on a wired or admin network"
        else:
            sev, why = "normal", "a new client on " + (device.get("network") or "the network") + (" (private MAC)" if private else "")
    elif kind in ALARM_UPLOAD_KINDS:
        remote = (a.get("remote") or {}).get("name") or ""
        known = remote and outbound_base(remote) in history.get(mac.upper(), set())
        maker = alarm_maker_cloud((vendors or {}).get(mac.upper()), remote)
        personal = any(w in (str(device.get("name") or "") + " ").lower() for w in ALARM_PERSONAL_WORDS)
        if maker:
            sev, why = "normal", "its maker's own cloud"
        elif mac.upper() in iot_macs and not known and not personal:
            sev, why = "high", "an IoT client or camera sending a lot somewhere it doesn't normally"
        else:
            sev, why = "normal", ("a destination this client uses" if known else "a phone, PC or TV using the internet")
    else:
        sev, why = "normal", "no rule ranks this kind higher"
    return sev, why


def alarm_bytes_text(n):
    return f"{n / 1e9:.1f} GB" if n >= 1e9 else f"{n / 1e6:.1f} MB" if n >= 1e6 else f"{n / 1e3:.0f} KB"


def alarm_analysis(row, rows, st, vendors, iot, history, outbound_open):
    """The dashboard's analysis of one alarm (rules and history, not AI):
    what it probably is, its history, the device's context, what was done
    with alike ones, and a suggested action. Shown on hover and in the
    alarm's popup on the Alarms page."""
    kind = row.get("kind") or ""
    device = row.get("device") or {}
    mac = str(device.get("mac") or "").upper()
    name = device.get("name") or "this client"
    remote = (row.get("remote") or {}).get("name") or ""
    size = row.get("bytes") or 0
    alike = [r for r in rows if r["pattern"] == row["pattern"]]
    earlier = [r for r in alike if (r.get("ts") or 0) < (row.get("ts") or 0)]
    sizes = sorted(r["bytes"] for r in alike if r.get("bytes"))
    usual = sizes[len(sizes) // 2] if sizes else None
    maker = alarm_maker_cloud(vendors.get(mac), remote)
    personal = any(w in (name + " ").lower() for w in ALARM_PERSONAL_WORDS)
    is_iot = mac in iot and not personal
    known = remote and outbound_base(remote) in history.get(mac, set())
    vendor = (vendors.get(mac) or "").split(",")[0].split(" ")[0] or "its maker"
    # What it probably is
    if kind in ALARM_UPLOAD_KINDS and kind != "Abnormal Bandwidth Usage":
        if maker:
            likely = f"{name} sending data (likely video clips or a status upload) to {vendor}'s own cloud."
        elif personal or not is_iot:
            likely = f"An app on {name} uploading to {remote or 'a cloud service'}: a backup, a sync or a file upload is the usual cause."
        elif known:
            likely = f"{name} uploading to {outbound_base(remote)}, a destination it has used before."
        else:
            likely = f"Unusual: {name} (an IoT client or camera) sent {alarm_bytes_text(size) if size else 'a lot'} to {remote or 'an address'} that isn't its maker or a usual destination."
    elif kind == "Abnormal Bandwidth Usage":
        likely = f"Heavy use by {name}" + (": streaming, downloads or updates are the usual cause." if not is_iot else ", unusual for an IoT client.")
    elif kind == "VPN Client Connection":
        likely = (row.get("message") or "A VPN connection.") + (" This is one of your VPN peers." if row["severity"] != "critical" else " This peer isn't set up on the router.")
    elif kind == "Dual WAN":
        likely = (row.get("message") or "A WAN change.") + " Traffic moves to the other WAN automatically."
    elif kind == "New Device":
        private = re.match(r"^[0-9A-F]{2}:", mac) and int(mac[:2], 16) & 2
        likely = (f"A phone, tablet or laptop joining {device.get('network') or 'the network'} with a private (randomised) address: often a client you already have."
                  if private else f"A client not seen before joined {device.get('network') or 'the network'}.")
    else:
        likely = row.get("message") or kind
    # History
    hist = (f"{len(alike)} alike in 30 days (first {time.strftime('%m/%d', time.localtime(alike[-1].get('ts') or 0))})"
            if len(alike) > 1 else "the only one like it in 30 days")
    if usual and size:
        ratio = size / usual
        hist += f" · usually {alarm_bytes_text(usual)}" + (f", this one {ratio:.1f}x that" if ratio >= 1.5 or ratio <= 0.5 else ", this one about the same")
    # Context
    context = []
    if device:
        context.append(("IoT client or camera" if is_iot else "phone, PC or TV") + (f" · {device.get('group')}" if device.get("group") else "") +
                       (f" · {device.get('network')}" if device.get("network") else ""))
    if remote:
        context.append(f"Destination {outbound_base(remote)}: " + ("its maker's cloud" if maker else "one it uses normally" if known else "not one it normally uses"))
    if outbound_open.get(mac):
        context.append(f"{outbound_open[mac]} open Outbound item(s) for this client")
    done = []
    dismissed = sum(1 for r in earlier if r.get("dismissed"))
    if dismissed:
        done.append(f"you dismissed {dismissed} alike before")
    if row["pattern"] in st["learned"]:
        done.append("you marked this pattern Normal: " + (st["learned"][row["pattern"]].get("reason") or ""))
    if row["pattern"] in st["declined"]:
        done.append("you said this pattern isn't normal")
    # Suggested action
    if row["severity"] == "critical":
        action = ("Look now", "a critical alarm is never normal; check the client and archive it in the app when handled")
    elif row["pattern"] in st["declined"]:
        action = ("Look", "you said alarms like this aren't normal")
    elif row["severity"] == "high":
        action = ("Look", "unusual for an IoT client or camera" + ("; it has happened before, so if you know where it goes (for example the maker's servers), Mark Normal" if earlier else ""))
    elif maker or len(alike) >= 3:
        action = ("Mark Normal", ("it repeats with a similar size" if sizes else f"it repeats ({len(alike)} in 30 days)") if len(alike) >= 3 else "its maker's own cloud")
    else:
        action = ("Dismiss", "a one-off with nothing unusual about it")
    return {"likely": likely, "history": hist, "context": context, "done": done, "action": action[0], "action_why": action[1]}


def alarms_device(device):
    """An alarm's client, marked (owner, 23 Nov 2026): "peer" for a VPN
    connection (D-973), "gone" for a client the router no longer lists
    (D-972, as Outbound Review's D-960)."""
    if not isinstance(device, dict):
        return device
    d = dict(device)
    if "_PEER:" in str(d.get("mac") or ""):
        d["peer"] = True
        return d
    return outbound_gone(d)


def alarms_page_build(now=None):
    now = now or time.time()
    st = alarm_state_load()
    alarms = list(msp.get("alarms") or [])
    # What each device normally reaches (internet store, all history) and
    # which devices are IoT (Device Active Protect or IoT-like network/group).
    history = {}
    try:
        with internet_traffic_connection() as connection:
            for mac, dest in connection.execute("SELECT DISTINCT device_mac, destination FROM internet_traffic_daily"):
                history.setdefault(mac, set()).add(outbound_base(dest))
    except Exception:
        pass
    _, _, dap = outbound_rules()
    iot = set(dap.values())
    net_names = {i.get("target"): i.get("display_name") or i.get("name") for i in state.get("interfaces") or []}
    member_of = {}
    for g in (state.get("groups") or {}).get("groups") or []:
        for m in g.get("members") or []:
            member_of.setdefault(str(m).upper(), []).append(str(g.get("id")))
    for d in state.get("devices") or []:
        mac = str(d.get("mac") or "").upper()
        if outbound_device(mac, d.get("ip"), net_names.get(d.get("interface_uuid"), ""), member_of.get(mac, []), iot)["class"] == "iot":
            iot.add(mac)
    peers = {p.get("name") for ps in (state.get("vpn_peers") or {}).values() for p in ps or []}
    vendors = {str(d.get("mac") or "").upper(): d.get("vendor") for d in state.get("devices") or []}
    wans = (state.get("internet") or {}).get("wans") or {}
    wans_down = bool(wans) and not any(w.get("ready") for w in wans.values())
    week = [a for a in alarms if now - (a.get("ts") or 0) < 7 * 86400]
    alike = Counter(alarm_pattern(a) for a in week)
    rows = []
    hidden = traffic_hidden_resolve()
    for a in alarms:
        sev, why = alarm_severity(a, history, iot, peers, wans_down, vendors)
        pattern = alarm_pattern(a)
        if sev != "critical" and alike[pattern] >= 3:
            sev = "normal" if sev == "high" else sev
            why += f" · {alike[pattern]} alike this week"
        aid = str(a.get("aid"))
        learned = None if sev == "critical" else alarm_learned_match(a, st["learned"])
        # A destination you hid on Traffic: its alarms come in as Hidden (no
        # review); a Critical one still asks for you (the user, 15 Nov 2026).
        remote = a.get("remote") or {}
        hid = sev != "critical" and bool(hidden) and traffic_is_hidden(hidden, (a.get("device") or {}).get("mac"), remote.get("name"), remote.get("ip"))
        status = "archived" if a.get("status") != "active" else "dismissed" if aid in st["dismissed"] \
            else "hidden" if hid else "learned" if learned else "active"
        rows.append({**a, "device": alarms_device(a.get("device")), "aid": aid, "severity": sev, "why": why, "pattern": pattern, "state": status,
                     "dismissed": st["dismissed"].get(aid), "learned_as": learned.get("reason") if learned else None,
                     "pinned": st["pinned"].get(aid)})
    for rule in st["learned"].values():
        rule["silenced"] = sum(1 for r in rows if r["pattern"] == rule["pattern"] and r["state"] == "learned")
    outbound_open = Counter((i.get("device") or {}).get("mac") for i in outbound_state_load()["items"].values()
                            if i.get("status") in ("open", "needs_attention"))
    for r in rows:
        r["analysis"] = alarm_analysis(r, rows, st, vendors, iot, history, outbound_open)
    needs = sorted([r for r in rows if r["state"] == "active"], key=lambda r: (-ALARM_SEVERITY[r["severity"]], -(r.get("ts") or 0)))
    # Suggestions: patterns seen 2+ times this week, not learned or declined, never critical.
    suggestions = []
    for pattern, count in alike.most_common():
        if count < 2 or pattern in st["learned"] or pattern in st["declined"]:
            continue
        sample = [r for r in rows if r["pattern"] == pattern and now - (r.get("ts") or 0) < 7 * 86400]
        if not sample or any(r["severity"] == "critical" for r in sample):
            continue
        sizes = [r["bytes"] for r in sample if r.get("bytes")]
        first = sample[0]
        suggestions.append({"pattern": pattern, "kind": first.get("kind"), "device": first.get("device"),
                            "destination": pattern.split("|")[2] or None,
                            "count": count, "min_bytes": min(sizes) if sizes else None, "max_bytes": max(sizes) if sizes else None,
                            "last": max(r.get("ts") or 0 for r in sample), "aid": first["aid"]})
    per_day = Counter(time.strftime("%Y-%m-%d", time.localtime(r.get("ts") or 0)) for r in rows)
    counts = {
        "needs_look": len(needs), "needs_at": max([r.get("ts") or 0 for r in needs] or [0]),   # for the menu's * colour
        "critical": sum(1 for r in needs if r["severity"] == "critical"),
        "high": sum(1 for r in needs if r["severity"] == "high"),
        "dismissed": sum(1 for r in rows if r["state"] == "dismissed"),
        "learned": sum(1 for r in rows if r["state"] == "learned"),
        "hidden": sum(1 for r in rows if r["state"] == "hidden"),
        "archived": sum(1 for r in rows if r["state"] == "archived"),
        "active_at_firewalla": sum(1 for r in rows if r.get("status") == "active"),
        "last_24h": sum(1 for r in rows if now - (r.get("ts") or 0) < 86400),
        "last_7d": len(week), "total": len(rows),
    }
    state["msp_alarms"] = {**msp_alarm_summary(alarms, msp.get("alarms_at")), **counts,
                           "top_needs": [[r["kind"], r["severity"]] for r in needs[:3]],
                           # For the Critical Alarm email (alert_worker).
                           "critical_list": [{"aid": r["aid"], "kind": r.get("kind"), "message": r.get("message"), "ts": r.get("ts"),
                                              "device": (r.get("device") or {}).get("name"), "why": r.get("why"),
                                              "likely": (r.get("analysis") or {}).get("likely")}
                                             for r in needs if r["severity"] == "critical"]}
    return {"at": msp.get("alarms_at"), "error": msp.get("error"), "counts": counts, "needs": needs, "alarms": rows,
            "suggestions": suggestions[:8],
            "learned": sorted(st["learned"].values(), key=lambda r: -r.get("at", 0)),
            "per_day": sorted(per_day.items()),
            "by_kind": Counter(r.get("kind") for r in rows).most_common(),
            "noisy": [{"mac": mac, "name": name, "count": n, "peer": "_PEER:" in str(mac or ""),
                       "gone": any((r.get("device") or {}).get("gone") for r in rows if (r.get("device") or {}).get("mac") == mac)} for (mac, name), n in
                      Counter(((r.get("device") or {}).get("mac"), (r.get("device") or {}).get("name")) for r in rows if r.get("device")).most_common(6)]}


ALARMS_PAGE_KEEP_SECONDS = 20
alarms_page_cache = {"at": 0, "page": None}


@app.get("/api/alarms-page")
def api_alarms_page():
    # Built at most every 20 seconds (and again after any action on it): the
    # page asks every few seconds while Claude is answering, and each build
    # went through up to 2,500 alarms and a year of daily traffic.
    with alarm_lock:
        if not alarms_page_cache["page"] or time.time() - alarms_page_cache["at"] > ALARMS_PAGE_KEEP_SECONDS:
            alarms_page_cache.update(page=alarms_page_build(), at=time.time())
        page = dict(alarms_page_cache["page"])
    with claude_lock:
        page["claude"] = claude_public(claude_load(), "alarm")
    return page


@app.post("/api/alarms/act")
def api_alarms_act(payload: dict = Body(default={})):
    """action: dismiss | undismiss (aids, note) · pin | unpin (aids; owner,
    18 Nov 2026: kept at the top of the page) · learn (aid, reason) ·
    forget (pattern) · decline (pattern)."""
    action = payload.get("action")
    fields = Fields(payload)
    aids = fields.strings("aids", 500, 100)
    pattern = fields.text("pattern", 300, strip=False)
    with alarm_lock:
        alarms_page_cache["at"] = 0   # the page is built again after this
        st = alarm_state_load()
        now = time.time()
        by_aid = {str(a.get("aid")): a for a in msp.get("alarms") or []}
        if action == "dismiss":
            for aid in aids:
                st["dismissed"][aid] = {"at": now, "note": fields.text("note", 300, strip=False)}
        elif action == "undismiss":
            for aid in aids:
                st["dismissed"].pop(aid, None)
        elif action == "pin":
            for aid in aids:
                if aid in by_aid:
                    st["pinned"][aid] = now
        elif action == "unpin":
            for aid in aids:
                st["pinned"].pop(aid, None)
        elif action == "learn":
            reason = fields.text("reason", 500)
            a = by_aid.get(str(payload.get("aid"))[:100])
            if not a:
                return {"ok": False, "error": "no such alarm"}
            if not reason:
                return {"ok": False, "error": "say why it's normal"}
            page = alarms_page_build(now)
            row = next((r for r in page["alarms"] if r["aid"] == str(a.get("aid"))), None)
            if row and row["severity"] == "critical":
                return {"ok": False, "error": "a critical alarm can't be learned"}
            pattern = alarm_pattern(a)
            sizes = [x.get("bytes") for x in msp.get("alarms") or [] if alarm_pattern(x) == pattern and x.get("bytes")]
            st["learned"][pattern] = {"pattern": pattern, "kind": a.get("kind"), "device": a.get("device"),
                                      "destination": pattern.split("|")[2] or None,
                                      "max_bytes": max(sizes) if sizes else None, "reason": reason[:300], "at": now}
            st["declined"].pop(pattern, None)
        elif action == "forget":
            st["learned"].pop(pattern, None)
        elif action == "decline":
            if pattern:
                st["declined"][pattern] = now
        else:
            return {"ok": False, "error": "unknown action"}
        alarm_state_save(st)
        return {"ok": True, "page": alarms_page_build(now)}


def rule_target_entry(text, by_ip):
    """'192.168.10.51,tcp:554,2020' -> address, ports and the device using it."""
    address, _, ports = str(text).partition(",")
    protocol, _, numbers = ports.partition(":")
    device = by_ip.get(address.strip())
    return {"text": text, "address": address.strip(),
            "ports": f"{protocol.upper()} {numbers.replace(',', ', ')}" if numbers else (protocol.upper() or "all ports"),
            "device": {"mac": device["mac"], "name": device["name"]} if device else None}


def rule_side(obj, sides, by_ip):
    """One side of a rule in words, with the devices it covers."""
    obj = obj or {}
    out = {"kind": obj.get("kind"), "label": obj.get("label") or obj.get("name") or "--", "name": obj.get("name")}
    if obj.get("kind") == "target_list":
        tl = msp["lists"].get(str(obj.get("id")))
        if tl:
            out.update({"name": tl["name"], "notes": tl["notes"], "last_updated": tl["last_updated"],
                        "entries": [rule_target_entry(t, by_ip) for t in tl["targets"]]})
        elif str(obj.get("id") or "").startswith("TL-"):
            out["entries_error"] = msp["error"] or "list not found in your MSP"
    elif obj.get("kind") in ("device", "group", "network"):
        out["devices"] = sorted(({"mac": s["mac"], "name": s["name"], "ip": s.get("ip")}
                                 for s in sides.values() if access_covers(obj, s)), key=lambda d: d["name"].lower())
    return out


@app.get("/api/rules-page")
def api_rules_page():
    """The Rules and Groups pages' extras: your target lists' names, sizes
    and entries (the router sends only their ids), read from your MSP. The
    entries let Groups see a domain rule that contradicts one of your lists."""
    return {"lists": {lid: {"name": l.get("name"), "count": l.get("count"), "targets": l.get("targets") or []}
                      for lid, l in (msp.get("lists") or {}).items()},
            "lists_at": msp.get("at")}


@app.get("/api/rule-names")
def api_rule_names():
    """Every rule's number, name and action, for the hover tips (owner, 22
    Nov 2026): a rule number shows its name, a rule name its number. name is
    what you called it in the Firewalla app ("" when unnamed); text is what
    the dashboard shows for it either way."""
    return {pid: {"name": r.get("display_name") or r.get("name") or "", "text": access_rule_text(r), "action": r.get("action") or ""}
            for pid, r in list(router.policy_rules_by_pid.items())}


@app.get("/api/rule/{pid}")
def api_rule(pid: str):
    rule = policy_rule_for_pid(pid)
    if not rule:
        return {"error": f"No rule #{pid} on the router"}
    sides, _ = access_sides()
    by_ip = {s["ip"]: s for s in sides.values() if s.get("ip")}
    hit = rule.get("last_hit") or {}
    name = lambda mac: (sides.get(str(mac or "").upper()) or {}).get("name")
    return {
        "pid": rule["pid"], "name": rule.get("display_name") or access_rule_text(rule), "text": access_rule_text(rule),
        "action": rule.get("action"), "direction": rule.get("direction") or "bidirection", "active": rule.get("active"),
        "purpose": rule.get("purpose"), "hit_count": rule.get("hit_count"), "last_hit_ts": rule.get("last_hit_ts"),
        "created_at": rule.get("created_at"),
        "from": rule_side(rule.get("applies_on"), sides, by_ip),
        "to": rule_side(rule.get("matching"), sides, by_ip),
        "last_hit": {"from": name(hit.get("device")) or hit.get("device_ip"), "to": name(hit.get("dst_mac")) or hit.get("ip"),
                     "port": f"{str(hit.get('protocol') or '').upper()} {hit.get('port') or ''}".strip(), "at": hit.get("ts")}
                    if hit else None,
        "target_lists_at": msp["at"],
    }


@app.get("/api/group/{gid}")
def api_group(gid: str):
    """The group popup: a Policy page side ("g<id>" = a Firewalla group,
    "n<network>" = devices in no group on that network) with its members
    and, for a group, its VqLAN / Isolation settings and allowed list."""
    sides, groups = access_sides()
    member = lambda s: {"mac": s["mac"], "name": s["name"], "ip": s.get("ip"), "online": s.get("online"),
                        "network": s.get("network_name")}
    if gid.startswith("g") and gid[1:] in groups:
        g = groups[gid[1:]]
        members = [member(s) for s in sides.values() if gid[1:] in s["groups"]]
        return {"id": gid, "kind": "group", "name": g.get("name"), "vqlan": g.get("vqlan"), "isolation": g.get("isolation"),
                # set_on: whose list the entry is in (this group's own, or another
                # group's list naming this group or, via, some of its members).
                "allowed": [{"name": a.get("name"), "kind": a.get("kind"), "pid": a.get("pid"),
                             "own": str(a.get("set_on")) == gid[1:], "via": a.get("via") or []} for a in g.get("allowed") or []],
                "members": sorted(members, key=lambda m: m["name"].lower())}
    if gid.startswith("n"):
        network = gid[1:]
        members = [member(s) for s in sides.values()
                   if (s.get("network") or "none") == network and not any(str(x) in groups for x in s["groups"])]
        label = internet_interface_name(network) if network != "none" else "No network"
        return {"id": gid, "kind": "network", "name": f"{label} (no group)", "members": sorted(members, key=lambda m: m["name"].lower())}
    return {"error": f"No group {gid}"}


# ============================================================
# TEST A WEBSITE: what one device was blocked from while you used a site
#
# You start a test for a device (the one the browser is on, found by its
# address, or one you pick), use the site or app on it, then stop (at most
# 10 minutes). The device's flow records in that window (flow history) are
# split into:
#   blocked for this site   new in the window, or 3x the 10 minutes before,
#                           or part of the site's own domain
#   other blocks            the device's steady background (seen before
#                           the test at the same rate, or known telemetry)
#   loaded fine             allowed connections in the window
# Each blocked domain carries the rule that blocked it and how (DNS: the
# name was refused; else the connection was). A test's results are saved
# with it when it ends, because raw flows are kept only 24 hours. Tests are
# kept 30 days in /data/site_tests.json. Nothing is changed at Firewalla.
# ============================================================

SITE_TEST_FILE = os.environ.get("FIREWALLA_SITE_TESTS_FILE", "/data/site_tests.json")
SITE_TEST_MAX_SECONDS = 600
SITE_TEST_KEEP_SECONDS = 30 * 86400
SITE_TEST_SETTLE_SECONDS = 60    # flow records arrive a few seconds late; rule hit counters up to ~40 s late
site_test_lock = threading.Lock()

# What a domain usually does: (words in the name, what it is, needed by
# some sites, everyday background). First match wins.
SITE_TEST_KINDS = [
    (("imasdk.googleapis.com",), "video ad player (needed by some video sites)", True, False),
    (("adtrafficquality.google",), "ad fraud check (needed by some video players)", True, False),
    (("googletagmanager.com",), "tag manager (needed by some sites)", True, False),
    (("recaptcha", "hcaptcha", "challenges.cloudflare.com", "arkoselabs"), "robot check (needed for sign-ins and forms)", True, False),
    (("login.", "auth.", "accounts.", "sso.", "okta", "auth0"), "sign-in (needed)", True, False),
    (("connect.facebook.net", "graph.facebook.com"), "Facebook sign-in and share (needed for Facebook logins)", True, False),
    (("paypal", "stripe.com", "braintree"), "payments (needed at checkout)", True, False),
    (("jwplayer", "brightcove", "vimeocdn", "ytimg.com", "googlevideo.com"), "video player (needed)", True, False),
    (("fundingchoicesmessages.google.com", "consensu.org", "cookielaw.org", "onetrust", "cookiebot", "trustarc"),
     "cookie consent box (some sites wait for it before showing content)", True, False),
    (("doubleclick.net", "googlesyndication.com", "googleadservices.com", "adnxs.com", "amazon-adsystem.com", "criteo",
      "taboola", "outbrain", "pubmatic", "rubiconproject", "adsrvr.org", "moatads", "openx.net", "casalemedia",
      "tblcontent.com", "adsafeprotected.com", "doubleverify", "media.net", "teads", "sharethrough", "33across"), "ads", False, False),
    (("google-analytics.com", "analytics.google.com", "cloudflareinsights.com", "hotjar", "segment.io", "segment.com",
      "mixpanel", "pendo.io", "app-measurement.com", "nr-data.net", "newrelic", "scorecardresearch", "chartbeat", "omtrdc.net",
      "demdex.net", "smetrics.", "metrics.", "loki-ingest", "sentry.io", "bugsnag", "datadoghq"),
     "analytics", False, False),
    (("nvidia.com",), "NVIDIA telemetry", False, True),
    (("events.data.msn.com", "data.microsoft.com", "vortex.data", "telemetry"), "Microsoft telemetry", False, True),
    (("samsung-analytics", "samsungelectronics.com", "samsungcloud", "samsungdm"), "Samsung usage data", False, True),
    (("crashlytics", "firebaselogging", "app-measurement"), "app crash and usage logs", False, True),
    (("reporting-nel", "-nel."), "error reporting", False, True),
    (("akamai", "cloudfront.net", "fastly", "cdn"), "content delivery (needed)", True, False),
]


def site_test_kind(domain):
    d = str(domain or "").lower()
    if d.replace(".", "").isdigit() or ":" in d:
        return {"kind": "an address with no name", "needed": False, "background": False}
    for words, text, needed, background in SITE_TEST_KINDS:
        if any(w in d for w in words):
            return {"kind": text, "needed": needed, "background": background}
    return {"kind": "", "needed": False, "background": False}


def site_test_site(text):
    """'https://www.foxnews.com/video' -> 'foxnews.com'."""
    t = str(text or "").strip().lower()
    t = re.sub(r"^[a-z]+://", "", t).split("/")[0].split(":")[0].strip(".")
    return outbound_base(t[4:] if t.startswith("www.") else t) if t else ""


def site_test_load():
    st = policy_read_json(SITE_TEST_FILE) or {}
    st.setdefault("tests", [])
    return st


def site_test_save(st):
    temporary = SITE_TEST_FILE + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(st, handle, indent=1)
    os.replace(temporary, SITE_TEST_FILE)


def site_test_device(mac):
    mac = str(mac or "").upper()
    d = next((x for x in state.get("devices") or [] if str(x.get("mac") or "").upper() == mac), None)
    return {"mac": mac, "name": (d or {}).get("name") or recent_flow_device_name(mac, ""), "ip": (d or {}).get("ip")}


def site_test_rule(pid, fallback=None):
    rule = compact_policy_rule_for_flow(policy_rule_for_pid(pid)) if pid else None
    return rule or fallback


def site_test_hits():
    """Every active block rule's hit counter now (re-read every 5 s). Some
    blocks leave no flow record, only a hit on the rule: Family Protect's
    category blocks (seen 14 Nov 2026: #957 Category: porn hit 36 times,
    no record in the feed). A test compares the counters at its start and
    when its results are saved (the counters lag up to ~40 s)."""
    return {str(r.get("pid")): int(r.get("hit_count") or 0) for r in (state.get("policy_rules") or {}).get("rules") or []
            if r.get("action") == "block" and r.get("disabled") is not True}


def site_test_applies(rule, mac):
    """Does a rule apply to this device (all devices, the device, one of
    its groups or its network)?"""
    on = (rule or {}).get("applies_on") or {}
    kind, target = on.get("kind"), str(on.get("id") or "")
    if kind == "all_devices":
        return True
    if kind == "device":
        return target.upper() == mac
    if kind == "group":
        return target in {g["id"] for g in site_test_groups(mac)}
    if kind == "network":
        device = next((d for d in state.get("devices") or [] if str(d.get("mac") or "").upper() == mac), {})
        return bool(target) and target == str(device.get("interface_uuid") or "")
    return False


def site_test_results(test, now):
    """The device's flow records in the test window, sorted out."""
    start = test["start"]
    end = min(test.get("end") or now, now, start + SITE_TEST_MAX_SECONDS)
    length = max(60.0, end - start)
    with flow_history_reader() as connection:
        rows = connection.execute("SELECT event_at, kind, destination, protocol, count, policy_pid, payload_json FROM flow_records "
                                  "WHERE device_mac = ? AND event_at >= ? AND event_at < ?",
                                  (test["mac"], start - max(600.0, length), end)).fetchall()
        # Rules that left a record for any device in the window: their hits
        # are explained, so they aren't silent blocks.
        recorded_pids = {str(p) for (p,) in connection.execute(
            "SELECT DISTINCT policy_pid FROM flow_records WHERE kind = 'blocked' AND policy_pid IS NOT NULL "
            "AND event_at >= ? AND event_at < ?", (start - 30, end + 30))}
    site = test.get("site") or ""
    blocked, before, fine = {}, Counter(), {}
    categories = {}    # domain -> Firewalla's category for it (e.g. porn)
    named = 0
    seen = 0
    for at, kind, destination, protocol, count, pid, payload in rows:
        destination = str(destination or "--").lower().rstrip(".")
        count = int(count or 1)
        if at < start:
            if kind == "blocked":
                before[destination] += count
            continue
        seen += 1
        if not (destination.replace(".", "").isdigit() or ":" in destination):
            named += 1
        try:
            category = str(json.loads(payload).get("category") or "").lower()
        except Exception:
            category = ""
        if category:
            categories[destination] = category
        if kind == "blocked":
            b = blocked.setdefault(destination, {"domain": destination, "n": 0, "how": set(), "first": at, "rules": {}})
            b["n"] += count
            b["how"].add("DNS" if protocol == "DNS" else "connection")
            b["first"] = min(b["first"], at)
            if pid and pid not in b["rules"]:
                try:
                    fallback = json.loads(payload).get("matched_rule")
                except Exception:
                    fallback = None
                b["rules"][pid] = site_test_rule(pid, fallback)
        else:
            f = fine.setdefault(destination, {"domain": destination, "n": 0})
            f["n"] += count
    scale = length / max(600.0, length)
    for_site, background = [], []
    for b in blocked.values():
        info = site_test_kind(b["domain"])
        steady = before[b["domain"]] * scale
        # The site's own domains, or ones learned to load with it (Traffic
        # page companions: e.g. its video player's or image server's site).
        related = bool(site) and (b["domain"] == site or b["domain"].endswith("." + site)
                                  or outbound_base(b["domain"]) in traffic_companions_of(site))
        is_site = related or (not info["background"] and (steady == 0 or b["n"] >= 3 * steady))
        row = {"domain": b["domain"], "n": b["n"], "how": sorted(b["how"]), "at": round(b["first"] - start),
               "before": before[b["domain"]], "kind": info["kind"], "needed": info["needed"] or (related and not info["kind"]), "site": related,
               "rules": [r for r in b["rules"].values() if r]}
        (for_site if is_site else background).append(row)
    for_site.sort(key=lambda r: (not r["site"], not r["needed"], r["at"]))
    background.sort(key=lambda r: -r["n"])
    loaded = sorted(fine.values(), key=lambda f: (not (site and f["domain"].endswith(site)),
                                                  f["domain"].replace(".", "").isdigit() or ":" in f["domain"], -f["n"]))
    # Blocks with no record: rules for this device whose counter went up
    # during the test though none of the records names them, and rules
    # blocking a category (e.g. porn) that a domain in the test belongs to.
    named_pids = {str(r.get("pid")) for b in for_site + background for r in b["rules"]}
    start_hits = test.get("hits_start")
    end_hits = test.get("hits_end") or site_test_hits()
    silent = {}
    for r in (state.get("policy_rules") or {}).get("rules") or []:
        pid = str(r.get("pid"))
        if r.get("action") != "block" or r.get("disabled") is True or pid in named_pids or not site_test_applies(r, test["mac"]):
            continue
        grew = end_hits.get(pid, 0) - start_hits.get(pid, 0) if start_hits is not None and pid in start_hits and pid not in recorded_pids else 0
        match = r.get("matching") or {}
        in_category = sorted(d for d, c in categories.items() if match.get("kind") == "category" and c == str(match.get("id") or "").lower())
        if grew > 0 or in_category:
            silent[pid] = {"rule": compact_policy_rule_for_flow(r), "hits": max(grew, 0), "domains": in_category[:10],
                           "everyone": (r.get("applies_on") or {}).get("kind") == "all_devices"}
    rule_hits = sorted(silent.values(), key=lambda x: (not x["domains"], -x["hits"]))
    return {"window": [start, end], "records": seen, "named": named, "blocked": for_site, "background": background,
            "fine": [{"domain": f["domain"], "n": f["n"], "kind": site_test_kind(f["domain"])["kind"], "category": categories.get(f["domain"])}
                     for f in loaded[:80]],
            "fine_total": len(loaded), "rule_hits": rule_hits,
            "rule_count": len({r.get("pid") for b in for_site for r in b["rules"]} | {x["rule"].get("pid") for x in rule_hits})}


def site_test_finish(st, now):
    """End tests past 10 minutes, save results of ended ones (once their
    flow records are in), drop tests older than 30 days. True if changed."""
    changed = False
    keep = [t for t in st["tests"] if now - t["start"] < SITE_TEST_KEEP_SECONDS]
    if len(keep) != len(st["tests"]):
        st["tests"], changed = keep, True
    for t in st["tests"]:
        if not t.get("end") and now >= t["start"] + SITE_TEST_MAX_SECONDS:
            t["end"], t["stopped"], changed = t["start"] + SITE_TEST_MAX_SECONDS, "time", True
        if t.get("end") and "results" not in t and now >= t["end"] + SITE_TEST_SETTLE_SECONDS:
            # The router updates rule hit counters in batches (seen 14 Nov
            # 2026: a test's hits on #957 showed ~30 s after Stop), so the
            # counters are read now, when the results are saved.
            t["hits_end"] = site_test_hits()
            try:
                t["results"] = site_test_results(t, now)
            except Exception as exc:
                t["results"] = {"error": public_error("Test a Website", exc)}
            changed = True
    return changed


def site_test_exceptions(mac):
    """Allow rules that apply to this device or one of its groups."""
    groups = {str(g.get("id")) for g in (state.get("groups") or {}).get("groups") or []
              if mac in {str(m).upper() for m in g.get("members") or []}}
    out = []
    for r in (state.get("policy_rules") or {}).get("rules") or []:
        on = r.get("applies_on") or {}
        if r.get("action") != "allow" or r.get("disabled") is True or r.get("purpose") in ("dap", "ap_allow"):
            continue
        if (on.get("kind") == "device" and str(on.get("id") or "").upper() == mac) or (on.get("kind") == "group" and str(on.get("id")) in groups):
            out.append({"pid": str(r.get("pid")), "text": access_rule_text(r), "hits": r.get("hit_count") or 0})
    return sorted(out, key=lambda x: -x["hits"])


def site_test_groups(mac):
    return [{"id": str(g.get("id")), "name": g.get("name")} for g in (state.get("groups") or {}).get("groups") or []
            if mac in {str(m).upper() for m in g.get("members") or []}]


@app.get("/api/site-test-page")
def api_site_test_page(test: str = None, mac: str = None):
    """The Test a Website page: the device list, the running or chosen test
    with its results, earlier tests. The client is always picked: every
    browser reaches the NAS through Docker's own address, so the one it is
    on can't be found (owner, 23 Nov 2026, D-979)."""
    now = time.time()
    with site_test_lock:
        st = site_test_load()
        if site_test_finish(st, now):
            site_test_save(st)
    tests = sorted(st["tests"], key=lambda t: -t["start"])
    chosen = next((t for t in tests if t["id"] == test), None) if test else None
    pick = str(mac or "").upper()
    if not chosen:
        chosen = next((t for t in tests if not t.get("end") and (not pick or t["mac"] == pick)), None)
    current = None
    if chosen:
        current = {k: v for k, v in chosen.items() if k != "results"}
        current["running"] = not chosen.get("end")
        current["elapsed"] = round(min(chosen.get("end") or now, now) - chosen["start"])
        try:
            current["results"] = chosen.get("results") or site_test_results(chosen, now)
        except Exception as exc:
            current["results"] = {"error": public_error("Test a Website", exc)}
        current["settling"] = bool(chosen.get("end")) and "results" not in chosen
    device_mac = (current or {}).get("mac") or pick
    devices = sorted(({"mac": str(d.get("mac") or "").upper(), "name": d.get("name") or d.get("mac"), "online": d.get("online"),
                       "ip": d.get("ip")} for d in state.get("devices") or [] if d.get("mac")), key=lambda d: str(d["name"]).lower())
    return {
        "now": now, "device": site_test_device(device_mac) if device_mac else None,
        "groups": site_test_groups(device_mac) if device_mac else [],
        "exceptions": site_test_exceptions(device_mac) if device_mac else [],
        "devices": devices, "test": current, "max_seconds": SITE_TEST_MAX_SECONDS,
        "tests": [{"id": t["id"], "mac": t["mac"], "name": t.get("name"), "site": t.get("site"), "start": t["start"],
                   "seconds": round((t.get("end") or now) - t["start"]), "running": not t.get("end"),
                   "blocked": len((t["results"].get("blocked")) or []) + len(t["results"].get("rule_hits") or []) if "results" in t else None}
                  for t in tests[:30]],
    }


@app.post("/api/site-test/start")
def api_site_test_start(payload: dict = Body(default={})):
    """{mac, site}: start a test (a running test on that device ends)."""
    mac = Fields(payload).mac("mac")
    if not mac:
        return {"ok": False, "error": "pick a client first"}
    now = time.time()
    with site_test_lock:
        st = site_test_load()
        for t in st["tests"]:
            if t["mac"] == mac and not t.get("end"):
                t["end"], t["stopped"] = now, "new test"
        test = {"id": hashlib.sha1(f"{mac}{now}".encode()).hexdigest()[:10], "mac": mac, "name": site_test_device(mac)["name"],
                "site": site_test_site(payload.get("site")), "start": now, "hits_start": site_test_hits()}
        st["tests"] = st["tests"][-199:] + [test]   # the 200 latest
        site_test_finish(st, now)
        site_test_save(st)
    return {"ok": True, "id": test["id"]}


@app.post("/api/site-test/stop")
def api_site_test_stop(payload: dict = Body(default={})):
    now = time.time()
    with site_test_lock:
        st = site_test_load()
        t = next((x for x in st["tests"] if x["id"] == str(payload.get("id"))), None)
        if not t:
            return {"ok": False, "error": "no such test"}
        if not t.get("end"):
            t["end"], t["stopped"] = min(now, t["start"] + SITE_TEST_MAX_SECONDS), "you"
        site_test_save(st)
    return {"ok": True, "id": t["id"]}


@app.post("/api/site-test/delete")
def api_site_test_delete(payload: dict = Body(default={})):
    """{ids}: delete these tests (a running one stops first)."""
    ids = set(Fields(payload).strings("ids", 500))
    with site_test_lock:
        st = site_test_load()
        before = len(st["tests"])
        st["tests"] = [t for t in st["tests"] if t["id"] not in ids]
        site_test_save(st)
    return {"ok": True, "deleted": before - len(st["tests"])}


# ============================================================
# DESTINATIONS: who runs a site or address, and what it is for
#
# Four layers, best first, each named in "how" so the page can say where a
# label came from:
# 1 Firewalla's own category on the flow (ad, av, shopping, social...).
# 2 The block list that blocked it (ads and trackers, encrypted DNS, a
#   threat list).
# 3 Public owner lists: DuckDuckGo Tracker Radar (owner and what each
#   tracker domain does) and Disconnect (owner and category).
# 4 The IP address's network owner (iptoasn.com, public domain), for
#   destinations with no name or no other owner.
# Plus the dashboard's own company list (TRAFFIC_FAMILIES) and name words
# (site_test_kind). The three files live in /data/lists and are fetched
# again after 30 days (agreed 14 Nov 2026: these three addresses only).
# ============================================================
DEST_LIST_DIR = os.environ.get("FIREWALLA_LIST_DIR", "/data/lists")
DEST_REFRESH_SECONDS = 30 * 86400
DEST_SOURCES = {
    "tds": ("extension-tds.json", "https://staticcdn.duckduckgo.com/trackerblocking/v6/current/extension-tds.json",
            "DuckDuckGo Tracker Radar"),
    "disconnect": ("services.json", "https://raw.githubusercontent.com/disconnectme/disconnect-tracking-protection/master/services.json",
                   "Disconnect"),
    "asn": ("ip2asn-combined.tsv.gz", "https://iptoasn.com/data/ip2asn-combined.tsv.gz", "iptoasn.com"),
}
DEST_FIREWALLA_CATEGORIES = {"ad": "ads", "av": "video and audio", "shopping": "shopping", "social": "social media",
                             "games": "games", "porn": "adult", "gamble": "gambling", "vpn": "VPN", "p2p": "file sharing",
                             "edu": "education", "intel": "threat", "news": "news", "sports": "sports"}
DEST_TRACKER_WORDS = [  # list category -> plain words, best first
    ("Advertising", "ads"), ("Ad Motivated Tracking", "ad tracking"), ("Session Replay", "session recording"),
    ("Analytics", "analytics"), ("Third-Party Analytics Marketing", "analytics"), ("Audience Measurement", "audience measurement"),
    ("Action Pixels", "tracking pixel"), ("Fingerprinting", "fingerprinting"), ("FingerprintingInvasive", "fingerprinting"),
    ("FingerprintingGeneral", "fingerprinting"), ("Cryptomining", "cryptomining"), ("Ad Fraud", "ad fraud checks"),
    ("Social Network", "social"), ("Social - Share", "social sharing"), ("Social - Comment", "comments"), ("Social", "social"),
    ("Embedded Content", "embedded content"), ("CDN", "content delivery"), ("Online Payment", "payments"),
    ("SSO", "sign-in"), ("Federated Login", "sign-in"), ("Consent Management Platform", "cookie consent"), ("Email", "email"),
]
DEST_TRACKER_RANK = {k: (i, v) for i, (k, v) in enumerate(DEST_TRACKER_WORDS)}
# Big companies' own domains: the tracker lists name the whole domain, so a
# service under it (docs.google.com) isn't called ads by that (D-953).
DEST_SERVICE_BASES = {"google.com", "youtube.com", "microsoft.com", "live.com", "office.com", "apple.com", "icloud.com", "amazon.com"}
# What a few well-known service names are (D-953).
DEST_SERVICE_NAMES = {
    "www.google.com": "Google Search", "docs.google.com": "Google Docs", "drive.google.com": "Google Drive",
    "mail.google.com": "Gmail", "maps.google.com": "Google Maps", "calendar.google.com": "Google Calendar",
    "photos.google.com": "Google Photos", "play.google.com": "Google Play", "accounts.google.com": "Google sign-in",
    "meet.google.com": "Google Meet", "chat.google.com": "Google Chat", "scholar.google.com": "Google Scholar",
    "news.google.com": "Google News", "translate.google.com": "Google Translate", "keep.google.com": "Google Keep",
    "classroom.google.com": "Google Classroom", "contacts.google.com": "Google Contacts", "lens.google.com": "Google Lens",
    "www.youtube.com": "YouTube", "m.youtube.com": "YouTube", "music.youtube.com": "YouTube Music",
}
DEST_LIST_WORDS = {"oisd": "ads or tracking (block list)", "msp-prod-oisd-big-prod": "ads or tracking (block list)",
                   "hagezi-multipro": "ads or tracking (block list)", "msp-prod-goodbye-ads": "ads (block list)",
                   "doh": "encrypted DNS (block list)"}
DEST_ASN_NAMES = (("AMAZON", "Amazon"), ("GOOGLE", "Google"), ("MICROSOFT", "Microsoft"), ("AKAMAI", "Akamai"),
                  ("CLOUDFLARE", "Cloudflare"), ("FASTLY", "Fastly"), ("APPLE", "Apple"), ("FACEBOOK", "Meta"),
                  ("NETFLIX", "Netflix"), ("EDGECAST", "Edgio"), ("LIMELIGHT", "Edgio"), ("DIGITALOCEAN", "DigitalOcean"),
                  ("OVH", "OVH"), ("HETZNER", "Hetzner"), ("LINODE", "Akamai (Linode)"), ("ORACLE", "Oracle"), ("ROKU", "Roku"),
                  ("SAMSUNG", "Samsung"), ("TWITTER", "X (Twitter)"), ("COMCAST", "Comcast"), ("FRONTIER", "Frontier"),
                  ("CHARTER", "Spectrum"), ("TWC-", "Spectrum"), ("VERIZON", "Verizon"), ("T-MOBILE", "T-Mobile"), ("ATT-", "AT&T"))
dest_lock = threading.Lock()
dest_lists = {"tds": {}, "tds_domains": {}, "disconnect": {}, "asn4": None, "asn6": None, "asn_names": {}, "files": {}}


def dest_file(key):
    return os.path.join(DEST_LIST_DIR, DEST_SOURCES[key][0])


def dest_download(key):
    """Fetch one list to a temporary file, then replace the old one."""
    name, url, _ = DEST_SOURCES[key]
    os.makedirs(DEST_LIST_DIR, exist_ok=True)
    temporary = os.path.join(DEST_LIST_DIR, name + ".download")
    with requests.get(url, timeout=120, stream=True, headers={"User-Agent": "firewalla-dashboard"}) as r:
        r.raise_for_status()
        with open(temporary, "wb") as handle:
            for chunk in r.iter_content(1 << 16):
                handle.write(chunk)
    if os.path.getsize(temporary) < 1000:
        os.remove(temporary)
        raise RuntimeError("the download was empty")
    os.replace(temporary, os.path.join(DEST_LIST_DIR, name))


def dest_fetch(key):
    """Download one list, noting the result for the Settings page."""
    info = dest_lists["files"].setdefault(key, {})
    try:
        dest_download(key)
        info.update(fetched_at=time.time(), error=None)
    except Exception as exc:
        info.update(error=f"couldn't download: {exc}", tried_at=time.time())
        print("Destination list download error:", key, exc)


def dest_load_tds(path):
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    entities = data.get("entities") or {}
    owner_name = lambda o: (entities.get(o) or {}).get("displayName") or o
    trackers = {}
    for domain, t in (data.get("trackers") or {}).items():
        owner = (t.get("owner") or {})
        trackers[domain.lower()] = (owner.get("displayName") or owner.get("name") or "", tuple(t.get("categories") or ()))
    domains = {d.lower(): owner_name(o) for d, o in (data.get("domains") or {}).items()}
    return trackers, domains


def dest_load_disconnect(path):
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    out = {}
    for category, entries in (data.get("categories") or {}).items():
        for entry in entries or []:
            for company, sites in (entry or {}).items():
                for value in (sites or {}).values() if isinstance(sites, dict) else ():
                    for domain in value if isinstance(value, list) else ():
                        out.setdefault(str(domain).lower(), (company, []))[1].append(category)
    return {d: (c, tuple(dict.fromkeys(cats))) for d, (c, cats) in out.items()}


def dest_load_asn(path):
    """Two sorted range tables (IPv4 in arrays, IPv6 in lists) and the
    network names by AS number."""
    import gzip
    from array import array
    v4s, v4e, v4a = array("I"), array("I"), array("I")
    v6s, v6e, v6a = [], [], []
    names = {}
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 5 or parts[2] == "0":
                continue
            asn = int(parts[2])
            names.setdefault(asn, parts[4])
            if ":" in parts[0]:
                v6s.append(int(ipaddress.IPv6Address(parts[0])))
                v6e.append(int(ipaddress.IPv6Address(parts[1])))
                v6a.append(asn)
            else:
                v4s.append(int(ipaddress.IPv4Address(parts[0])))
                v4e.append(int(ipaddress.IPv4Address(parts[1])))
                v4a.append(asn)
    return (v4s, v4e, v4a), (v6s, v6e, v6a), names


def dest_load():
    """Read whichever lists are on disk into memory."""
    for key, loader in (("tds", dest_load_tds), ("disconnect", dest_load_disconnect), ("asn", dest_load_asn)):
        path = dest_file(key)
        info = dest_lists["files"].setdefault(key, {})
        if not os.path.exists(path) or info.get("loaded_mtime") == os.path.getmtime(path):
            continue
        try:
            value = loader(path)
        except Exception as exc:
            info["error"] = f"couldn't read: {exc}"
            continue
        with dest_lock:
            if key == "tds":
                dest_lists["tds"], dest_lists["tds_domains"] = value
            elif key == "disconnect":
                dest_lists["disconnect"] = value
            else:
                dest_lists["asn4"], dest_lists["asn6"], dest_lists["asn_names"] = value
        info.update(loaded_mtime=os.path.getmtime(path), size=os.path.getsize(path), error=None)


def dest_lists_worker():
    """Fetch a list that is missing or 30 days old, then load what's new.
    Checked every 6 hours; a failed fetch keeps the old file."""
    time.sleep(30)
    while True:
        for key in DEST_SOURCES:
            path = dest_file(key)
            if os.path.exists(path) and time.time() - os.path.getmtime(path) < DEST_REFRESH_SECONDS:
                continue
            dest_fetch(key)
        try:
            dest_load()
        except Exception as exc:
            print("Destination list error:", exc)
            traceback.print_exc()
        time.sleep(6 * 3600)


def dest_lists_status():
    out = []
    for key, (name, url, label) in DEST_SOURCES.items():
        path = dest_file(key)
        info = dest_lists["files"].get(key, {})
        out.append({"key": key, "label": label, "url": url, "loaded": bool(info.get("loaded_mtime")),
                    "updated": os.path.getmtime(path) if os.path.exists(path) else None, "error": info.get("error")})
    return out


def dest_suffixes(name):
    labels = str(name or "").lower().rstrip(".").split(".")
    return [".".join(labels[i:]) for i in range(len(labels) - 1)]


def dest_asn(ip):
    """{asn, network, owner} for an IP address, or None."""
    import bisect
    try:
        address = ipaddress.ip_address(str(ip))
    except ValueError:
        return None
    if address.is_private or address.is_loopback or address.is_link_local:
        return None
    with dest_lock:
        table = dest_lists["asn6"] if address.version == 6 else dest_lists["asn4"]
        names = dest_lists["asn_names"]
        if not table:
            return None
        starts, ends, asns = table
        n = int(address)
        i = bisect.bisect_right(starts, n) - 1
        if i < 0 or n > ends[i]:
            return None
        asn = asns[i]
        network = names.get(asn, "")
    upper = network.upper()
    owner = next((nice for word, nice in DEST_ASN_NAMES if word in upper), "")
    if not owner:
        # "APPLE-ENGINEERING - Apple Inc." or "PFCLOUD Pfcloud UG": the
        # network's handle, then its organisation.
        handle = re.match(r"^[A-Z0-9][A-Z0-9_.-]*(?:\s+-)?\s+(?=\S)", network)
        owner = network[handle.end():] if handle and network[handle.end():] else network
        owner = re.sub(r",?\s+(Inc\.?|LLC|Ltd\.?|Corporation|Corp\.?|GmbH|B\.V\.|S\.A\.)$", "", owner.strip(), flags=re.I)
    return {"asn": asn, "network": network, "owner": owner}


def dest_classify(name, ip=None, category=None, pid=None):
    """{owner, what, how: [where each came from], network} for a domain or
    address. ip: an address it used (for the network owner). category:
    Firewalla's category on its flows. pid: the rule that blocked it."""
    name = str(name or "").lower().rstrip(".")
    bare = name.replace(".", "").isdigit() or ":" in name
    owner, whats, how = "", [], []
    family = TRAFFIC_FAMILY_OF.get(outbound_base(name)) if not bare else None
    if family:
        owner = family
        how.append("the dashboard's company list")
    if name in DEST_SERVICE_NAMES:
        whats.append((2, DEST_SERVICE_NAMES[name]))
        how.append("the dashboard's service list")
    # A big company's site under its own domain (docs.google.com) is not one
    # of its ad or tracking sites because the domain (google.com) is listed:
    # its owner is kept, its ad / tracking words only for the exact name (D-953).
    service = lambda s: s != name and s in DEST_SERVICE_BASES
    if not bare:
        with dest_lock:
            tds, tds_domains, disconnect = dest_lists["tds"], dest_lists["tds_domains"], dest_lists["disconnect"]
            for s in dest_suffixes(name):
                hit = tds.get(s)
                if hit:
                    owner = owner or hit[0]
                    if not service(s):
                        whats += [DEST_TRACKER_RANK[c] for c in hit[1] if c in DEST_TRACKER_RANK]
                    how.append("DuckDuckGo Tracker Radar")
                    break
            if not owner:
                o = next((tds_domains[s] for s in dest_suffixes(name) if s in tds_domains), "")
                if o:
                    owner = o
                    how.append("DuckDuckGo Tracker Radar")
            at = next((s for s in dest_suffixes(name) if s in disconnect), None)
            hit = disconnect[at] if at else None
            if hit:
                owner = owner or hit[0]
                if not service(at):
                    whats += [DEST_TRACKER_RANK[c] for c in hit[1] if c in DEST_TRACKER_RANK]
                how.append("Disconnect")
    guess = core.dest_claude.get(outbound_base(name)) if not bare and not owner else None
    if guess and guess.get("owner") and guess["owner"].strip().lower() != "unknown":
        owner = f"{guess['owner']} (Claude's guess)"
        if guess.get("what"):
            whats.append((3, guess["what"]))
        how.append(f"Claude's guess ({guess.get('confidence') or 'unsure'} confidence)")
    cat = str(category or "").lower()
    if cat:
        whats.append((5, DEST_FIREWALLA_CATEGORIES.get(cat, cat)))
        how.append("Firewalla's category")
    if pid:
        rule = policy_rule_for_pid(pid) or {}
        target = str(rule.get("target") or "")
        word = DEST_LIST_WORDS.get(target) or (OUTBOUND_THREAT_LISTS[target] + " (threat list)" if target in OUTBOUND_THREAT_LISTS else "")
        if word:
            whats.append((4 if target in OUTBOUND_THREAT_LISTS else 6, word))
            how.append("the block list")
    if not whats:
        kind = site_test_kind(name)["kind"]
        if kind:
            whats.append((50, kind))
            if not bare:
                how.append("words in the name")
    net = dest_asn(name if bare else ip) if (bare or ip) else None
    if net and not owner:
        owner = net["owner"]
        how.append("the address's network")
    seen, what = set(), []
    for _, w in sorted(whats):
        if w not in seen:
            seen.add(w)
            what.append(w)
    return {"owner": owner, "what": ", ".join(what[:2]), "how": list(dict.fromkeys(how)),
            "network": f"AS{net['asn']} {net['network']}" if net else "",
            "claude_note": (guess or {}).get("summary"), "claude_concern": (guess or {}).get("concern") == "look"}


def dest_flow_facts(connection, names, where, params):
    """For destinations on the Traffic page: an address each used, Firewalla's
    category, and the rule that blocked it most, within the page's filter."""
    names = [n for n in names if n][:60]
    if not names:
        return {}
    marks = ",".join("?" * len(names))
    key = "COALESCE(destination, remote_ip, '--')"
    rows = connection.execute(f"""
        SELECT {key} AS v, MAX(remote_ip), MAX(json_extract(payload_json, '$.category')) FROM flow_records{where}
        AND {key} IN ({marks}) GROUP BY v""", params + names).fetchall()
    out = {v: {"ip": ip, "category": cat, "pid": None} for v, ip, cat in rows}
    for v, pid, n in connection.execute(f"""
            SELECT {key} AS v, policy_pid, SUM(COALESCE(starts, count)) AS n FROM flow_records{where}
            AND {key} IN ({marks}) AND kind = 'blocked' AND policy_pid IS NOT NULL GROUP BY v, policy_pid ORDER BY n""",
            params + names).fetchall():
        out.setdefault(v, {"ip": None, "category": None, "pid": None})["pid"] = pid   # ascending: the biggest wins
    return out


# ============================================================
# TRAFFIC PAGE: look up what a device, site or rule did (24-hour flow
# history; most visits come from a link on another page, with a filter)
#
# /api/traffic-page   totals, flows over time, one top list (the open tab)
#                     and the newest 500 records for the page's filters
# /api/traffic/related  the session around one record: the device's flows
#                     that start within 20 s of each other (a quiet gap
#                     ends it), sorted into the same service, blocked during
#                     it, other flows, and background (destinations the
#                     device repeats all through the 2 hours around it).
#                     Each flow is labelled by timing: loaded with the
#                     burst's first site (within 3 s), or opened after the
#                     one before (a new burst after a pause).
# Companions: which sites load together, learned from every device every
#   10 minutes (a site opened after 10 s of quiet, and what starts within
#   8 s of it). Shown as "usually loaded by" in Related, in the domain
#   popup and by Test a Website. Half-life 14 days (/data/traffic_companions.json).
# The router sees no page addresses (HTTPS hides them), so "loaded with"
# and "opened after" are read from timing: an educated guess, said so.
# ============================================================
# Destinations you hid on the Traffic page (the user, 15 Nov 2026): left out
# of its Records and Destinations lists for the client hidden from and every
# client in its groups, still counted in the totals and the chart. Their
# alarms come in as Hidden and their Outbound To Triage items are filed as
# Normal (Critical alarms and threat-list hits still ask); Device Activity,
# Test a Website and Claude still see them. Exact names only. Kept for good:
# no Unhide yet.
TRAFFIC_HIDDEN_MAX = 10000   # 15 Nov 2026: 1,000 was reached; 10,000 adds ~0.1 s per Traffic query
TRAFFIC_HIDDEN_FILE = os.environ.get("FIREWALLA_TRAFFIC_HIDDEN_FILE", "/data/traffic_hidden.json")
TRAFFIC_COMPANIONS_FILE = os.environ.get("FIREWALLA_TRAFFIC_COMPANIONS_FILE", "/data/traffic_companions.json")
TRAFFIC_SESSION_GAP = 20          # seconds of quiet that end a session
TRAFFIC_SESSION_MAX = 900         # a session is at most 15 minutes
TRAFFIC_WAVE_GAP = 3              # flows this close start together ("loaded with")
TRAFFIC_COMPANION_QUIET = 10      # a site counts as opened after this much quiet
TRAFFIC_COMPANION_WINDOW = 8      # what starts this soon after it loads with it
TRAFFIC_COMPANION_HALF_LIFE = 14 * 86400
TRAFFIC_COMPANION_MIN_OPENS = 3   # a site opened at least this often
TRAFFIC_COMPANION_MIN_SHARE = 0.3  # and the other site with it at least this often
traffic_lock = threading.Lock()
traffic_companions = {"leads": {}, "until": 0, "at": 0}

# Sites of one company count as the same service.
TRAFFIC_FAMILIES = {
    "Google": ("google.com", "gstatic.com", "googleapis.com", "googleusercontent.com", "gvt1.com", "gvt2.com", "ggpht.com",
               "youtube.com", "ytimg.com", "googlevideo.com", "android.com", "firebaseio.com", "google.co.uk"),
    "Facebook": ("facebook.com", "fbcdn.net", "facebook.net", "instagram.com", "cdninstagram.com", "whatsapp.net", "whatsapp.com"),
    "Microsoft": ("microsoft.com", "msn.com", "live.com", "windows.com", "office.com", "office.net", "bing.com", "microsoftonline.com",
                  "skype.com", "xboxlive.com", "windowsupdate.com", "msftconnecttest.com"),
    "Amazon": ("amazon.com", "media-amazon.com", "amazonvideo.com", "a2z.com", "amazon.dev", "primevideo.com", "aiv-cdn.net"),
    "Netflix": ("netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com", "nflxso.net"),
    "Apple": ("apple.com", "icloud.com", "mzstatic.com", "apple-dns.net", "cdn-apple.com"),
    "Samsung": ("samsung.com", "samsungcloud.com", "samsungosp.com", "samsungdm.com", "samsungqbe.com", "samsungapps.com",
                "samsungelectronics.com", "bixbyllm.com"),
    "TP-Link": ("tplinkcloud.com", "tplinknbu.com", "tp-link.com"),
    "Plex": ("plex.tv", "plex.direct"),
    "ESPN": ("espn.com", "bamgrid.com", "espncdn.com", "go.com"),
    "Eufy": ("eufylife.com", "eufy.com", "anker.com"),
}
TRAFFIC_FAMILY_OF = {base: name for name, bases in TRAFFIC_FAMILIES.items() for base in bases}
TRAFFIC_TABS = ("devices", "hidden_devices", "destinations", "networks", "wans", "ports", "countries", "rules")
TRAFFIC_SORTS = {"flows": "flow_count", "allowed": "normal_count", "blocked": "blocked_count",
                 "down": "download_bytes", "up": "upload_bytes"}


def traffic_service(destination, remote_ip=None):
    """('Google', 'google') for any Google site; else the base domain."""
    base = outbound_base(destination or remote_ip or "")
    family = TRAFFIC_FAMILY_OF.get(base)
    return (family, family.lower()) if family else (base, base)


def traffic_scan(mac):
    return str(mac or "").upper().startswith("IF:")


def traffic_device_name(mac, device, network):
    """A device's name; a WAN's internet scans as 'Internet → <WAN> WAN'."""
    if traffic_scan(mac):
        return f"Internet → {network or 'a'} WAN"
    current = recent_flow_device_name(mac, "") if mac else None
    return (current if current and current.upper() != str(mac).upper() else None) or device or mac or "--"


def traffic_rule_name(pid):
    rule = policy_rule_for_pid(pid) if pid else None
    return access_rule_text(rule) if rule else (f"Rule {pid}" if pid else "")


def traffic_range(f, now):
    """(start, end, bucket seconds) for the page's time filter: h = 1, 6 or
    24 hours back, or a zoomed span from/to (Unix seconds)."""
    try:
        start, end = float(f.get("from")), float(f.get("to"))
        start, end = max(start, now - FLOW_HISTORY_HOURS * 3600), min(end, now)
        if end - start >= 60:
            span = end - start
            bucket = next(b for b in (60, 300, 900, 1800, 3600) if span / b <= 36 or b == 3600)
            return start, end, bucket
    except (TypeError, ValueError):
        pass
    hours = {"1": 1, "6": 6}.get(str(f.get("h") or ""), 24)
    return now - hours * 3600, now, {1: 300, 6: 900}.get(hours, 3600)


def traffic_where(f, start, end):
    """SQL WHERE for the page's filters. Names are what other pages link
    with (device name, network name, WAN name); mac, rule and port are exact."""
    where, p = ["event_at >= ?", "event_at < ?"], [start, end]

    def add(sql, *values):
        where.append(sql)
        p.extend(values)

    if f.get("kind") in ("normal", "blocked"):
        add("kind = ?", f["kind"])
    if f.get("mac"):
        add("device_mac = ?", str(f["mac"]).upper())
    if f.get("device"):
        add("COALESCE(device, device_ip, device_mac) = ?", str(f["device"]))
    if f.get("network"):
        add("source_network = ?", str(f["network"]))
    if f.get("wan"):
        # Traffic that went out of it, or internet scans that came in on it.
        add("(outbound = ? OR (device_mac LIKE 'IF:%' AND source_network = ?))", str(f["wan"]), str(f["wan"]))
    if f.get("destination"):
        add("(destination = ? OR remote_ip = ?)", str(f["destination"]), str(f["destination"]))
    if f.get("protocol"):
        add("protocol = ?", str(f["protocol"]).upper())
    if str(f.get("port") or "").isdigit():
        add("port = ?", int(f["port"]))
    if f.get("rule"):
        add("(policy_pid = ? OR allowed_pid = ?)", str(f["rule"]), str(f["rule"]))
    mechanism = f.get("mechanism")
    if mechanism:
        add("kind = 'blocked'")
        if mechanism == "DNS filtering":
            add("protocol = 'DNS'")
        elif mechanism == "WAN / ingress":
            add("device_mac LIKE 'IF:%'")
        elif mechanism == "IP block":
            add("protocol != 'DNS' AND device_mac NOT LIKE 'IF:%'")
    search = str(f.get("search") or "").strip()
    if search:
        like = f"%{search}%"
        sql = ("(device LIKE ? OR device_ip LIKE ? OR device_mac LIKE ? OR destination LIKE ? OR remote_ip LIKE ? "
               "OR service LIKE ? OR country = ?")
        values = [like] * 6 + [search.upper()]
        if search.isdigit():
            sql += " OR port = ?"
            values.append(int(search))
        add(sql + ")", *values)
    for hidden in [h for h in str(f.get("hide") or "").split(",") if h][:10]:
        add("COALESCE(destination, remote_ip, '') != ?", hidden)
    return " WHERE " + " AND ".join(where), p


def traffic_record(row_id, at, payload):
    """One record for the page: what the Records table and Related show."""
    try:
        r = json.loads(payload)
    except (TypeError, ValueError):
        return None
    mac = str(r.get("device_mac") or "")
    pid = r.get("policy_pid") if r.get("kind") == "blocked" else r.get("allowed_pid")
    rule = traffic_rule_name(pid) if pid else ("WAN default (no rule)" if traffic_scan(mac) and r.get("kind") == "blocked" else "")
    return {
        "id": row_id, "at": at, "kind": r.get("kind"), "mac": mac,
        "device": traffic_device_name(mac, r.get("device"), r.get("source_network")),
        "destination": r.get("destination") or r.get("remote_ip") or "--", "ip": r.get("remote_ip"),
        "country": r.get("country") or "", "protocol": r.get("protocol") or "", "port": r.get("port"),
        "way": "in" if traffic_scan(mac) else "out", "wan": r.get("outbound") or (r.get("source_network") if traffic_scan(mac) else ""),
        "network": r.get("source_network") or "", "rule_pid": pid, "rule": rule, "count": int(r.get("count") or 1),
        "down": r.get("download_bytes"), "up": r.get("upload_bytes"), "category": r.get("category") or "",
        "duration": r.get("duration_seconds"),
    }


def traffic_ranking(connection, tab, where, p, sort, limit=25):
    order = TRAFFIC_SORTS.get(sort, "blocked_count")
    if tab == "rules":
        rows = connection.execute(f"""
            WITH related AS (
                SELECT policy_pid AS value, kind, count, starts, upload_bytes, download_bytes FROM flow_records{where} AND policy_pid IS NOT NULL AND policy_pid != ''
                UNION ALL
                SELECT allowed_pid AS value, kind, count, starts, upload_bytes, download_bytes FROM flow_records{where} AND allowed_pid IS NOT NULL AND allowed_pid != ''
            )
            SELECT value, '', '', {FLOW_METRICS_SQL} FROM related GROUP BY value ORDER BY {order} DESC, flow_count DESC LIMIT ?""",
            p + p + [limit]).fetchall()
    else:
        key, label, extra = {
            "devices": ("device_mac", "MAX(device)", "MAX(source_network)"),
            "destinations": ("COALESCE(destination, remote_ip, '--')", "''", "MAX(country)"),
            "networks": ("COALESCE(source_network, '--')", "''", "''"),
            "wans": ("COALESCE(outbound, CASE WHEN device_mac LIKE 'IF:%' THEN source_network END, '--')", "''", "''"),
            "ports": ("COALESCE(protocol, '--') || CASE WHEN protocol = 'DNS' OR port IS NULL THEN '' ELSE ' ' || port END", "''", "''"),
            "countries": ("COALESCE(NULLIF(country, ''), '--')", "''", "''"),
        }[tab]
        rows = connection.execute(f"""
            SELECT {key} AS value, {label}, {extra}, {FLOW_METRICS_SQL} FROM flow_records{where}
            GROUP BY value ORDER BY {order} DESC, flow_count DESC LIMIT ?""", p + [limit]).fetchall()
    out = []
    for value, label, extra, *metrics in rows:
        item = {"key": value, **flow_metrics(metrics)}
        if tab == "devices":
            item.update(name=traffic_device_name(value, label, extra), network=extra, scan=traffic_scan(value))
        elif tab == "rules":
            item["name"] = traffic_rule_name(value)
        elif tab == "destinations":
            item.update(name=value, country=extra or "")
        else:
            item["name"] = value
        out.append(item)
    if tab == "destinations":
        facts = dest_flow_facts(connection, [i["key"] for i in out], where, p)
        for i in out:
            f = facts.get(i["key"]) or {}
            c = dest_classify(i["key"], f.get("ip"), f.get("category"), f.get("pid"))
            i.update(owner=c["owner"], what=c["what"], how=c["how"])
    return out


def traffic_page_build(f, hide=("", [])):
    """hide: traffic_hidden_sql's test and values."""
    now = time.time()
    start, end, bucket = traffic_range(f, now)
    where, p = traffic_where(f, start, end)
    is_hidden, hide_p = hide
    hide_sql = f" AND NOT {is_hidden}" if is_hidden else ""
    tab = f.get("t") if f.get("t") in TRAFFIC_TABS else ("destinations" if f.get("mac") or f.get("device") else "devices")
    with flow_history_reader() as connection:
        # The hidden records are counted in the same pass as the totals.
        hidden_cols = (f"""COALESCE(SUM(CASE WHEN {is_hidden} THEN 1 ELSE 0 END), 0),
                COUNT(DISTINCT CASE WHEN {is_hidden} THEN COALESCE(destination, remote_ip, '') END)""" if is_hidden else "0, 0")
        row = connection.execute(f"""SELECT {FLOW_METRICS_SQL},
                COALESCE(SUM(CASE WHEN kind = 'blocked' AND protocol = 'DNS' THEN count ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN device_mac LIKE 'IF:%' THEN count ELSE 0 END), 0),
                COUNT(DISTINCT CASE WHEN device_mac NOT LIKE 'IF:%' THEN device_mac END),
                {hidden_cols}
            FROM flow_records{where}""", hide_p + hide_p + p).fetchone()
        totals = {**flow_metrics(row[:8]), "blocked_dns": int(row[8] or 0), "wan_scans": int(row[9] or 0), "devices": int(row[10] or 0)}
        hidden = {"records": int(row[11] or 0), "destinations": int(row[12] or 0)}
        steps = connection.execute(f"""SELECT CAST((event_at - ?) / ? AS INTEGER) AS slot,
                COALESCE(SUM(CASE WHEN kind = 'normal' THEN COALESCE(starts, count) ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN kind = 'blocked' THEN count ELSE 0 END), 0)
            FROM flow_records{where} GROUP BY slot""", [start, bucket] + p).fetchall()
        # Hidden destinations: out of Devices - Unhidden, Destinations and the
        # Records; Devices - Hidden counts only them (the user, 15 Nov 2026).
        if tab == "hidden_devices":
            top = traffic_ranking(connection, "devices", where + (f" AND {is_hidden}" if is_hidden else " AND 0"),
                                  p + hide_p, f.get("s") or "blocked")
        else:
            top = traffic_ranking(connection, tab, where + (hide_sql if tab in ("devices", "destinations") else ""),
                                  p + (hide_p if tab in ("devices", "destinations") else []), f.get("s") or "blocked")
        records = [r for r in (traffic_record(*x) for x in connection.execute(
            f"SELECT row_id, event_at, payload_json FROM flow_records{where}{hide_sql} ORDER BY event_at DESC, row_id DESC LIMIT 500", p + hide_p)) if r]
        # Who runs each destination and what it is (owner, 18 Nov 2026), as
        # Device Activity shows it: looked up once per site, not per row.
        known = {}
        for r in records:
            if r["destination"] not in known:
                c = dest_classify(r["destination"], r["ip"], r["category"], r.get("rule_pid") if r["kind"] == "blocked" else None)
                known[r["destination"]] = (c["owner"], c["what"])
            r["owner"], r["what"] = known[r["destination"]]
        # For the summary line: the busiest device (none chosen) or what the
        # chosen one was blocked from most.
        busiest = None
        if not (f.get("mac") or f.get("device")):
            b = connection.execute(f"""SELECT device_mac, MAX(device), MAX(source_network), COALESCE(SUM(COALESCE(starts, count)), 0) AS n
                FROM flow_records{where} AND device_mac NOT LIKE 'IF:%' GROUP BY device_mac ORDER BY n DESC LIMIT 1""", p).fetchone()
            if b:
                busiest = {"mac": b[0], "name": traffic_device_name(b[0], b[1], b[2]), "count": int(b[3] or 0)}
        mostly = connection.execute(f"""SELECT COALESCE(destination, remote_ip), MAX(policy_pid), COALESCE(SUM(COALESCE(starts, count)), 0) AS n
            FROM flow_records{where} AND kind = 'blocked' {"AND device_mac = ?" if busiest else ""}
            GROUP BY 1 ORDER BY n DESC LIMIT 1""", p + ([busiest["mac"]] if busiest else [])).fetchone()
        # The Network filter lists your own networks (owner, 23 Nov 2026, D-951):
        # the WANs have their own filter, and the busiest Wi-Fi networks were missing.
        networks = sorted({n for _, n in traffic_lan_names()} - {name for name, _ in wan_networks()})
    slots = int(-(-(end - start) // bucket))
    by_slot = {int(s): (int(a), int(b)) for s, a, b in steps}
    timeline = [{"start": start + i * bucket, "allowed": by_slot.get(i, (0, 0))[0], "blocked": by_slot.get(i, (0, 0))[1]}
                for i in range(slots)]
    if mostly and mostly[2]:
        mostly = {"destination": mostly[0], "count": int(mostly[2]), "rule": traffic_rule_name(mostly[1]), "rule_pid": mostly[1],
                  "what": dest_classify(mostly[0], pid=mostly[1])["what"]}
    else:
        mostly = None
    # Only rules that can match internet traffic (D-955): rules between your own clients are left out.
    local = {str(r.get("pid")) for r in access_local_rules()}
    rules = sorted(((r.get("hit_count") or 0, str(r.get("pid")), access_rule_text(r), r.get("action"))
                    for r in (state.get("policy_rules") or {}).get("rules") or [] if r.get("pid") and str(r.get("pid")) not in local), reverse=True)[:80]
    return {
        "healthy": True, "now": now, "start": start, "end": end, "bucket": bucket, "tab": tab,
        "totals": totals, "timeline": timeline, "top": top, "records": records, "busiest": busiest, "mostly": mostly, "hidden": hidden,
        "choices": {
            "networks": sorted(n for n in networks if n),
            "wans": [name for name, _ in wan_networks()],
            "rules": [{"pid": pid, "name": name, "action": action} for _, pid, name, action in rules],
        },
    }


TRAFFIC_PAGE_KEYS = ("kind", "mac", "device", "network", "wan", "destination", "protocol", "port", "rule", "mechanism",
                     "search", "hide", "h", "from", "to", "t", "s")


@app.get("/api/traffic-page")
def api_traffic_page(request: Request):
    f = {k: request.query_params.get(k) for k in TRAFFIC_PAGE_KEYS if request.query_params.get(k)}
    try:
        # Part of the key: a new hide (or a client joining a group) shows at once.
        hide = traffic_hidden_sql(traffic_hidden_resolve())
        key = hashlib.sha1("".join(hide[1]).encode()).hexdigest()
        return shared_result(("traffic-page", key, tuple(sorted(f.items()))), lambda: traffic_page_build(f, hide))
    except Exception as exc:
        return {"healthy": False, "error": public_error("Traffic page", exc)}


# ------------------------------------------------------------
# One activity's view (Device Activity): groups, timing labels, the read
# ------------------------------------------------------------
def traffic_session_view(inside, picked, mac, start, end, widen, times, now):
    """The groups, timing labels, educated read and totals of one session
    (Related) or activity (Device Activity): inside = its flows with their
    background mark, picked = the record it is about (an activity: its
    lead), times = each destination's flow times (for "every")."""
    # Timing labels: a burst = flows starting within 3 s of each other; its
    # first flow leads it. Later flows in a burst loaded with its lead; a
    # burst after a pause was opened after the one before.
    leads, lead, last = [], None, None
    for r in [x for x in inside if not x["background"]]:
        if last is None or r["at"] - last > TRAFFIC_WAVE_GAP:
            lead = r
            leads.append(r)
        r["lead"] = lead["destination"]
        r["lead_at"] = lead["at"]
        last = r["at"]
    companions = {}
    for i, l in enumerate(leads):
        companions[l["destination"]] = traffic_companions_of(outbound_base(l["destination"]))
        l["timing"] = f"opened after {outbound_base(leads[i - 1]['destination'])}" if i else "first in the session"
    for r in inside:
        if r["background"] or r.get("timing"):
            continue
        lead_base, base = outbound_base(r["lead"]), outbound_base(r["destination"])
        if base == lead_base:
            r["timing"] = f"part of {lead_base}"
        elif base in companions.get(r["lead"], {}):
            r["timing"] = f"usually loaded by {lead_base}"
        else:
            r["timing"] = f"loaded with {lead_base}"
    service_name, service = traffic_service(picked["destination"], picked["ip"])
    groups = {"service": [], "blocked": [], "other": [], "background": []}
    # The Service = the lead's own company or site, allowed and blocked (14 Nov
    # 2026); Blocked During It = other companies' blocked records only.
    for r in inside:
        r["group"] = ("background" if r["background"]
                      else "service" if traffic_service(r["destination"], r["ip"])[1] == service or (r["ip"] and r["ip"] == picked["ip"])
                      else "blocked" if r["kind"] == "blocked" else "other")
        groups[r["group"]].append(r)

    def rollup(items, group):
        by = {}
        for r in items:
            if r["destination"] not in by:
                c = dest_classify(r["destination"], r["ip"], r["category"], r["rule_pid"] if r["kind"] == "blocked" else None)
                by[r["destination"]] = {
                    "destination": r["destination"], "records": 0, "blocked_records": 0, "tries": 0, "first": r["at"], "last": r["at"],
                    "ports": set(), "kind": r["kind"], "rule": None, "rule_pid": None, "down": 0, "up": 0, "country": r["country"],
                    "owner": c["owner"], "what": c["what"], "timing": r.get("timing") or "", "picked": False}
            g = by[r["destination"]]
            g["records"] += 1
            if r["kind"] == "blocked":
                # The dot: green all allowed, red all blocked, yellow both.
                g["blocked_records"] += 1
                g["rule"], g["rule_pid"] = g["rule"] or r["rule"], g["rule_pid"] or r["rule_pid"]
            g["kind"] = "blocked" if g["blocked_records"] == g["records"] else "normal"
            g["tries"] += r["count"]
            g["first"], g["last"] = min(g["first"], r["at"]), max(g["last"], r["at"])
            g["ports"].add(f"{r['protocol']} {r['port']}" if r["protocol"] != "DNS" and r["port"] else r["protocol"])
            g["down"] += r["down"] or 0
            g["up"] += r["up"] or 0
            g["picked"] = g["picked"] or r["id"] == picked["id"]
        out = sorted(by.values(), key=lambda g: (not g["picked"], g["first"]))
        for g in out:
            g["ports"] = ", ".join(sorted(g["ports"]))
            if group == "background":
                gaps = sorted(b - a for a, b in zip(times[g["destination"]], times[g["destination"]][1:]) if b > a)
                g["every"] = gaps[len(gaps) // 2] if gaps else None
        return out

    session_flows = [r for r in inside if not r["background"]]
    blocked = groups["blocked"]
    kinds = Counter(g["what"] for g in rollup(blocked, "blocked") if g["what"])
    service_rows = [r for r in groups["service"] if r["kind"] != "blocked"]
    service_blocked = len(groups["service"]) - len(service_rows)
    read = []
    if service_rows:
        read.append(f"{len(service_rows)} flow{'s' if len(service_rows) != 1 else ''} to {service_name}"
                    f" ({traffic_bytes(sum(r['down'] or 0 for r in service_rows))} down)")
    if service_blocked:
        read.append(f"{service_blocked} of {service_name}'s own blocked")
    if groups["other"]:
        others = Counter(traffic_service(r["destination"], r["ip"])[0] for r in groups["other"])
        read.append("also " + ", ".join(name for name, _ in others.most_common(3)))
    if blocked:
        rules = sorted({r["rule"] for r in blocked if r["rule"]})
        places = len(rollup(blocked, "blocked"))
        read.append(f"{places} destination{'s' if places != 1 else ''} blocked"
                    + (" (" + ", ".join(f"{n} {k}" for k, n in kinds.most_common(4)) + ")" if kinds else "")
                    + (f" by {', '.join(rules[:2])}" if rules else ""))
    return {
        "healthy": True, "now": now, "picked": picked, "mac": mac, "device": picked["device"], "widen": widen,
        "start": start, "end": end, "service": service_name,
        "read": "; ".join(read) + ("." if read else ""),
        "if_failed": bool(blocked) or bool(service_blocked),
        "totals": {"flows": len(session_flows), "allowed": sum(1 for r in session_flows if r["kind"] != "blocked"),
                   "blocked": sum(1 for r in session_flows if r["kind"] == "blocked"), "down": sum(r["down"] or 0 for r in session_flows), "up": sum(r["up"] or 0 for r in session_flows),
                   "background": len(groups["background"])},
        "groups": {k: rollup(v, k) for k, v in groups.items()},
        "marks": [{"at": r["at"], "group": r["group"], "picked": r["id"] == picked["id"]}
                  for r in inside[:600]],
    }


# ------------------------------------------------------------
# Device Activity: one device's period as activities (14 Nov 2026; mock-up
# DeviceActivity.dc.html). An activity = the device's flows (background
# set aside) less than 20 s apart, at most 15 minutes: the same rule as
# Related. Background = a destination the device reached in at least half
# of the 10-minute slots it was active in (at least 3), one row per
# destination. Retries = one blocked destination making up 90% or more of
# an activity. Opening one shows its Related view (groups, timing labels,
# the read), Ask Claude (kind traffic, ref a<mac>|<start>|<end>) and Save
# This Activity.
# ------------------------------------------------------------
ACTIVITY_LIMIT = 40000      # records read for one device and period
ACTIVITY_ROWS = 300         # activities listed (newest first)


def activity_flows(mac, start, end):
    """The device's records in the period, background marked; also each
    destination's flow times, and whether the limit cut the period short."""
    with flow_history_reader() as connection:
        rows = connection.execute("SELECT row_id, event_at, payload_json FROM flow_records WHERE device_mac = ? AND event_at >= ? "
                                  "AND event_at < ? ORDER BY event_at DESC, row_id DESC LIMIT ?", (mac, start, end, ACTIVITY_LIMIT)).fetchall()
    flows = sorted((r for r in (traffic_record(*x) for x in rows) if r), key=lambda r: (r["at"], r["id"]))
    slots, times = {}, {}
    for r in flows:
        slots.setdefault(r["destination"], set()).add(int(r["at"] // 600))
        times.setdefault(r["destination"], []).append(r["at"])
    active = len({int(r["at"] // 600) for r in flows})
    background = {d for d, s in slots.items() if len(s) >= max(3, active / 2)}
    for r in flows:
        r["background"] = r["destination"] in background
    return flows, times, len(rows) >= ACTIVITY_LIMIT


def activity_split(flows):
    acts, cur = [], []
    for r in (x for x in flows if not x["background"]):
        if cur and (r["at"] - cur[-1]["at"] > TRAFFIC_SESSION_GAP or r["at"] - cur[0]["at"] > TRAFFIC_SESSION_MAX):
            acts.append(cur)
            cur = []
        cur.append(r)
    if cur:
        acts.append(cur)
    return acts


def activity_row(a, mac):
    """One line of the Activities list."""
    allowed = [r for r in a if r["kind"] != "blocked"]
    blocked = [r for r in a if r["kind"] == "blocked"]
    lead = allowed[0] if allowed else a[0]
    top, top_n = Counter(r["destination"] for r in a).most_common(1)[0]
    retries = len(a) >= 5 and top_n >= 0.9 * len(a) and any(r["destination"] == top and r["kind"] == "blocked" for r in a)
    names = {}
    for r in a:
        names.setdefault(traffic_service(r["destination"], r["ip"])[0], r["destination"])
    lead_name = traffic_service(lead["destination"], lead["ip"])[0]
    others = [n for n in names if n != lead_name]
    rules = Counter(r["rule"] for r in blocked if r["rule"])
    start, end = a[0]["at"], a[-1]["at"]
    # How long it really lasted: to when its last connection ended (a
    # record's time is when the connection started), but never past now:
    # the router can log a connection as lasting far longer than it did
    # (a speed test at 04:39 "lasted" 24 hours, owner 20 Nov 2026).
    length = max(1, min(time.time(), max(r["at"] + float(r.get("duration") or 0) for r in a)) - start)
    return {"start": start, "end": end, "length": length, "records": len(a), "tries": sum(r["count"] or 1 for r in a), "blocked": len(blocked),
            "down": sum(r["down"] or 0 for r in a), "up": sum(r["up"] or 0 for r in a), "retries": retries,
            "what": f"{top} retries" if retries else lead_name, "lead": top if retries else lead["destination"],
            "base": outbound_base(top if retries else lead["destination"]),
            "owner": dest_classify(lead["destination"], lead["ip"], lead["category"])["owner"],
            "others": others[:3], "other_count": len(others), "rule": rules.most_common(1)[0][0] if rules else None,
            "ref": f"a{mac}|{int(start)}|{int(end) + 1}"}


# ------------------------------------------------------------
# What the device was doing (Device Activity step 2, owner 18 Nov 2026):
# each activity gets a type, Certain or Likely, and the clues it was
# decided from. Firewalla records connections, not pages: the clues are
# Firewalla's category, the company, the ports and the shape of the bytes
# (how much, which way, for how long). Back-to-back pieces of the same
# thing (a 2-hour stream is cut into 15-minute activities) are joined.
# ------------------------------------------------------------
ACTIVITY_JOIN_GAP = 120            # seconds between pieces of the same thing that are joined
ACTIVITY_ACTIVE_ALLOW = 10         # seconds a browsing-like connection counts towards the tiles' time
ACTIVITY_BURSTY = {"browse", "brief", "mail", "retry", "speedtest"}
# Speed-test servers (owner, 20 Nov 2026): a test pushes hundreds of MB for a
# few seconds, which looked like a backup; the router can also log its
# connection as lasting a whole day. Any host with "speedtest" in its name
# (Ookla's servers are speedtest.<place>.<isp>), and these sites.
ACTIVITY_SPEEDTEST_SITES = {"ookla.com": "Ookla", "speedtest.net": "Ookla", "measurementlab.net": "M-Lab", "speed.cloudflare.com": "Cloudflare"}
ACTIVITY_VPN_PORTS = {51820: "WireGuard", 1194: "OpenVPN", 1701: "L2TP", 1723: "PPTP"}
ACTIVITY_TOR_PORTS = {9001, 9030, 9050, 9150}
# VPN services (owner, 23 Nov 2026, D-974): Firewalla's "VPN" category alone
# called Office 365, Amazon and Facebook VPN; an activity is VPN only on these,
# a VPN port or a Tor port.
ACTIVITY_VPN_SITES = {"proton.me": "Proton", "protonvpn.com": "Proton VPN", "protonvpn.ch": "Proton VPN", "nordvpn.com": "NordVPN",
                      "expressvpn.com": "ExpressVPN", "surfshark.com": "Surfshark", "mullvad.net": "Mullvad", "privateinternetaccess.com": "PIA",
                      "windscribe.com": "Windscribe", "tunnelbear.com": "TunnelBear", "ipvanish.com": "IPVanish", "cyberghostvpn.com": "CyberGhost",
                      "hide.me": "hide.me", "torproject.org": "Tor", "cloudflareclient.com": "Cloudflare WARP"}
ACTIVITY_MAIL_PORTS = {993: "IMAP", 143: "IMAP", 995: "POP", 110: "POP", 587: "SMTP", 465: "SMTP", 25: "SMTP"}
ACTIVITY_CALL_PORTS = [(3478, 3481), (19302, 19309), (8801, 8810), (50000, 50059)]
ACTIVITY_CALL_SITES = ("teams.microsoft.com", "skype.com", "zoom.us", "webex.com", "facetime.apple.com", "meet.google.com",
                       "discord.media", "discord.gg", "whatsapp.net")
ACTIVITY_STREAM_SITES = {"googlevideo.com": "YouTube", "youtube.com": "YouTube", "nflxvideo.net": "Netflix", "netflix.com": "Netflix",
                         "hulustream.com": "Hulu", "hulu.com": "Hulu", "disneyplus.com": "Disney+", "dssott.com": "Disney+",
                         "aiv-cdn.net": "Prime Video", "primevideo.com": "Prime Video", "ttvnw.net": "Twitch", "twitch.tv": "Twitch",
                         "hbomaxcdn.com": "Max", "max.com": "Max", "pluto.tv": "Pluto TV", "plex.tv": "Plex", "vimeocdn.com": "Vimeo",
                         "tiktokcdn.com": "TikTok", "tiktokv.com": "TikTok"}
ACTIVITY_AUDIO_SITES = {"scdn.co": "Spotify", "spotify.com": "Spotify", "pandora.com": "Pandora", "music.apple.com": "Apple Music",
                        "audible.com": "Audible", "siriusxm.com": "SiriusXM", "iheart.com": "iHeart"}
ACTIVITY_UPDATE_SITES = {"steamcontent.com": "Steam", "steampowered.com": "Steam", "windowsupdate.com": "Windows Update",
                         "delivery.mp.microsoft.com": "Windows Update", "update.microsoft.com": "Windows Update",
                         "swcdn.apple.com": "Apple update", "updates.cdn-apple.com": "Apple update", "epicgames-download1.akamaized.net": "Epic Games",
                         "download.epicgames.com": "Epic Games", "blizzard.com": "Battle.net", "playstation.net": "PlayStation",
                         "xboxlive.com": "Xbox", "dl.google.com": "Google update", "officecdn.microsoft.com": "Office update"}
ACTIVITY_BACKUP_SITES = {"icloud.com": "iCloud", "icloud-content.com": "iCloud", "onedrive.com": "OneDrive", "sharepoint.com": "OneDrive",
                         "dropbox.com": "Dropbox", "dropboxapi.com": "Dropbox", "backblazeb2.com": "Backblaze", "googleapis.com": "Google Drive",
                         "synology.me": "Synology", "quickconnect.to": "Synology"}
ACTIVITY_MAIL_SITES = {"outlook.office365.com": "Outlook", "outlook.office.com": "Outlook", "imap.gmail.com": "Gmail",
                       "mail.google.com": "Gmail", "imap.mail.me.com": "iCloud Mail", "mail.yahoo.com": "Yahoo Mail"}


def activity_site(destination, table):
    """The table's name for a destination (matched on its own name or any
    domain it ends with), else None."""
    name = str(destination or "").lower().rstrip(".")
    for key, label in table.items():
        if name == key or name.endswith("." + key):
            return label
    return None


def activity_kind_hint(a, row):
    """activity_kind, with "Firewalla calls it VPN" among the clues when
    Firewalla's category said VPN but nothing else did (D-974)."""
    kind = activity_kind(a, row)
    if kind and kind.get("type") != "vpn" and any(str(r.get("category") or "").lower() == "vpn" for r in a if r["kind"] != "blocked"):
        kind = {**kind, "why": list(kind.get("why") or []) + ["Firewalla calls it VPN"]}
    return kind


def activity_kind(a, row):
    """{type, label, conf ("Certain" | "Likely"), why: [clues]} for one
    activity's records (background left out)."""
    allowed = [r for r in a if r["kind"] != "blocked"]
    span = row["length"]
    down, up = row["down"], row["up"]
    total = down + up
    lead = row["what"]
    port = lambda r: int(r["port"]) if str(r.get("port") or "").isdigit() else None
    by_bytes = Counter()
    for r in allowed:
        by_bytes[r["destination"]] += (r["down"] or 0) + (r["up"] or 0)
    top_dest, top_bytes = (by_bytes.most_common(1)[0] if by_bytes else (row["lead"], 0))
    cats = Counter()
    for r in allowed:
        if r["category"]:
            cats[str(r["category"]).lower()] += (r["down"] or 0) + (r["up"] or 0) + 1
    cat_share = lambda c: cats[c] / max(1, sum(cats.values()))
    rate = f"{traffic_bytes(total)} in {fmt_duration_short(span)}"
    if row["retries"]:
        return {"type": "retry", "label": f"Blocked Retries · {row['lead']}", "conf": "Certain",
                "why": [f"{row['tries']} tries at {row['lead']}, blocked" + (f" by {row['rule']}" if row["rule"] else "")]}
    # VPN or Tor: its contents are hidden inside the tunnel.
    vpn = [(r, ACTIVITY_VPN_PORTS[port(r)]) for r in allowed if port(r) in ACTIVITY_VPN_PORTS]
    tor = [r for r in allowed if port(r) in ACTIVITY_TOR_PORTS]
    # The VPN service must be what the activity is mainly about (its lead, or
    # the destination with most of its data): one look-up at proton.me inside
    # an Office 365 activity isn't a tunnel, whose traffic the router can't see (D-974).
    vpn_site = activity_site(top_dest, ACTIVITY_VPN_SITES) or activity_site(row["lead"], ACTIVITY_VPN_SITES)
    if vpn_site or vpn or tor:
        if tor and not vpn_site and not vpn:
            return {"type": "vpn", "label": f"Tor · {lead}", "conf": "Likely",
                    "why": [f"Port {port(tor[0])}, which Tor uses", rate, "What goes on inside it is hidden"]}
        how = vpn[0][1] if vpn else "VPN"
        why = ([f"{vpn_site}, a VPN service"] if vpn_site else []) + (["Firewalla's category: VPN"] if cats["vpn"] else []) + ([f"{how} port {port(vpn[0][0])}"] if vpn else [])
        return {"type": "vpn", "label": f"VPN · {lead}" + (f" ({how})" if vpn else ""), "conf": "Certain" if vpn_site or vpn else "Likely",
                "why": why + [rate, "What goes on inside it is hidden"]}
    # A speed test: a speed-test server, whatever it sent (an upload test
    # looks like a backup, a download test like a large download).
    # They must carry at least half its data: a page that only touches
    # speedtest.net in passing stays what it is.
    is_speed = lambda d: "speedtest" in str(d).lower() or bool(activity_site(d, ACTIVITY_SPEEDTEST_SITES))
    speed = next((d for d, _ in by_bytes.most_common() if is_speed(d)), None)
    if speed and sum(n for d, n in by_bytes.items() if is_speed(d)) >= 0.5 * max(1, total):
        return {"type": "speedtest", "label": f"Speed Test · {activity_site(speed, ACTIVITY_SPEEDTEST_SITES) or lead}", "conf": "Certain",
                "why": [f"{speed} is a speed-test server", f"{traffic_bytes(up)} up, {traffic_bytes(down)} down"]}
    # A video or voice call: UDP to call servers, both ways, for a while.
    call_port = [r for r in allowed if r["protocol"].upper() == "UDP" and port(r) and any(lo <= port(r) <= hi for lo, hi in ACTIVITY_CALL_PORTS)]
    call_site = next((r["destination"] for r in allowed if any(str(r["destination"]).lower().endswith(s) for s in ACTIVITY_CALL_SITES)), None)
    if (call_port or call_site) and span >= 60 and total >= 2 * 1024 ** 2 and up >= 0.25 * max(1, down):
        why = ([f"UDP port {port(call_port[0])}, used by calls"] if call_port else []) + ([f"Call service {call_site}"] if call_site else [])
        return {"type": "call", "label": f"Video or Voice Call · {lead}", "conf": "Certain" if call_port and call_site else "Likely",
                "why": why + [f"About as much up ({traffic_bytes(up)}) as down ({traffic_bytes(down)}) for {fmt_duration_short(span)}"]}
    # Streaming video or audio: a steady large download from a video service.
    stream = activity_site(top_dest, ACTIVITY_STREAM_SITES)
    audio = activity_site(top_dest, ACTIVITY_AUDIO_SITES)
    if (cat_share("av") >= 0.5 or stream or audio) and down >= (3 if audio else 20) * 1024 ** 2 and span >= 60:
        name = stream or audio or lead
        why = (["Firewalla's category: video and audio"] if cat_share("av") >= 0.5 else []) + ([f"{top_dest} is {name}"] if stream or audio else [])
        return {"type": "audio" if audio and not stream else "stream", "label": f"Streaming {'Audio' if audio and not stream else 'Video'} · {name}",
                "conf": "Certain" if (cat_share("av") >= 0.5) and (stream or audio) else "Likely",
                "why": why + [f"{traffic_bytes(down)} down over {fmt_duration_short(span)}, steady"]}
    # Gaming: Firewalla's games category.
    if cat_share("games") >= 0.5:
        return {"type": "game", "label": f"Gaming · {lead}", "conf": "Likely",
                "why": ["Firewalla's category: games", rate]}
    # A backup or upload: much more up than down.
    if up >= 50 * 1024 ** 2 and up >= 2 * max(1, down):
        site = activity_site(top_dest, ACTIVITY_BACKUP_SITES)
        return {"type": "upload", "label": f"Upload or Backup · {site or lead}", "conf": "Certain" if site else "Likely",
                "why": ([f"{top_dest} is {site}"] if site else []) + [f"{traffic_bytes(up)} up, {traffic_bytes(down)} down"]}
    # A large download or update: one place, a lot of data.
    if down >= 100 * 1024 ** 2 and top_bytes >= 0.7 * max(1, total):
        site = activity_site(top_dest, ACTIVITY_UPDATE_SITES)
        return {"type": "download", "label": f"{'Update' if site else 'Large Download'} · {site or lead}", "conf": "Certain" if site else "Likely",
                "why": ([f"{top_dest} is {site}"] if site else []) + [f"{traffic_bytes(down)} down from {top_dest} in {fmt_duration_short(span)}"]}
    # Email: mail ports or mail services.
    mail_port = next((r for r in allowed if port(r) in ACTIVITY_MAIL_PORTS), None)
    mail_site = next((activity_site(r["destination"], ACTIVITY_MAIL_SITES) for r in allowed if activity_site(r["destination"], ACTIVITY_MAIL_SITES)), None)
    if mail_port or mail_site:
        why = ([f"{ACTIVITY_MAIL_PORTS[port(mail_port)]} mail port {port(mail_port)}"] if mail_port else []) + ([f"Mail service: {mail_site}"] if mail_site else [])
        return {"type": "mail", "label": f"Email · {mail_site or lead}", "conf": "Certain" if mail_port else "Likely", "why": why}
    # Anything small: an app or page checking in briefly.
    if total < 100 * 1024:
        return {"type": "brief", "label": f"Brief Check-In · {lead}", "conf": "Likely",
                "why": [f"Only {traffic_bytes(total)} in {fmt_duration_short(span)}"]}
    web = sum(1 for r in allowed if port(r) in (80, 443)) >= 0.6 * max(1, len(allowed))
    helpers = row["other_count"]
    return {"type": "browse", "label": f"Browsing · {lead}", "conf": "Likely",
            "why": (["Web traffic (ports 443 and 80)"] if web else []) + [f"{rate}"]
            + ([f"{helpers} other compan{'y' if helpers == 1 else 'ies'} pulled in (images, scripts, ads)"] if helpers else [])}


ACTIVITY_JOINABLE = {"stream", "audio", "call", "game", "download", "upload", "vpn", "browse"}


def activity_join(acts, rows, kinds):
    """Back-to-back pieces of the same thing, joined: same type, same lead
    company, at most ACTIVITY_JOIN_GAP apart."""
    out = []
    for a, row, kind in zip(acts, rows, kinds):
        if out:
            pa, prow, pkind = out[-1]
            if (kind["type"] == pkind["type"] and kind["type"] in ACTIVITY_JOINABLE
                    and row["what"] == prow["what"] and row["start"] - prow["end"] <= ACTIVITY_JOIN_GAP):
                out[-1] = (pa + a, {**prow, "end": row["end"]}, kind)
                continue
        out.append((a, row, kind))
    return [x[0] for x in out]


def activity_view(flows, a, mac, times, now):
    """The Related view of one activity: its flows plus the background ones
    in the same time, its lead as the picked record."""
    start, end = a[0]["at"], a[-1]["at"]
    inside = [r for r in flows if start <= r["at"] <= end]
    lead = next((r for r in a if r["kind"] != "blocked"), a[0])
    view = traffic_session_view(inside, lead, mac, start, end, None, times, now)
    # Its own records in time order, for The Records list (and Export).
    view["records"] = [{k: r.get(k) for k in ("id", "at", "destination", "protocol", "port", "kind", "rule", "rule_pid", "count", "down", "up", "country")}
                       for r in a[:500]]
    view["records_count"] = len(a)
    return view


def device_activity_detail(mac, start, end):
    """One activity by its device and times (Ask Claude, Save This
    Activity): read again with an hour either side for the background."""
    flows, times, _ = activity_flows(mac, start - 3600, end + 3600)
    a = [r for r in flows if not r["background"] and start <= r["at"] <= end]
    if not a:
        return {"healthy": False, "error": "That activity is gone: flow records are kept 24 hours."}
    return activity_view(flows, a, mac, times, time.time())


def activity_dest_24h(mac, destination, now):
    """The clicked activity's exact destination, this device, the last 24
    hours (whatever the page's period): records, allowed, blocked, bytes."""
    with flow_history_reader() as connection:
        n, blocked, down, up = connection.execute(
            """SELECT COUNT(*), SUM(kind = 'blocked'), SUM(COALESCE(download_bytes, 0)), SUM(COALESCE(upload_bytes, 0))
               FROM flow_records WHERE device_mac = ? AND COALESCE(destination, remote_ip, '--') = ? AND event_at >= ?""",
            (mac, destination, now - 86400)).fetchone()
    return {"destination": destination, "records": n or 0, "blocked": blocked or 0, "allowed": (n or 0) - (blocked or 0),
            "down": down or 0, "up": up or 0}


def device_activity_records(mac, start, end):
    """The period's records, split into activities with their rows: the part
    of the Device Activity page that is the same whichever row is clicked.
    Kept a short while (shared_result), so a click on a row no longer reads
    and sorts out up to 40,000 records again (20 Nov 2026). Nothing in it
    is changed afterwards."""
    flows, times, cut = activity_flows(mac, start, end)
    acts = activity_split(flows)
    rows = [activity_row(a, mac) for a in acts]
    acts = activity_join(acts, rows, [activity_kind_hint(a, r) for a, r in zip(acts, rows)])
    rows = [activity_row(a, mac) for a in acts]
    for a, r in zip(acts, rows):
        r["kind"] = activity_kind_hint(a, r)
        # A speed test lasts its few seconds of traffic, not the day the
        # router may log its connection for (owner, 20 Nov 2026).
        if r["kind"]["type"] == "speedtest":
            r["length"] = max(1, max(x["at"] + min(float(x.get("duration") or 0), ACTIVITY_ACTIVE_ALLOW) for x in a) - r["start"])
    return {"healthy": True, "flows": flows, "times": times, "cut": cut, "acts": acts, "rows": rows}


def device_activity(mac, start, end, pick=None, show=None):
    now = time.time()
    got = shared_result(("device-activity-records", mac, int(start // 60), int(end // 60)), lambda: device_activity_records(mac, start, end))
    flows, times, cut, acts, rows = got["flows"], got["times"], got["cut"], got["acts"], got["rows"]
    keep = [i for i, r in enumerate(rows) if show != "blocked" or r["blocked"]]
    keep = [i for i in keep if show != "big" or rows[i]["down"] + rows[i]["up"] >= 1024 * 1024]
    chosen = None
    if keep:
        if pick:
            chosen = min(keep, key=lambda i: 0 if rows[i]["start"] - 1 <= pick <= rows[i]["end"] + 1 else abs(rows[i]["start"] - pick) + 1)
        else:
            # The newest real activity: Brief Check-Ins are hidden unless
            # their chip is picked (owner, 18 Nov 2026).
            chosen = next((i for i in reversed(keep) if rows[i]["kind"]["type"] != "brief"), keep[-1])
    bg = {}
    for r in flows:
        if r["background"]:
            b = bg.setdefault(r["destination"], {"destination": r["destination"], "records": 0, "blocked": 0, "down": 0, "up": 0,
                                                 "first": r["at"], "last": r["at"], "ip": r["ip"], "category": r["category"]})
            b["records"] += 1
            b["blocked"] += r["kind"] == "blocked"
            b["down"] += r["down"] or 0
            b["up"] += r["up"] or 0
            b["last"] = r["at"]
    for b in bg.values():
        gaps = sorted(y - x for x, y in zip(times[b["destination"]], times[b["destination"]][1:]) if y > x)
        b["every"] = gaps[len(gaps) // 2] if gaps else None
        c = dest_classify(b["destination"], b.pop("ip"), b.pop("category"))
        b["owner"], b["what"] = c["owner"], c["what"]
    device = flows[-1]["device"] if flows else next((d.get("name") for d in state.get("devices") or [] if str(d.get("mac") or "").upper() == mac.upper()), mac)
    selected, domain = None, None
    if chosen is not None:
        row = rows[chosen]
        # Elsewhere: other times in the period it did the same thing.
        same = [[r["start"], r["start"] + r["length"]] for i, r in enumerate(rows)
                if i != chosen and r["kind"]["type"] == row["kind"]["type"] and r["what"] == row["what"]]
        selected = {**activity_view(flows, acts[chosen], mac, times, now), "row": row,
                    "dest_24h": activity_dest_24h(mac, row["lead"], now),
                    "elsewhere": same[-6:], "elsewhere_count": len(same)}
    # The list shows every activity: a click opens one on the right (the
    # list no longer narrows to its domain: redesign step 1, 18 Nov 2026).
    listed = [rows[i] for i in reversed(keep)]
    # The newest ACTIVITY_ROWS of the real activities and of the Brief
    # Check-Ins each, so hidden check-ins don't push real ones off the list.
    shown = sorted([r for r in listed if r["kind"]["type"] != "brief"][:ACTIVITY_ROWS]
                   + [r for r in listed if r["kind"]["type"] == "brief"][:ACTIVITY_ROWS], key=lambda r: -r["start"])
    # The day in a line: time and data per type (the page's tiles).
    # The tiles' time is when traffic flowed (owner, 18 Nov 2026): for
    # browsing-like types each connection counts from its start for at most
    # ACTIVITY_ACTIVE_ALLOW seconds, not for as long as the browser kept it
    # open (about a minute after the last click). Streaming, calls, games,
    # downloads and VPNs send all the while, so their connections count in
    # full. Overlaps count once.
    summary, spans = {}, {}
    for a, r in zip(acts, rows):
        t = summary.setdefault(r["kind"]["type"], {"seconds": 0, "bytes": 0, "count": 0})
        t["bytes"] += r["down"] + r["up"]
        t["count"] += 1
        spans.setdefault(r["kind"]["type"], []).extend(
            (x["at"], x["at"] + max(1.0, min(float(x.get("duration") or 0), ACTIVITY_ACTIVE_ALLOW)
                                    if r["kind"]["type"] in ACTIVITY_BURSTY else float(x.get("duration") or 0))) for x in a)
    # Only time inside the period counts, and never past now (a connection
    # the router logged as lasting a day made a 23h 59m tile, 20 Nov 2026).
    last = min(end, now)
    for k, list_ in spans.items():
        reach = None
        for s, e in sorted((max(s, start), min(e, last)) for s, e in list_):
            if e <= s:
                continue
            if reach is None or s > reach:
                summary[k]["seconds"] += e - s
                reach = e
            elif e > reach:
                summary[k]["seconds"] += e - reach
                reach = e
    return {
        "healthy": True, "now": now, "mac": mac, "device": device, "start": start, "end": end, "cut": cut,
        "totals": {"records": len(flows), "allowed": sum(1 for r in flows if r["kind"] != "blocked"),
                   "blocked": sum(1 for r in flows if r["kind"] == "blocked"), "activities": len(rows), "shown": len(keep),
                   "background": sum(b["records"] for b in bg.values()), "down": sum(r["down"] or 0 for r in flows),
                   "up": sum(r["up"] or 0 for r in flows)},
        "strip": [[r["start"], r["start"] + r["length"], r["blocked"] > 0, r["kind"]["type"]] for r in (rows[i] for i in keep)],
        "summary": summary,
        "strip_background": sorted({int(r["at"] // 60 * 60) for r in flows if r["background"]}),
        "activities": shown, "more": len(listed) - len(shown), "domain": domain,
        "background": sorted(bg.values(), key=lambda b: -b["records"]),
        "selected": selected,
    }


@app.get("/api/device-activity")
def api_device_activity(request: Request):
    """?mac= the device; h= hours back (default 24) or from= / to=; pick= a
    time (the activity at it is opened); show= blocked | big."""
    q = request.query_params
    now = time.time()
    mac = str(q.get("mac") or "").upper()
    try:
        end = float(q.get("to") or now)
        start = float(q.get("from") or end - float(q.get("h") or 24) * 3600)
        pick = float(q["pick"]) if q.get("pick") else None
    except ValueError:
        return {"healthy": False, "error": "Bad time"}
    if not all(abs(t) < 1e11 for t in (start, end, pick or 0)):   # also refuses inf and nan
        return {"healthy": False, "error": "Bad time"}

    def devices():
        with flow_history_reader() as connection:
            got = connection.execute("SELECT device_mac, MAX(device), MAX(source_network), COUNT(*) AS n FROM flow_records WHERE event_at >= ? "
                                     "AND device_mac NOT LIKE 'IF:%' GROUP BY device_mac ORDER BY n DESC LIMIT 120", (now - 86400,)).fetchall()
        return {"healthy": True, "list": [{"mac": m, "name": traffic_device_name(m, d, n), "records": int(c)} for m, d, n, c in got if m]}

    with claude_lock:
        claude = claude_public(claude_load(), "traffic")   # fresh each time; the rest is cached 60 s
    out = {"devices": shared_result(("activity-devices",), devices)["list"], "claude": claude}
    if q.get("record") and not mac:
        # An older Related link (#flows?related=<record>): that record's device and time.
        with flow_history_reader() as connection:
            got = connection.execute("SELECT device_mac, event_at FROM flow_records WHERE row_id = ?", (int(q["record"]) if q["record"].isdigit() and len(q["record"]) <= 18 else -1,)).fetchone()
        if not got:
            return {**out, "healthy": False, "error": "That record is gone: flow records are kept 24 hours."}
        mac, pick = str(got[0]).upper(), float(got[1])
    if not mac:
        return {**out, "healthy": True, "mac": None}
    try:
        page = shared_result(("device-activity", mac, int(start // 60), int(end // 60), pick, q.get("show")),
                             lambda: device_activity(mac, start, end, pick, q.get("show")))
    except Exception as exc:
        return {**out, "healthy": False, "error": public_error("Client Activity", exc)}
    return {**page, **out}


# ------------------------------------------------------------
# Traffic page, Local tab (owner, 18 Nov 2026): device-to-device traffic
# inside your network, from the local traffic recorder's hourly totals
# (7 days). One device (mac=) lists the devices it talks to; no device
# lists every pair. A peer (peer=, with mac=) opens that pair: each port,
# who starts it, allowed and blocked, data, and what allowed or blocked
# it. Two devices on the same network talk through the switches and APs:
# the router never sees that, so it isn't here.
# ------------------------------------------------------------
TRAFFIC_LOCAL_HOURS = (1, 6, 24, 168)


@app.get("/api/traffic-local/open")
def api_traffic_local_open(port: str = "", minutes: int = 5):
    """How "starts" are counted, checked (23 Nov 2026: camera streams on tcp
    554 counted ~200 starts an hour): the local connections with a record in
    the last minutes (1-5, the start-counting gap), for one port if given,
    each with its addresses, ports and how long ago its last record was; and
    per port the records with no starting-side port, which count as starts."""
    minutes = max(1, min(LOCAL_CONNECTION_GAP // 60, minutes))
    latest = max(local_connections_open.values(), default=0)
    rows = [{"src": c[0], "src_port": c[1], "dst": c[2], "dst_port": c[3], "protocol": c[4], "ago": round(latest - ts)}
            for c, ts in list(local_connections_open.items())
            if latest - ts <= minutes * 60 and (not port or str(c[3]) == port)]
    by_port = Counter(f"{r['protocol']} {r['dst_port']}" for r in rows)
    return {"latest_record": latest, "minutes": minutes, "port": port or None, "open": len(rows), "by_port": dict(by_port.most_common(30)),
            "connections": sorted(rows, key=lambda r: r["ago"])[:300] if port else [],
            "no_port_since_start": dict(local_no_port.most_common(30)), "recorder_started": local_traffic_stats.get("started_at")}


@app.get("/api/traffic-local")
def api_traffic_local(request: Request):
    """mac= the Device, with= the device it talks with (both optional); h=
    1, 6, 24 or 168 hours; kind= normal | blocked. One row per pair, each
    with a line per way a connection is made (who starts it, protocol and
    port; replies travel on the same connection), allowed and blocked side
    by side, and an hourly strip (owner, 18 Nov 2026)."""
    q = request.query_params
    mac = str(q.get("mac") or "").upper()
    peer = str(q.get("with") or "").upper()
    if peer and not mac:
        mac, peer = peer, ""   # With alone is the same as Device alone
    try:
        hours = int(q.get("h") or 24)
    except ValueError:
        hours = 24
    hours = hours if hours in TRAFFIC_LOCAL_HOURS else 24
    outcome = {"normal": "allowed", "blocked": "blocked"}.get(q.get("kind") or "")
    now = time.time()
    since = int((now - hours * 3600) // 3600 * 3600)
    base, base_args = " WHERE hour >= ?", [since]
    if outcome:
        base += " AND outcome = ?"
        base_args.append(outcome)
    where, args = base, list(base_args)
    if mac:
        where += " AND (src_mac = ? OR dst_mac = ?)"
        args += [mac, mac]
    if peer:
        where += " AND (src_mac = ? OR dst_mac = ?)"
        args += [peer, peer]
    try:
        flush_local_traffic()
        with local_traffic_connection() as connection:
            rows = connection.execute(f"""
                SELECT hour, src_mac, dst_mac, protocol, port, outcome, flows, bytes_sent, bytes_received,
                       first_ts, last_ts, allowed_by, blocked_by, starts
                FROM local_traffic_hourly{where}""", args).fetchall()
            # The With box: the devices the Device talked with (or every
            # device that talked), busiest first.
            if mac:
                partners = connection.execute(f"""
                    SELECT CASE WHEN src_mac = ? THEN dst_mac ELSE src_mac END AS other, SUM(COALESCE(starts, flows)) AS n
                    FROM local_traffic_hourly{base} AND (src_mac = ? OR dst_mac = ?) GROUP BY other ORDER BY n DESC""",
                    [mac] + base_args + [mac, mac]).fetchall()
            else:
                partners = connection.execute(f"""
                    SELECT m, SUM(n) AS t FROM (SELECT src_mac AS m, SUM(COALESCE(starts, flows)) AS n FROM local_traffic_hourly{base} GROUP BY src_mac
                    UNION ALL SELECT dst_mac, SUM(COALESCE(starts, flows)) FROM local_traffic_hourly{base} GROUP BY dst_mac) GROUP BY m ORDER BY t DESC""",
                    base_args + base_args).fetchall()
            oldest = connection.execute("SELECT MIN(hour) FROM local_traffic_hourly").fetchone()[0]
    except Exception as exc:
        return {"healthy": False, "error": public_error("Local traffic", exc)}
    sides, groups = access_sides()
    peers = access_peer_sides()
    lans = traffic_lan_names()
    name = lambda m: (sides.get(m) or peers.get(m) or {}).get("name") or m

    def side(m):
        """A pair's end: one of your clients, a VPN peer by its name (D-948),
        or an address no client has, with the network it is on (D-947)."""
        if m in sides or m in peers:
            s_ = sides.get(m) or peers[m]
            return {"mac": m, "name": s_["name"], "network": s_.get("network_name") or "--", "known": m in sides, "peer": m in peers}
        net = next((n for net_, n in lans if traffic_ip_in(m, net_)), None)
        return {"mac": m, "name": m, "network": net or "--", "known": False, "no_client": local_no_client(m)}
    slots = int((now // 3600 * 3600 - since) // 3600) + 1   # every hour from since to the current one
    pairs, chart = {}, {}
    for hour, src, dst, protocol, port, out, flows, sent, received, first, last, allowed_by, blocked_by, starts in rows:
        a, b = (mac, dst if src == mac else src) if mac else tuple(sorted((src, dst)))
        # Connections started (one that stays open counts once; router records
        # on rows from before 23 Nov 2026), as on every page (D-904, D-913).
        n = int(starts if starts is not None else flows or 0)
        p = pairs.setdefault((a, b), {"a": a, "b": b, "allowed": 0, "blocked": 0, "unanswered": 0, "bytes": 0, "last": 0, "lines": {}})
        # A blocked try at a client not answering isn't a block (D-913: the
        # one definition, policy.local_block_kind): counted apart.
        if out == "blocked" and local_block_kind(src, dst, protocol, port, blocked_by, int(sent or 0) + int(received or 0), first, last) != "real":
            out = "unanswered"
        p[{"blocked": "blocked", "unanswered": "unanswered"}.get(out, "allowed")] += n
        p["bytes"] += int(sent or 0) + int(received or 0)
        p["last"] = max(p["last"], last or 0)
        key, label = local_port_label(protocol, port)
        line = p["lines"].setdefault((src, key), {
            "starts": src, "to": dst, "port": label, "service": LOCAL_PORT_SERVICES.get(key) or "",
            "allowed": 0, "blocked": 0, "unanswered": 0, "sent": 0, "received": 0, "last_allowed": None, "last_blocked": None,
            "allowed_by": set(), "blocked_by": set(), "strip": [[0, 0] for _ in range(slots)], "conn": {}})
        slot = min(slots - 1, max(0, int((hour - since) // 3600)))
        if out == "unanswered":
            line["unanswered"] += n
            line["last_unanswered"] = max(line.get("last_unanswered") or 0, last or 0) or None
            continue
        if out == "blocked":
            line["blocked"] += n
            line["last_blocked"] = max(line["last_blocked"] or 0, last or 0) or None
            line["blocked_by"].update(x for x in str(blocked_by or "").split(",") if x)
            line["strip"][slot][1] += n
        else:
            line["allowed"] += n
            line["last_allowed"] = max(line["last_allowed"] or 0, last or 0) or None
            line["allowed_by"].update(x for x in str(allowed_by or "").split(",") if x)
            line["strip"][slot][0] += n
        if starts is not None:   # connections opened (one that stays open counts once; from 23 Nov 2026)
            line["conn"][slot] = line["conn"].get(slot, 0) + int(starts)
        line["sent"] += int(sent or 0)
        line["received"] += int(received or 0)
        c = chart.setdefault(hour, [0, 0, 0])
        c[1 if out == "blocked" else 0] += n
        c[2] += int(sent or 0) + int(received or 0)
    out_pairs = []
    for p in pairs.values():
        lines = []
        for line in p["lines"].values():
            lines.append({**{k: line.get(k) for k in ("port", "service", "allowed", "blocked", "unanswered", "sent", "received", "last_allowed", "last_blocked", "last_unanswered")},
                          # The hourly strip, only the hours with traffic: [slot, allowed, blocked].
                          "strip": [[i, x, y] for i, (x, y) in enumerate(line["strip"]) if x or y],
                          # Connections opened per hour, allowed and blocked together: [slot, n],
                          # only the hours counted that way (router records count each open minute).
                          "conn_strip": sorted([i, n] for i, n in line["conn"].items()),
                          "starts": "a" if line["starts"] == p["a"] else "b",
                          "allowed_by": [traffic_rule_name(x) for x in sorted(line["allowed_by"])],
                          "blocked_by": [policy_blocked_text(x, groups) for x in sorted(line["blocked_by"])]})
        lines.sort(key=lambda x: (x["starts"], -(x["allowed"] + x["blocked"])))
        out_pairs.append({"key": f"{p['a']}|{p['b']}", "a": side(p["a"]), "b": side(p["b"]), "allowed": p["allowed"], "blocked": p["blocked"], "unanswered": p["unanswered"],
                          "bytes": p["bytes"], "last": p["last"] or None, "lines": lines})
    out_pairs = traffic_sweeps(out_pairs)
    # Pairs with something blocked first, then the busiest.
    out_pairs.sort(key=lambda r: (not r["blocked"], -(r["allowed"] + r["blocked"] + r["unanswered"])))
    me = mac or None
    sent = sum(int(r[7] or 0) for r in rows if not me or r[1] == me) + sum(int(r[8] or 0) for r in rows if me and r[2] == me)
    received = sum(int(r[8] or 0) for r in rows if not me or r[1] == me) + sum(int(r[7] or 0) for r in rows if me and r[2] == me)
    return {
        "healthy": True, "now": now, "hours": hours, "since": since, "slots": slots, "oldest": oldest,
        "mac": mac or None, "with": peer or None, "device": side(mac) if mac else None, "partner": side(peer) if peer else None,
        "with_options": [{"mac": m, "name": name(m), "flows": int(n or 0)} for m, n in partners if m and m != mac],
        "totals": {"flows": sum(p["allowed"] for p in out_pairs), "blocked": sum(p["blocked"] for p in out_pairs),
                   "unanswered": sum(p["unanswered"] for p in out_pairs),
                   "sent": sent, "received": received, "pairs": len(out_pairs)},
        "hourly": [{"hour": h, "allowed": v[0], "blocked": v[1], "bytes": v[2]} for h, v in sorted(chart.items())],
        "rows": out_pairs[:300], "more": max(0, len(out_pairs) - 300),
    }

def traffic_lan_names():
    """[(ip_network, name)]: your own networks (not WAN) by Firewalla's name."""
    out = []
    for uuid, meta in core.INTERFACE_METADATA.items():
        if meta.get("network_type") == "wan" or not meta.get("subnet"):
            continue
        try:
            out.append((ipaddress.ip_network(str(meta["subnet"]), strict=False), internet_interface_name(uuid) or meta.get("display_name") or str(uuid)))
        except ValueError:
            pass
    return out


def traffic_ip_in(text, net):
    try:
        return ipaddress.ip_address(str(text)) in net
    except ValueError:
        return False


def traffic_sweeps(pairs):
    """One row for a client's tries at two or more addresses no client has on
    one network, nothing answered (owner, 23 Nov 2026, D-947: a printer search
    sweeping 192.168.7.x made 37 rows): "<n> addresses with no client"."""
    groups, keep = {}, []
    for p in pairs:
        ends = [k for k in ("a", "b") if p[k].get("no_client")]
        if len(ends) != 1 or p["allowed"] or p["blocked"]:
            keep.append(p)
            continue
        nobody = ends[0]
        me = "b" if nobody == "a" else "a"
        groups.setdefault((p[me]["mac"], p[nobody]["network"]), []).append((p, me, nobody))
    for (mac, net), items in groups.items():
        if len(items) < 2:
            keep += [p for p, _, _ in items]
            continue
        addresses = sorted((p[nb]["mac"] for p, _, nb in items), key=lambda t: [int(x) for x in t.split(".")])
        lines = {}
        for p, me, _ in items:
            for ln in p["lines"]:
                starts = "a" if ln["starts"] == me else "b"
                m = lines.setdefault((starts, ln["port"]), {**ln, "starts": starts, "strip": [], "conn_strip": [], "allowed": 0, "blocked": 0, "unanswered": 0,
                                                             "sent": 0, "received": 0, "last_allowed": None, "last_blocked": None, "last_unanswered": None,
                                                             "allowed_by": [], "blocked_by": []})
                for k in ("allowed", "blocked", "unanswered", "sent", "received"):
                    m[k] += ln.get(k) or 0
                for k in ("last_allowed", "last_blocked", "last_unanswered"):
                    if ln.get(k):
                        m[k] = max(m[k] or 0, ln[k])
                strip = {i: [x, y] for i, x, y in m["strip"]}
                for i, x, y in ln.get("strip") or []:
                    strip.setdefault(i, [0, 0]); strip[i][0] += x; strip[i][1] += y
                m["strip"] = [[i, x, y] for i, (x, y) in sorted(strip.items())]
                conn = dict(m["conn_strip"])
                for i, n in ln.get("conn_strip") or []:
                    conn[i] = conn.get(i, 0) + n
                m["conn_strip"] = sorted([i, n] for i, n in conn.items())
                m["allowed_by"] = sorted(set(m["allowed_by"]) | set(ln.get("allowed_by") or []))
                m["blocked_by"] = sorted(set(m["blocked_by"]) | set(ln.get("blocked_by") or []))
        first = items[0][0][items[0][1]]
        keep.append({"key": f"{mac}|sweep|{net}", "a": first,
                     "b": {"mac": f"sweep:{net}", "name": f"{len(addresses)} addresses with no client", "network": net, "known": False,
                           "no_client": True, "addresses": addresses},
                     "allowed": 0, "blocked": 0, "unanswered": sum(p["unanswered"] for p, _, _ in items),
                     "bytes": sum(p["bytes"] for p, _, _ in items), "last": max(p["last"] or 0 for p, _, _ in items) or None,
                     "lines": sorted(lines.values(), key=lambda x: (x["starts"], -(x["unanswered"] or 0)))})
    return keep


def traffic_bytes(n):
    n = float(n or 0)
    for unit, size in (("GB", 1024 ** 3), ("MB", 1024 ** 2), ("KB", 1024)):
        if n >= size:
            return f"{n / size:.1f} {unit}" if n < 10 * size else f"{n / size:.0f} {unit}"
    return f"{int(n)} B"


# ------------------------------------------------------------
# Hidden destinations
# ------------------------------------------------------------
def traffic_hidden():
    """{destination: {"at", "scopes": [{"mac", "groups": [group ids], "at"}]}}.
    A hide is for the client it was hidden from and every client in its
    groups (the user, 15 Nov 2026: ads blocked on a TV are fine, the same
    block on another group's PC must still show). An entry with no scopes
    (the first hides) is for every device."""
    return (policy_read_json(TRAFFIC_HIDDEN_FILE) or {}).get("hidden") or {}


def traffic_hidden_macs(entry):
    """The clients a hide covers (upper-case MACs), or None for every device.
    Group members are read now, so a client joining the group is covered."""
    scopes = (entry or {}).get("scopes")
    if not scopes:
        return None
    groups = (state.get("groups") or {}).get("groups") or []
    macs = set()
    for sc in scopes:
        macs.add(str(sc.get("mac") or "").upper())
        wanted = {str(g) for g in sc.get("groups") or []}
        for g in groups:
            if str(g.get("id")) in wanted:
                macs |= {str(m).upper() for m in g.get("members") or []}
    return macs


def traffic_hidden_resolve(hidden=None):
    """{destination: the clients it is hidden for, or None for every device},
    worked out once per page build."""
    hidden = traffic_hidden() if hidden is None else hidden
    return {dest: traffic_hidden_macs(entry) for dest, entry in hidden.items()}


def traffic_is_hidden(resolved, mac, *names):
    """True if any of names (a destination's name or IP) is hidden for mac.
    resolved: from traffic_hidden_resolve."""
    mac = str(mac or "").upper()
    for n in names:
        if n and n in resolved:
            macs = resolved[n]
            if macs is None or mac in macs:
                return True
    return False


def traffic_hidden_sql(resolved):
    """A SQL test that is true for a hidden record, and its values; ("", [])
    when nothing is hidden. The lists go in as JSON (two values however many
    hides), so SQLite's limit on values can't be reached."""
    everyone, pairs = [], []
    for dest, macs in sorted(resolved.items()):
        if macs is None:
            everyone.append(dest)
        else:
            pairs += sorted(f"{m}|{dest}" for m in macs if m)
    parts, values = [], []
    if everyone:
        parts.append("COALESCE(destination, remote_ip, '') IN (SELECT value FROM json_each(?))")
        values.append(json.dumps(everyone))
    if pairs:
        parts.append("(COALESCE(UPPER(device_mac), '') || '|' || COALESCE(destination, remote_ip, '')) IN (SELECT value FROM json_each(?))")
        values.append(json.dumps(pairs))
    return (f"({' OR '.join(parts)})", values) if parts else ("", [])


TRAFFIC_HIDE_BATCH = 500


@app.post("/api/traffic/hide")
def api_traffic_hide(payload: dict = Body(default={})):
    """{destination, mac}, or {items: [{destination, mac}, ...]} (the row
    check boxes, up to 500): hide each from Traffic's Records and
    Destinations for that client and every client in its groups."""
    items = payload.get("items") if "items" in payload else [payload]
    if not isinstance(items, list) or not items or len(items) > TRAFFIC_HIDE_BATCH:
        return {"ok": False, "error": f"Pick 1 to {TRAFFIC_HIDE_BATCH} rows."}
    picks = []
    for item in items:
        if not isinstance(item, dict):
            return {"ok": False, "error": "Not a row."}
        destination = str(item.get("destination") or "").strip()[:255]
        mac = str(item.get("mac") or "").strip().upper()
        if not destination or destination == "--":
            return {"ok": False, "error": "No destination."}
        if not re.fullmatch(r"([0-9A-F]{2}:){5}[0-9A-F]{2}|IF:[\w:.-]{1,37}", mac):
            return {"ok": False, "error": "No client: pick a client first."}
        picks.append((destination, mac))
    groups_of = {mac: site_test_groups(mac) for mac in {m for _, m in picks}}
    now = time.time()
    with traffic_lock:
        st = policy_read_json(TRAFFIC_HIDDEN_FILE) or {}
        hidden = st.setdefault("hidden", {})
        if len(set(hidden) | {d for d, _ in picks}) > TRAFFIC_HIDDEN_MAX:
            return {"ok": False, "error": f"Only {TRAFFIC_HIDDEN_MAX} destinations can be hidden."}
        for destination, mac in picks:
            scope = {"mac": mac, "groups": [g["id"] for g in groups_of[mac]], "at": now}
            entry = hidden.get(destination)
            if entry is None:
                entry = hidden[destination] = {"at": now, "scopes": []}
            if entry.get("scopes"):    # none = already hidden for every device
                entry["scopes"] = [sc for sc in entry["scopes"] if str(sc.get("mac") or "").upper() != mac]
                entry["scopes"].append(scope)
            elif "scopes" in entry:
                entry["scopes"] = [scope]
        temporary = TRAFFIC_HIDDEN_FILE + ".tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump(st, handle, indent=1)
        os.replace(temporary, TRAFFIC_HIDDEN_FILE)
    # What is already waiting for it: Outbound To Triage items are filed at
    # once (alarms turn Hidden by themselves on the next read).
    with outbound_lock:
        ob = outbound_state_load()
        if outbound_apply_hidden(ob, st["hidden"], time.time()):
            outbound_state_save(ob)
            outbound_cache["data"] = None
    return {"ok": True, "hidden": len(st["hidden"]), "rows": len(picks),
            "groups": sorted({g["name"] for gs in groups_of.values() for g in gs})}


# ------------------------------------------------------------
# Companions: which sites load together
# ------------------------------------------------------------
def traffic_companions_of(base):
    """{other base domain: share of the times base was opened}."""
    lead = traffic_companions["leads"].get(base)
    if not lead or lead["n"] < TRAFFIC_COMPANION_MIN_OPENS:
        return {}
    opens = lead["n"]
    return {c: round(n / opens, 2) for c, n in list(lead["c"].items())   # a copy: the worker adds sites while pages read
            if n / opens >= TRAFFIC_COMPANION_MIN_SHARE}


def traffic_loaded_by(base):
    """{site: share} for the sites that usually load base."""
    return {lead: share for lead in list(traffic_companions["leads"])   # a copy: the worker adds sites while pages read
            for c, share in traffic_companions_of(lead).items() if c == base}


def traffic_companions_learn(now=None):
    """Read the records since the last run: per device, a site opened after
    10 s of quiet (an allowed flow, not background) and the other sites that
    start within 8 s of it. Background = destinations the device reached in
    8 or more of the last 24 hours."""
    now = now or time.time()
    since = max(traffic_companions.get("until") or 0, now - FLOW_HISTORY_HOURS * 3600)
    until = now - 60    # records arrive a few seconds late
    if until <= since:
        return
    with flow_history_reader() as connection:
        background = {(m, d) for m, d, _ in connection.execute(
            "SELECT device_mac, COALESCE(destination, remote_ip), COUNT(DISTINCT CAST(event_at / 3600 AS INTEGER)) AS h "
            "FROM flow_records WHERE event_at >= ? AND device_mac NOT LIKE 'IF:%' GROUP BY 1, 2 HAVING h >= 8", (now - 86400,))}
        rows = connection.execute(
            "SELECT device_mac, event_at, kind, COALESCE(destination, remote_ip) FROM flow_records "
            "WHERE event_at >= ? AND event_at < ? AND device_mac NOT LIKE 'IF:%' ORDER BY device_mac, event_at",
            (since - TRAFFIC_COMPANION_QUIET, until + TRAFFIC_COMPANION_WINDOW)).fetchall()
    decay = 0.5 ** ((now - (traffic_companions.get("at") or now)) / TRAFFIC_COMPANION_HALF_LIFE)
    leads = traffic_companions["leads"]
    for lead in leads.values():
        lead["n"] *= decay
        lead["c"] = {c: n * decay for c, n in lead["c"].items() if n * decay >= 0.5}
    device, last, opened = None, None, None
    for mac, at, kind, destination in rows:
        if (mac, destination) in background or not destination:
            continue
        if mac != device:
            device, last, opened = mac, None, None
        base = outbound_base(destination)
        quiet = last is None or at - last > TRAFFIC_COMPANION_QUIET
        if quiet and kind == "normal" and since <= at < until and not base.replace(".", "").isdigit():
            opened = {"base": base, "at": at, "with": set()}
            lead = leads.setdefault(base, {"n": 0.0, "c": {}})
            lead["n"] += 1
        elif opened and at - opened["at"] <= TRAFFIC_COMPANION_WINDOW and base != opened["base"] and base not in opened["with"]:
            opened["with"].add(base)
            c = leads[opened["base"]]["c"]
            c[base] = c.get(base, 0.0) + 1
        last = at
    for lead in leads.values():
        if len(lead["c"]) > 60:
            lead["c"] = dict(sorted(lead["c"].items(), key=lambda x: -x[1])[:60])
    if len(leads) > 3000:
        traffic_companions["leads"] = dict(sorted(leads.items(), key=lambda x: -x[1]["n"])[:3000])
    traffic_companions.update(until=until, at=now)
    traffic_companions.setdefault("first", now)
    temporary = TRAFFIC_COMPANIONS_FILE + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(traffic_companions, handle)
    os.replace(temporary, TRAFFIC_COMPANIONS_FILE)


def traffic_worker():
    try:
        saved = policy_read_json(TRAFFIC_COMPANIONS_FILE)
    except StateFileError:
        saved = None   # learned again from the traffic; the next save replaces the file
    if saved and isinstance(saved.get("leads"), dict):
        traffic_companions.update(saved)
    while True:
        time.sleep(600)
        try:
            traffic_companions_learn()
        except Exception as exc:
            print("Traffic companions error:", exc)


# ------------------------------------------------------------
# Domain popup
# ------------------------------------------------------------
@app.get("/api/domain/{name}")
def api_domain(name: str):
    name = str(name or "").strip().lower().rstrip(".")
    base = outbound_base(name)
    since = time.time() - 86400
    with flow_history_reader() as connection:
        total = connection.execute(f"SELECT {FLOW_METRICS_SQL}, MAX(country) FROM flow_records WHERE event_at >= ? "
                                   "AND (destination = ? OR remote_ip = ?)", (since, name, name)).fetchone()
        devices = connection.execute("SELECT device_mac, MAX(device), MAX(source_network), COALESCE(SUM(COALESCE(starts, count)), 0) AS n, "
                                     "SUM(CASE WHEN kind = 'blocked' THEN count ELSE 0 END) FROM flow_records "
                                     "WHERE event_at >= ? AND (destination = ? OR remote_ip = ?) GROUP BY device_mac ORDER BY n DESC LIMIT 6",
                                     (since, name, name)).fetchall()
        rules = connection.execute("SELECT policy_pid, COALESCE(SUM(COALESCE(starts, count)), 0) AS n FROM flow_records WHERE event_at >= ? "
                                   "AND (destination = ? OR remote_ip = ?) AND kind = 'blocked' AND policy_pid IS NOT NULL "
                                   "GROUP BY policy_pid ORDER BY n DESC LIMIT 4", (since, name, name)).fetchall()
        f = dest_flow_facts(connection, [name], " WHERE event_at >= ?", [since]).get(name) or {}
    c = dest_classify(name, f.get("ip"), f.get("category"), f.get("pid"))
    loads = sorted(traffic_companions_of(base).items(), key=lambda x: -x[1])[:15]
    loaded_by = sorted(traffic_loaded_by(base).items(), key=lambda x: -x[1])[:15]
    return {
        "name": name, "base": base, "owner": c["owner"], "what": c["what"], "how": c["how"], "network": c["network"],
        "claude_note": c["claude_note"], "claude_concern": c["claude_concern"],
        "lists": dest_lists_status(),
        "country": total[8] or "", "totals": flow_metrics(total[:8]),
        "devices": [{"mac": m, "name": traffic_device_name(m, d, n), "count": int(c or 0), "blocked": int(b or 0)}
                    for m, d, n, c, b in devices],
        "rules": [{"pid": p, "name": traffic_rule_name(p), "count": int(n or 0)} for p, n in rules],
        "loads": [{"site": c, "share": s} for c, s in loads], "loaded_by": [{"site": c, "share": s} for c, s in loaded_by],
        "opened": round(traffic_companions["leads"].get(base, {}).get("n", 0)),
        "learning_since": traffic_companions.get("first") or None,
    }


CLIENT_USAGE_WINDOWS = (1, 3, 6, 12, 24)


# ============================================================
# INTERNET PATTERNS PAGE (owner, 20 Nov 2026)
#
# What a group's devices reach on the internet (Allowed) and what is
# stopped (Blocked), over the kept daily totals, so its allow list can
# be worked out per group and per maker instead of Device Active Protect
# deciding it. A row is one destination with the devices that share it:
#   group   most of the group (at least 3 in 4 of its devices)
#   maker   most of one maker's devices in the group
#   set     two or more devices otherwise
#   device  one device
# By = what allowed or blocked it, from the rule the router credited:
#   dap       a Device Active Protect rule
#   admin     a rule of yours aimed at a device, group or site
#   none      no rule (allowed only: it went out because nothing stopped it)
#   firewalla list-based blocking and Firewalla's features (block lists,
#             Family Protect, Region Blocking, threat filtering)
# A connection the router recorded without its site's name takes the
# name that address had on other connections (named = "remembered").
# Period (owner, 20 Nov 2026): the traffic of the last 24 hours, 2 days,
# 1 or 2 weeks, 1 or 6 months or 1 year, or of your own start and end
# dates. Read from the hourly totals while they reach back that far (30
# days), else from the daily ones for the older days. Besides your groups
# the page can show All Devices and Devices In No Group (read only: a
# change is made for a group). A blocked row every device of which has
# reached the destination since its last block is "now allowed", and
# leaves 7 days after that last block.
#
# Marks (stage 2): a blocked row can be marked To Be Allowed, an allowed
# row To Be Blocked, either Keep (as it is: it moves to Kept). A group's
# To Be Allowed marks are one change, its To Be Blocked marks another;
# Show Me How gives each change's ways, what else each way changes, and
# its steps (the same step shapes as Show Me How's own, so the page draws
# them the same way):
#   allow  the group's own list ("<group> Sites", an allow rule on the
#          group) · one allow rule per domain · Device Active Protect off
#   block  the lines out of your list that allows them · the group's
#          blocked list ("<group> Blocked", a block rule on the group)
# Rules on a group are checked before a device's Device Active Protect
# rules; at the same level Allow beats Block.
#
# I'm Doing This (stage 3) keeps the ticked way with its steps as the
# group's change in progress; each step is watched (your rules from the
# router, your target lists from the MSP) and the change is Done once
# every step is seen: its marks go, and it is listed as done for 30 days.
# Its sites wait (no other change takes them) until then or until Not
# Doing This. The Planned Changes page lists every group's changes, with
# the same Show Me How (/api/internet-patterns/changes).
# Kept in /data/internet_patterns.json: {period: {kind, start, end}, marks: {group id:
# {"<view>|<destination>|<by>": {mark, at, and the row as it was}}},
# doing: {group id: {allow | block: {way, title, impact, steps, sites, at}}},
# done: [{group, name, kind, sites, title, at, done_at}], changed}.
# ============================================================

PATTERNS_FILE = os.environ.get("FIREWALLA_PATTERNS_FILE", "/data/internet_patterns.json")
PATTERNS_MOST = 0.75             # the share of a group (or of a maker's devices) that counts as all of it
PATTERNS_NOW_ALLOWED_SECONDS = 7 * 86400
PATTERNS_FIREWALLA_PURPOSES = ("family", "region_blocking", "advanced_threat_filtering", "firewall")
PATTERNS_PERIODS = {"24h": 86400, "2d": 2 * 86400, "1w": 7 * 86400, "2w": 14 * 86400, "1m": 30 * 86400, "6m": 182 * 86400, "1y": 366 * 86400}
PATTERNS_PSEUDO = {"all": "All Devices", "none": "Clients In No Group"}
PATTERNS_DONE_KEEP_SECONDS = 30 * 86400
patterns_lock = threading.RLock()   # (a mark is saved while the page's own build checks the changes in progress)


def patterns_by(rule, rules):
    """(by, pid, text) for a totals row's rule value ("rule:<pid>",
    "type:<how it was blocked>" or "")."""
    kind, _, value = str(rule or "").partition(":")
    if kind == "type":
        return "firewalla", None, f"Firewalla, no rule number ({value})"
    if kind != "rule" or not value:
        return "none", None, ""
    r = rules.get(value)
    if not r:
        return "admin", value, f"rule #{value} (since removed)"
    target = str(r.get("target") or "")
    if r.get("purpose") == "dap":
        # Its rules are each client's own learned list (dap_<id>): one plain
        # line for all of them, not their internal names (D-963).
        return "dap", None, "Device Active Protect: each client's learned list"
    elif (r.get("purpose") in PATTERNS_FIREWALLA_PURPOSES or r.get("type") == "country"
          or (r.get("type") == "category" and r.get("action") == "block")
          or target in OUTBOUND_THREAT_LISTS or target in OUTBOUND_NOISE_LISTS):
        by = "firewalla"
    else:
        by = "admin"
    return by, value, access_rule_text(r)


def patterns_state():
    st = policy_read_json(PATTERNS_FILE) or {}
    st.setdefault("period", {"kind": "1y"})
    st.setdefault("marks", {})
    st.setdefault("doing", {})
    st.setdefault("done", [])
    st.setdefault("changed", 0)
    return st


def patterns_seen(watch):
    """Has the dashboard seen this step done? (Show Me How's own kinds,
    plus a domain rule on a group and Device Active Protect off.)"""
    if not router_ready():   # just after a start (see howto_seen)
        return False
    kind = watch.get("kind")
    if kind == "rule" and watch.get("domain"):
        return any(r.get("disabled") is not True and r.get("action") == watch["action"] and r.get("type") == "dns"
                   and (r.get("applies_on") or {}).get("kind") == watch["on"][0] and str((r.get("applies_on") or {}).get("id")) == str(watch["on"][1])
                   and str(r.get("target") or "").lower().lstrip("*.") == str(watch["domain"]).lower()
                   for r in (state.get("policy_rules") or {}).get("rules") or [])
    if kind == "dap-off":
        return str((access_device_protect.get(str(watch.get("mac") or "").upper()) or {}).get("state") or "").lower() not in ("active", "optimizing")
    return howto_seen(watch)


def patterns_progress(st, now):
    """Each change in progress against the router and the MSP: steps seen;
    a change with every step seen is done (its marks go). True when the
    state changed."""
    changed = False
    for gid, kinds in list(st["doing"].items()):
        for kind, change in list(kinds.items()):
            seen = [patterns_seen(s.get("watch") or {}) for s in change.get("steps") or []]
            if seen != change.get("seen"):
                change["seen"] = seen
                changed = True
            if seen and all(seen):
                sites = set(change.get("sites") or [])
                marks = st["marks"].get(gid) or {}
                for key in [k for k, m in marks.items() if m.get("mark") == kind and m.get("dest") in sites]:
                    del marks[key]
                if not marks:
                    st["marks"].pop(gid, None)
                st["done"].append({"group": gid, "name": change.get("group_name") or gid, "kind": kind, "sites": sorted(sites),
                                   "title": change.get("title"), "at": change.get("at"), "done_at": now})
                del kinds[kind]
                changed = True
        if not kinds:
            del st["doing"][gid]
    kept = [d for d in st["done"] if now - (d.get("done_at") or 0) < PATTERNS_DONE_KEEP_SECONDS]
    if len(kept) != len(st["done"]):
        st["done"] = kept
        changed = True
    return changed


def patterns_refresh():
    """The state, with the changes in progress checked first."""
    with patterns_lock:
        st = patterns_state()
        if patterns_progress(st, time.time()):
            patterns_save(st)
    return st


def patterns_save(st):
    st["changed"] = time.time()
    temporary = PATTERNS_FILE + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(st, handle)
    os.replace(temporary, PATTERNS_FILE)


def patterns_window(st, now):
    """(start, end) of the period chosen: the last so long, or your dates."""
    period = st["period"]
    if period.get("kind") == "custom":
        return float(period.get("start") or 0), min(now, float(period.get("end") or now))
    return now - PATTERNS_PERIODS.get(period.get("kind"), PATTERNS_PERIODS["1y"]), now


def patterns_group(gid):
    """A group by its id, or one of the two made-up ones (all devices,
    devices in no group)."""
    groups = (state.get("groups") or {}).get("groups") or []
    if gid in PATTERNS_PSEUDO:
        grouped = {str(m).upper() for g in groups for m in g.get("members") or []}
        macs = sorted({str(d.get("mac") or "").upper() for d in state.get("devices") or []} - {""})
        return {"id": gid, "name": PATTERNS_PSEUDO[gid], "pseudo": True,
                "members": macs if gid == "all" else [m for m in macs if m not in grouped]}
    return next((g for g in groups if str(g["id"]) == str(gid)), None)


def patterns_ways(group, kind, items):
    """The ways to make one change (kind allow | block) for a group's
    marked rows: [{id, title, summary, impact: [tone, text], recommended,
    steps}], the way that changes least first."""
    gid, gname, size = str(group["id"]), group.get("name") or str(group["id"]), len(group.get("members") or [])
    on = f"FWG Pro (Router) + {gname}"
    lines = sorted({i["dest"] for i in items})
    n = len(lines)
    sites = f"{n} site{'s' if n != 1 else ''}"
    by_name = {str(l.get("name") or ""): (lid, l) for lid, l in (msp.get("lists") or {}).items()}
    rules = (state.get("policy_rules") or {}).get("rules") or []
    made = time.strftime("%d %b %Y")

    def list_way(action, lname, wid):
        lid, old = by_name.get(lname) or (None, None)
        steps = []
        if old:
            have = {str(t).strip().lower() for t in old.get("targets") or []}
            missing = [l for l in lines if l.lower() not in have]
            if missing:
                steps.append({"title": f"Add {len(missing)} line{'s' if len(missing) != 1 else ''} to your list \"{lname}\"",
                              "msp": {"path": ["Target Lists", lname], "fields": [["Targets", "add these lines", "\n".join(missing)]], "lines": missing},
                              "app": {"note": "Target lists can only be edited on the MSP website."}, "note": "Then Save & Apply.",
                              "picture": "msp-targetlist-edit.jpg", "undo": f"Remove those lines from \"{lname}\".",
                              "watch": {"kind": "list", "name": lname, "lines": missing}})
        else:
            steps.append({"title": "Create the target list", "msp": {"path": ["Target Lists", "Create Target List"], "fields": [
                ["List Name", lname, lname], ["Category", "Private", None],
                ["Targets", f"{n} line{'s' if n != 1 else ''}", "\n".join([f"#Made by the dashboard's Internet Patterns, {made}"] + lines)],
                ["Notes", "what it's for", None]], "lines": lines},
                "app": {"note": "Target lists can only be made on the MSP website."},
                "note": "Then Create.", "picture": "msp-targetlist-create.jpg", "undo": f"Delete the list \"{lname}\" (after its rule).",
                "watch": {"kind": "list", "name": lname, "lines": lines}})
        uses = lid and any(r.get("action") == action and r.get("disabled") is not True
                           and (r.get("applies_on") or {}).get("kind") == "group" and str((r.get("applies_on") or {}).get("id")) == gid
                           and str((r.get("matching") or {}).get("id")) == str(lid) for r in rules)
        if not uses:
            steps.append({"title": f"Create the rule On {gname}", "msp": {"path": ["Rules", "Create Rule"], "fields": [
                ["Name", lname, lname], ["Action", action.title(), None], ["Matching", f"Target List › {lname}", None],
                ["On", on, None], ["Direction", "Outbound only", None], ["Schedule", "Always", None]]},
                "app": howto_app("rule", name=lname, action=action, matching_path=f"Set a target › Target List › {lname}",
                                 matching_label="Target List", matching_value=lname, target=f"Target List {lname}", list=True,
                                 on_kind="group", on=gname, direction="outbound"),
                "note": "Then Create. Direction appears once Matching is set.", "picture": "msp-rule-create.jpg",
                "undo": f"Delete the rule \"{lname}\" On {gname}.",
                "watch": {"kind": "rule", "action": action, "on": ["group", gid], "list": lname}})
        return {"id": wid, "list": lname, "steps": steps, "exists": bool(old)}

    ways = []
    dap = [i for i in items if i.get("by") == "dap"]
    if kind == "allow":
        w = list_way("allow", howto_fit([gname], tail="Sites"), "list")
        ways.append({**w, "title": f"{'Add' if w['exists'] else 'Put'} {sites} {'to' if w['exists'] else 'in'} the group's own list \"{w['list']}\"",
                     "summary": "A target list of exactly these sites, allowed on the group"
                                + (". A group's rule is checked before a client's Device Active Protect rule, so they get through while it stays on" if dap else ""),
                     "impact": ["good", f"Changes nothing else: only {'this site' if n == 1 else 'these sites'}, only for this group's {size} client{'s' if size != 1 else ''}"],
                     "recommended": True})
        if not any(i.get("address") for i in items):
            bases = sorted({outbound_base(l) for l in lines})
            steps = []
            for base in bases:
                name = howto_fit([gname], tail=base)
                steps.append({"title": f"Create the rule for {base} On {gname}", "msp": {"path": ["Rules", "Create Rule"], "fields": [
                    ["Name", name, name], ["Action", "Allow", None], ["Matching", f"Domain › {base}", base],
                    ["On", on, None], ["Direction", "Outbound only", None], ["Schedule", "Always", None]]},
                    "app": howto_app("rule", name=name, action="allow", matching_path=f"Set a target › Domain › {base}",
                                     matching_label="Domain", matching_value=base, target=base,
                                     on_kind="group", on=gname, direction="outbound"),
                    "note": "Then Create. A domain rule covers the domain and everything under it.", "picture": "msp-rule-create.jpg",
                    "undo": f"Delete the rule \"{name}\" On {gname}.",
                    "watch": {"kind": "rule", "action": "allow", "on": ["group", gid], "domain": base}})
            ways.append({"id": "domain", "title": f"One allow rule per domain: {', '.join(bases[:3])}{' …' if len(bases) > 3 else ''}",
                         "summary": f"{len(bases)} domain rule{'s' if len(bases) != 1 else ''} on the group, no list to keep",
                         "impact": ["warn", f"Also allows every other site under {', '.join(bases[:3])}{' …' if len(bases) > 3 else ''} for the group's {size} client{'s' if size != 1 else ''}"],
                         "recommended": False, "steps": steps})
        if dap:
            mac_of = {d["name"]: d["mac"] for i in dap for d in i.get("devices") or []}
            devices = sorted(mac_of)
            ways.append({"id": "dap-off", "title": f"Turn Device Active Protect off on {len(devices)} client{'s' if len(devices) != 1 else ''}",
                         "summary": ", ".join(devices[:4]) + (f" and {len(devices) - 4} more" if len(devices) > 4 else ""),
                         "impact": ["bad", f"Lifts every limit Device Active Protect puts on {'that client' if len(devices) == 1 else 'those clients'}, not only {'this site' if n == 1 else 'these sites'}"],
                         "recommended": False,
                         "steps": [{"title": f"Turn Device Active Protect off on {name}",
                                    "msp": {"path": [], "fields": []},
                                    "app": {"path": ["Home", "Protect", "Device Active Protect", "Protected Devices", name],
                                            "fields": [["Button", "Turn Off DAP on This Device", None]]},
                                    "note": "In the Firewalla app only: Protect › Device Active Protect › Protected Devices › the client › Turn Off DAP on This Device.",
                                    "undo": f"Turn DAP on again on {name} (it learns again).", "watch": {"kind": "dap-off", "device": name, "mac": mac_of[name]}} for name in devices]})
        return ways
    # To Be Blocked.
    users = sorted({d["name"] for i in items for d in i.get("devices") or []})
    allowing = {}
    for i in items:
        for r in i.get("rules") or []:
            if i.get("by") == "admin" and r.get("pid"):
                allowing.setdefault(str(r["pid"]), set()).add(i["dest"])
    edits = []
    for pid, dests in sorted(allowing.items()):
        rule = next((r for r in rules if str(r.get("pid")) == pid), None)
        lid = str(((rule or {}).get("matching") or {}).get("id") or "")
        old = (msp.get("lists") or {}).get(lid)
        listed = [t for t in (old or {}).get("targets") or [] if str(t).split(",")[0].strip().lower() in {d.lower() for d in dests}]
        if listed:
            edits.append({"title": f"Take {len(listed)} line{'s' if len(listed) != 1 else ''} out of your list \"{old['name']}\"",
                          "msp": {"path": ["Target Lists", old["name"]], "fields": [["Targets", "remove these lines", "\n".join(listed)]], "lines": listed},
                          "app": {"note": "Target lists can only be edited on the MSP website."},
                          "note": f"Rule #{pid} allows through this list. Then Save & Apply.", "picture": "msp-targetlist-edit.jpg",
                          "undo": f"Add those lines to \"{old['name']}\" again.", "watch": {"kind": "list_without", "name": old["name"], "lines": listed}})
    if edits:
        ways.append({"id": "unlist", "title": f"Take {sites} out of the list that allows {'it' if n == 1 else 'them'}",
                     "summary": "Your allow rule stays; it stops covering " + ("this site" if n == 1 else "these sites"),
                     "impact": ["good", "Changes nothing else: what your other rules say then decides " + ("this site" if n == 1 else "these sites")],
                     "recommended": True, "steps": edits})
    w = list_way("block", howto_fit([gname], tail="Blocked"), "block-list")
    held = sorted(allowing)
    ways.append({**w, "title": f"{'Add' if w['exists'] else 'Put'} {sites} {'to' if w['exists'] else 'in'} the group's blocked list \"{w['list']}\"",
                 "summary": "A target list of exactly these sites, blocked on the group. A group's rule is checked before a client's Device Active Protect rule",
                 "impact": ["warn", f"Rule{'s' if len(held) != 1 else ''} {', '.join('#' + p for p in held)} allow{'s' if len(held) == 1 else ''} {'it' if n == 1 else 'them'} at the same level, and Allow beats Block: this only takes effect once {'that rule stops' if len(held) == 1 else 'those rules stop'} covering {'it' if n == 1 else 'them'}"]
                 if held else ["good" if len(users) >= size else "warn",
                               f"Blocks {'it' if n == 1 else 'them'} for {'the one client' if size == 1 else f'all {size} clients'} in the group"
                               + ("" if len(users) >= size else f"; {len(users)} use{'s' if len(users) == 1 else ''} {'it' if n == 1 else 'them'} today ({', '.join(users[:3])}{' …' if len(users) > 3 else ''})")],
                 "recommended": not edits})
    return ways


def patterns_plan(group, marks, doing):
    """A group's changes: [{kind, sites, ways}] from its marks, and
    [{kind, doing: the way being done with its steps and which are seen,
    sites}] for a change in progress (its sites wait: no other change
    takes them)."""
    plan = []
    for kind in ("allow", "block"):
        busy = doing.get(kind)
        held = set((busy or {}).get("sites") or [])
        if busy:
            steps = [{**s, "seen": seen} for s, seen in zip(busy.get("steps") or [], busy.get("seen") or [False] * len(busy.get("steps") or []))]
            plan.append({"kind": kind, "sites": [{"dest": d} for d in sorted(held)],
                         "doing": {"way": busy.get("way"), "title": busy.get("title"), "impact": busy.get("impact"), "at": busy.get("at"), "steps": steps,
                                   "seen": sum(1 for s in steps if s["seen"]), "of": len(steps)}})
        items = sorted((m for m in marks.values() if m.get("mark") == kind and m.get("dest") not in held), key=lambda m: m.get("dest") or "")
        if items:
            plan.append({"kind": kind, "sites": [{"dest": m["dest"], "by": m.get("by"), "devices": len(m.get("devices") or [])} for m in items],
                         "ways": patterns_ways(group, kind, items)})
    return plan


patterns_built = {}   # (group, view, period, state change) -> (at, page): a minute, as the page asks again every minute


def patterns_build(gid, view):
    """The page for one group and view. Kept for a minute while nothing was
    marked or changed: a build reads a year of daily totals (up to a second
    for All Devices)."""
    st = patterns_refresh()
    key = (gid, view, json.dumps(st["period"], sort_keys=True), st["changed"])
    kept = patterns_built.get(key)
    if kept and time.time() - kept[0] < 60:
        return kept[1]
    out = patterns_page(gid, view, st)
    for old in [k for k, (at, _) in list(patterns_built.items()) if time.time() - at >= 60]:
        patterns_built.pop(old, None)
    patterns_built[key] = (time.time(), out)
    return out


def patterns_page(gid, view, st):
    now = time.time()
    start, end = patterns_window(st, now)
    groups = (state.get("groups") or {}).get("groups") or []
    listed = [{"id": k, "name": name, "devices": len(patterns_group(k)["members"]), "pseudo": True} for k, name in PATTERNS_PSEUDO.items()] + sorted(
        ({"id": str(g["id"]), "name": g.get("name") or str(g["id"]), "devices": len(g.get("members") or [])}
         for g in groups if g.get("members")), key=lambda g: g["name"].lower())
    group = patterns_group(gid)
    out = {"ok": True, "updated_at": now, "period": {"kind": st["period"].get("kind") or "1y", "start": start, "end": end}, "groups": listed, "view": view,
           "group": None, "rows": [], "days": 0, "recorded_since": None}
    if not group or not group.get("members"):
        return out
    macs = [str(m).upper() for m in group.get("members") or []]
    vendors = {str(d.get("mac") or "").upper(): d for d in state.get("devices") or []}
    saved = details_load()["devices"]
    maker_of, name_of = {}, {}
    for mac in macs:
        name_of[mac] = recent_flow_device_name(mac, None)
        d = vendors.get(mac) or {}
        maker_of[mac] = connections_details(connections_guess(name_of[mac], d.get("vendor") or "", d.get("model")), saved.get(mac))["maker"] or ""
    out["group"] = {"id": str(group["id"]), "name": group.get("name"), "devices": len(macs), "pseudo": bool(group.get("pseudo"))}
    marked = {} if group.get("pseudo") else st["marks"].get(str(group["id"])) or {}
    doing = {} if group.get("pseudo") else st["doing"].get(str(group["id"])) or {}
    out["plan"] = patterns_plan(group, marked, doing)
    waiting = {(kind, d) for kind, c in doing.items() for d in c.get("sites") or []}
    # The hourly totals cover the whole period when it starts inside what
    # they keep; else the daily totals give the days before `split`.
    hourly_from = (int(now - INTERNET_TRAFFIC_HOURLY_SECONDS) // 3600 + 1) * 3600
    split = int(start // 3600 * 3600) if start >= hourly_from else internet_day(hourly_from + 86400)
    offset = internet_day(now) % 86400          # a day's number: its local midnight, counted in days
    marks = ",".join("?" * len(macs))
    part = """SELECT device_mac, destination, remote_ip, protocol, port, outcome, rule, COALESCE(starts, flows) AS flows,
                     CAST(({period} - ?) / 86400 AS INTEGER) AS day, first_ts, last_ts
              FROM {table} WHERE device_mac IN (""" + marks + """) AND direction = 'out' AND {period} >= ? AND {period} < ?"""
    flush_internet_traffic()
    with internet_traffic_connection() as connection:
        rows = connection.execute(f"""
            SELECT device_mac, destination, MAX(remote_ip), protocol, port, outcome, rule, SUM(flows), COUNT(DISTINCT day),
                   MIN(first_ts), MAX(last_ts), GROUP_CONCAT(DISTINCT day)
            FROM ({part.format(table="internet_traffic_daily", period="day")}
                  UNION ALL {part.format(table="internet_traffic_hourly", period="hour")})
            GROUP BY device_mac, destination, protocol, port, outcome, rule""",
            (offset, *macs, internet_day(start), min(split, end) if start < hourly_from else 0, offset, *macs, split, end)).fetchall()
        bare = sorted({r[1] for r in rows if dest_is_address(r[1])})
        remembered = {}
        # Asked for 10,000 addresses at a time: SQLite takes at most 32,766 values in one question.
        for part_start in range(0, len(bare), 10000):
            some = bare[part_start:part_start + 10000]
            for ip, name, _ in connection.execute(f"""
                    SELECT remote_ip, destination, SUM(COALESCE(starts, flows)) AS n FROM internet_traffic_daily
                    WHERE remote_ip IN ({','.join('?' * len(some))}) AND destination != remote_ip
                    GROUP BY remote_ip, destination ORDER BY n""", some):
                remembered[ip] = name   # the name it carried most often comes last
        first = connection.execute(f"SELECT MIN(day) FROM internet_traffic_daily WHERE device_mac IN ({marks})", macs).fetchone()[0]
    out["recorded_since"] = first
    rules = {str(r.get("pid")): r for r in (state.get("policy_rules") or {}).get("rules") or []}
    wanted = "allowed" if view == "allowed" else "blocked"
    found, allowed_last, days_seen = {}, {}, set()
    for mac, dest, ip, protocol, port, outcome, rule, flows, _, first_ts, last_ts, day_list in rows:
        named = remembered.get(dest) if dest_is_address(dest) else None
        dest_key = named or dest
        days = {int(d) for d in str(day_list or "").split(",") if d}
        days_seen |= days
        if outcome == "allowed":
            allowed_last[(mac, dest_key)] = max(allowed_last.get((mac, dest_key), 0), last_ts or 0)
        if outcome != wanted:
            continue
        by, pid, text = patterns_by(rule, rules)
        # One row per destination (owner, 23 Nov 2026, D-962), whatever let
        # it through or blocked it; each kind of rule is a part of the row.
        e = found.setdefault(dest_key, {"dest": dest_key, "ip": ip, "remembered": False, "ports": set(), "macs": {},
                                        "flows": 0, "days": set(), "first": first_ts, "last": last_ts, "rules": {}, "parts": {}})
        part = e["parts"].setdefault(by, {"macs": set(), "flows": 0})
        part["macs"].add(mac)
        part["flows"] += flows or 0
        e["remembered"] = e["remembered"] or bool(named)
        e["ports"].add(f"{str(protocol).upper()} {port}".strip())
        e["macs"][mac] = max(e["macs"].get(mac, 0), last_ts or 0)
        e["flows"] += flows or 0
        e["days"] |= days
        e["first"] = min(e["first"] or first_ts or 0, first_ts or 0) or e["first"]
        e["last"] = max(e["last"] or 0, last_ts or 0)
        if pid or text:
            e["rules"][pid or text] = text
    by_maker = {}
    for mac in macs:
        if maker_of[mac]:
            by_maker.setdefault(maker_of[mac], []).append(mac)
    result = []
    for e in found.values():
        parts = sorted(e["parts"].items(), key=lambda kv: -kv[1]["flows"])
        e["by"] = parts[0][0]
        on = sorted(e["macs"], key=lambda m: name_of[m].lower())
        makers = {maker_of[m] for m in on}
        maker = next(iter(makers)) if len(makers) == 1 else ""
        if len(macs) > 1 and len(on) >= PATTERNS_MOST * len(macs):
            level, of = "group", len(macs)
        elif maker and len(by_maker[maker]) > 1 and len(on) >= PATTERNS_MOST * len(by_maker[maker]):
            level, of = "maker", len(by_maker[maker])
        elif len(on) > 1:
            level, of = "set", None
        else:
            level, of = "device", None
        now_allowed = None
        if view == "blocked":
            since_block = [allowed_last.get((m, e["dest"]), 0) for m in on]
            if all(a > e["macs"][m] for a, m in zip(since_block, on)):
                if now - e["last"] > PATTERNS_NOW_ALLOWED_SECONDS:
                    continue
                now_allowed = min(since_block)
        who = dest_classify(e["dest"], e["ip"])
        result.append({
            "dest": e["dest"], "address": dest_is_address(e["dest"]), "remembered": e["remembered"], "ip": e["ip"],
            "owner": who.get("owner") or "", "what": who.get("what") or "", "ports": sorted(e["ports"]),
            "level": level, "maker": maker if level == "maker" else "", "of": of,
            "devices": [{"mac": m, "name": name_of[m]} for m in on],
            "missing": [name_of[m] for m in (macs if level == "group" else by_maker.get(maker, []) if level == "maker" else []) if m not in e["macs"]],
            "flows": e["flows"], "days": len(e["days"]), "first": e["first"], "last": e["last"], "by": e["by"],
            "by_parts": [{"by": b, "clients": len(x["macs"]), "flows": x["flows"]} for b, x in parts],
            "rules": [{"pid": pid if str(pid).isdigit() else None, "text": text} for pid, text in sorted(e["rules"].items(), key=lambda kv: str(kv[0]))],
            "now_allowed": now_allowed,
            "mark": next(((marked.get(f"{view}|{e['dest']}|{b}") or {}).get("mark") for b, _ in parts if marked.get(f"{view}|{e['dest']}|{b}")), None),
            "doing": ("allow" if view == "blocked" else "block", e["dest"]) in waiting})
    order = {"group": 0, "maker": 1, "set": 2, "device": 3}
    result.sort(key=lambda r: (order[r["level"]], r["maker"].lower(), -len(r["devices"]), -r["flows"]))
    out.update(rows=result, days=len(days_seen), makers={k: len(v) for k, v in sorted(by_maker.items())})
    return out


def dest_is_address(name):
    name = str(name or "")
    return name.replace(".", "").isdigit() or ":" in name


@app.get("/api/internet-patterns")
def api_internet_patterns(group: str = "", view: str = "allowed"):
    """The Internet Patterns page: group = a group's id (none: only the
    list of groups), view = allowed | blocked."""
    view = view if view in ("allowed", "blocked") else "allowed"
    try:
        return patterns_build(group[:40], view)
    except Exception as exc:
        return {"ok": False, "error": public_error("Internet patterns", exc)}


@app.get("/api/internet-patterns/changes")
def api_internet_patterns_changes():
    """Every group's changes (marked, or in progress with the steps seen so
    far) and those done in the last 30 days: for the Planned Changes page."""
    try:
        st = patterns_refresh()
        changes = []
        for gid in sorted(set(st["marks"]) | set(st["doing"])):
            group = patterns_group(gid)
            if not group or group.get("pseudo"):
                continue
            for c in patterns_plan(group, st["marks"].get(gid) or {}, st["doing"].get(gid) or {}):
                marks = [m for m in (st["marks"].get(gid) or {}).values() if m.get("mark") == c["kind"]]
                changes.append({**c, "group": {"id": gid, "name": group.get("name") or gid},
                                "at": (c.get("doing") or {}).get("at") or min((m.get("at") or 0 for m in marks), default=None)})
        return {"ok": True, "changes": changes, "done": sorted(st["done"], key=lambda d: -(d.get("done_at") or 0))}
    except Exception as exc:
        return {"ok": False, "error": public_error("Internet patterns changes", exc), "changes": [], "done": []}


@app.post("/api/internet-patterns/doing")
def api_internet_patterns_doing(payload: dict = Body(default={})):
    """I'm Doing This: group, kind (allow | block), way = the ticked way's
    id; way "" = Not Doing This (the marks stay)."""
    fields = Fields(payload)
    gid, kind, way = fields.text("group", 40), fields.choice("kind", ("allow", "block")), fields.text("way", 40)
    group = patterns_group(gid) if gid else None
    if not group or group.get("pseudo") or not kind:
        return {"ok": False, "error": "The group and its change are needed"}
    with patterns_lock:
        st = patterns_state()
        kinds = st["doing"].setdefault(gid, {})
        if not way:
            kinds.pop(kind, None)
        elif kind in kinds:
            return {"ok": False, "error": "That change is already in progress: Not Doing This first, to pick another way"}
        else:
            change = next((c for c in patterns_plan(group, st["marks"].get(gid) or {}, kinds) if c["kind"] == kind and c.get("ways")), None)
            picked = next((w for w in (change or {}).get("ways") or [] if w["id"] == way), None)
            if not picked:
                return {"ok": False, "error": "That way isn't offered any more"}
            if not picked["steps"]:
                return {"ok": False, "error": "There is nothing to do: your rules already do this"}
            kinds[kind] = {"way": way, "title": picked["title"], "impact": picked["impact"], "steps": picked["steps"],
                           "sites": [s["dest"] for s in change["sites"]], "at": time.time(), "group_name": group.get("name") or gid}
        if not kinds:
            st["doing"].pop(gid, None)
        patterns_progress(st, time.time())
        patterns_save(st)
    return {"ok": True}


@app.post("/api/internet-patterns/period")
def api_internet_patterns_period(payload: dict = Body(default={})):
    """The period shown: kind = 24h | 2d | 1w | 2w | 1m | 6m | 1y, or
    custom with start and end (seconds; the end may be up to a day ahead,
    for a period that ends today). Nothing is deleted."""
    kind = Fields(payload).choice("kind", (*PATTERNS_PERIODS, "custom"))
    if not kind:
        return {"ok": False, "error": "Pick a period"}
    period = {"kind": kind}
    if kind == "custom":
        try:
            start, end = float(payload.get("start")), float(payload.get("end"))
        except (TypeError, ValueError):
            return {"ok": False, "error": "A start and an end date are needed"}
        if not 0 < start < end <= time.time() + 86400:   # (also refuses "NaN" and infinity)
            return {"ok": False, "error": "The start must be before the end, and the end no later than today"}
        period.update(start=start, end=end)
    with patterns_lock:
        st = patterns_state()
        st["period"] = period
        patterns_save(st)
    return {"ok": True, "period": period}


@app.post("/api/internet-patterns/mark")
def api_internet_patterns_mark(payload: dict = Body(default={})):
    """Mark a row: group, view (allowed | blocked), dest, by, mark = allow
    (a blocked row: To Be Allowed) | block (an allowed row: To Be Blocked)
    | keep | none (takes the mark off)."""
    fields = Fields(payload)
    gid, dest = fields.text("group", 40), fields.text("dest", 255)
    view, by = fields.choice("view", ("allowed", "blocked")), fields.choice("by", ("dap", "admin", "none", "firewalla"))
    mark = fields.choice("mark", ("allow", "block", "keep", "none"))
    if not (gid and dest and view and by and mark):
        return {"ok": False, "error": "The row and its mark are needed"}
    if (mark == "allow" and view != "blocked") or (mark == "block" and view != "allowed"):
        return {"ok": False, "error": "Only a blocked row can be marked To Be Allowed, and only an allowed row To Be Blocked"}
    if gid in PATTERNS_PSEUDO:
        return {"ok": False, "error": "A change is made for one of your groups: pick the group first"}
    key = f"{view}|{dest}|{by}"
    # The row is looked up before the lock (building the page is the slow
    # part, and it may save progress of its own); the state is read after.
    row = None if mark == "none" else next((r for r in patterns_build(gid, view)["rows"] if r["dest"] == dest and r["by"] == by), None)
    with patterns_lock:
        st = patterns_state()
        marks = st["marks"].setdefault(gid, {})
        waiting = {d for c in (st["doing"].get(gid) or {}).values() for d in c.get("sites") or []}
        if dest in waiting and (marks.get(key) or {}).get("mark") in ("allow", "block"):
            return {"ok": False, "error": "This site is part of a change in progress: Not Doing This first"}
        if mark == "none":   # any of the row's parts (one row per destination, D-962)
            for k in [k for k in marks if k.startswith(f"{view}|{dest}|")]:
                marks.pop(k, None)
        else:
            if not row:
                return {"ok": False, "error": "That row isn't on the page any more"}
            marks[key] = {"mark": mark, "at": time.time(), "view": view,
                          **{k: row[k] for k in ("dest", "by", "address", "ip", "ports", "devices", "rules", "level")}}
        if not marks:
            st["marks"].pop(gid, None)
        patterns_save(st)
    return {"ok": True}


@app.get("/api/internet-history")
def api_internet_history(mac: str = "", days: int = 30):
    """One device's internet destinations over the last days (1 to 366),
    from the kept hourly (today) and daily totals: a row per destination,
    port, direction, outcome and rule, with the days it was seen on.
    Read only (for working out what a maker's devices need to reach)."""
    mac = mac.strip().upper()
    if not re.fullmatch(r"[0-9A-F]{2}(:[0-9A-F]{2}){5}", mac):
        return {"ok": False, "error": "A client's MAC address is needed"}
    days = max(1, min(366, days))
    now = time.time()
    today = internet_day(now)
    try:
        flush_internet_traffic()
        with internet_traffic_connection() as connection:
            rows = connection.execute("""
                SELECT destination, MAX(remote_ip), MAX(country), protocol, port, direction, outcome, rule,
                       SUM(flows), SUM(bytes_up), SUM(bytes_down), COUNT(DISTINCT day), MIN(first_ts), MAX(last_ts)
                FROM (SELECT destination, remote_ip, country, protocol, port, direction, outcome, rule, COALESCE(starts, flows) AS flows, bytes_up, bytes_down,
                             day, first_ts, last_ts FROM internet_traffic_daily WHERE device_mac = ? AND day >= ? AND day < ?
                      UNION ALL
                      SELECT destination, remote_ip, country, protocol, port, direction, outcome, rule, COALESCE(starts, flows) AS flows, bytes_up, bytes_down,
                             ? AS day, first_ts, last_ts FROM internet_traffic_hourly WHERE device_mac = ? AND hour >= ?)
                GROUP BY destination, protocol, port, direction, outcome, rule""",
                (mac, internet_day(now - days * 86400), today, today, mac, today)).fetchall()
            first = connection.execute("SELECT MIN(day) FROM internet_traffic_daily WHERE device_mac = ?", (mac,)).fetchone()[0]
    except Exception as exc:
        return {"ok": False, "error": public_error("Internet history", exc)}
    keys = ("destination", "ip", "country", "protocol", "port", "direction", "outcome", "rule",
            "flows", "bytes_up", "bytes_down", "days", "first", "last")
    return {"ok": True, "mac": mac, "days": days, "recorded_since": first, "rows": [dict(zip(keys, r)) for r in rows]}


@app.get("/api/client-usage")
def api_client_usage(hours: int = 3):
    """Data used per client (internet, from the 24-hour flow history) over
    the last 1, 3, 6, 12 or 24 hours: download, upload, flows, and the
    busiest clock hour inside the window (its average rate = that hour's
    bytes x 8 / 3,600 s). Also each device's reserved addresses (the
    Clients page's Reserved column)."""
    if hours not in CLIENT_USAGE_WINDOWS:
        hours = 3
    reserved = {mac: ips for mac in (feature_settings.get("devices") or {}) if (ips := howto_reserved(mac))}
    # Device Isolation on the device itself, and who switched it on (owner,
    # 22 Nov 2026): "dap" = Device Active Protect, "you" = set in the app.
    isolation = {mac: "dap" if d.get("isolated_by_dap") else "you"
                 for mac, d in (feature_settings.get("devices") or {}).items() if d.get("isolated") or d.get("vqlan")}
    return {**shared_result(("client-usage", hours), lambda: client_usage(hours)), "reserved": reserved, "isolation": isolation}


def client_usage(hours):
    now = time.time()
    start = now - hours * 3600
    try:
        with flow_history_reader() as connection:
            rows = connection.execute("""
                SELECT COALESCE(device, device_ip, device_mac, '--') AS client, MAX(device_mac),
                       CAST(event_at / 3600 AS INTEGER) AS hour,
                       COALESCE(SUM(download_bytes), 0), COALESCE(SUM(upload_bytes), 0), COALESCE(SUM(COALESCE(starts, count)), 0)
                FROM flow_records WHERE event_at >= ? AND kind = 'normal'
                GROUP BY client, hour""", (start,)).fetchall()
    except Exception as exc:
        return {"healthy": False, "error": public_error("Client usage", exc), "clients": []}
    clients = {}
    for client, mac, hour, down, up, flows in rows:
        c = clients.setdefault(client, {
            "client": client, "mac": None, "download_bytes": 0, "upload_bytes": 0, "flows": 0,
            "busiest_hour_at": None, "busiest_hour_bytes": 0,
            "busiest_hour_download_bytes": 0, "busiest_hour_upload_bytes": 0,
        })
        if mac and not str(mac).startswith("IF:"):
            c["mac"] = mac
        c["download_bytes"] += int(down)
        c["upload_bytes"] += int(up)
        c["flows"] += int(flows)
        if int(down) + int(up) > c["busiest_hour_bytes"]:
            c["busiest_hour_bytes"] = int(down) + int(up)
            c["busiest_hour_download_bytes"] = int(down)
            c["busiest_hour_upload_bytes"] = int(up)
            c["busiest_hour_at"] = int(hour) * 3600
    ranked = sorted((c for c in clients.values() if c["download_bytes"] + c["upload_bytes"] > 0),
                    key=lambda c: -(c["download_bytes"] + c["upload_bytes"]))[:50]
    for c in ranked:
        c["busiest_hour_mbps"] = round(c["busiest_hour_bytes"] * 8 / 3600 / 1_000_000, 3)
        c["busiest_hour_download_mbps"] = round(c["busiest_hour_download_bytes"] * 8 / 3600 / 1_000_000, 3)
        c["busiest_hour_upload_mbps"] = round(c["busiest_hour_upload_bytes"] * 8 / 3600 / 1_000_000, 3)
    return {"healthy": True, "hours": hours, "start": start, "end": now, "clients": ranked}
