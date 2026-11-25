# Policy page: what you want, what your rules say, what happened.

import json
import os
import re
import threading
import time
import traceback
from collections import Counter
from fastapi import Body

from core import (
    CLAUDE_STATE_FILE, Fields, app, claude_load, claude_lock, claude_public, policy_read_json,
    state,
)
from router import (
    feature_settings, internet_interface_name, policy_rule_for_pid,
)
from flows import (
    LOCAL_TRAFFIC_RETENTION_SECONDS, flow_history_reader, flush_local_traffic, internet_day,
    local_traffic_connection, recent_flow_device_name,
)
from access import (
    ACCESS_HA_PAIRS, ACCESS_SUMMARY_BYTES, HOWTO_FILE, HOWTO_STEP_KEYS, access_address_rules, access_also_on, access_covers, access_is_gear, access_isolated, access_local_rules,
    access_peer_sides, access_rule_text, access_sides, check_local_access, howto_app, howto_done_facts, howto_load,
    howto_lock, howto_mark_done, howto_seen, msp_changes_check, open_unused_track,
)
from status import (
    missing_periods,
)


# ============================================================
# POLICY PAGE: what you want, what your rules say, what happened
#
# Three things are compared for every connection between your own
# devices (the starter's group -> the answerer's group, protocol and port;
# random high ports count as one, same-network traffic has no port):
#   intent   your decision on the Policy page: allow or block
#   rules    what your Firewalla rules and group settings say, worked out
#            per device pair by the client access model
#   reality  what the router did (allowed or blocked flows, last 7 days)
# The page's flow (owner, 19 Nov 2026; it replaced To Triage / Review /
# Awaiting Change and the Who Talks to Whom map). An item keeps its identity
# (its Claude conversation and what you had open) through every move:
# 1 New Connections: items = a pattern group of connections, or one
#   connection, or a device reaching a blocked country through your own
#   allow rule. Allow / Block per row, or Allow All / Block All, decides
#   those rows at once (D-1066): a row matching your rules is Decided, the
#   rest go to the pair's Review item (st["flow"]); Undo for a minute.
# 2 Review: Return (rows back to New Connections with their choices), Show
#   Me How (split first when the rows need different sets of Firewalla
#   changes), I'm Doing This -> 3 Pending Action.
# 3 Pending Action: waiting to see the change in your rules; once your
#   rules do what you chose -> Pending Confirmation.
# 4 Pending Confirmation: watched (24 h AND 10 connections; rarer traffic
#   up to 7 days). Clean -> Decided by itself; any traffic the opposite way
#   -> NOT WORKING, and once your rules are back as before -> Review again,
#   with what was tried (never offered as Recommended again).
# 5 Violations: the router did the opposite of what your rules say (true
#   contradictions only; the router's tiny summary records after blocked
#   tries count as blocked tries). Keep My Rule (back only if it happens
#   again), Make My Rule Work / Change My Rule (-> Review).
# Decided (its own page): never reopened; each keeps its details.
# Removed (Delete, a rule change contradicting a decision): only traffic
# after the removal brings a connection back, as new. Kept in
# /data/policy_state.json.
# ============================================================

POLICY_STATE_FILE = os.environ.get("FIREWALLA_POLICY_STATE_FILE", "/data/policy_state.json")
POLICY_BUILD_SECONDS = 60
POLICY_KEEP_SECONDS = 90
POLICY_INTERNET_SECONDS = 300
POLICY_QUIET_SECONDS = 24 * 3600
# New Connections keeps a connection this long after its last traffic (15 Nov 2026).
POLICY_TRIAGE_SECONDS = 7 * 86400
# A connection in New Connections that matches your rules is settled by default after
# this long untouched (on the rules alone since 18 Nov 2026).
POLICY_SETTLE_SECONDS = 7 * 86400
POLICY_SETTLED_LOG_SECONDS = 30 * 86400
# A rule change must contradict a decision this long before the decision
# is removed (so a moment of missing rule or group data removes nothing).
POLICY_CONTRADICT_SECONDS = 300
# Pending Confirmation's watch (owner, 19 Nov 2026): at least 24 hours AND
# at least 10 connections; rarer traffic is watched up to 7 days.
POLICY_WATCH_SECONDS = 86400
POLICY_WATCH_CONNECTIONS = 10
POLICY_WATCH_MAX_SECONDS = 7 * 86400
# The router's summary record after a burst of blocked tries: one tiny
# "allowed" record. Allowed tries this small (ACCESS_SUMMARY_BYTES each), on
# a pair with blocked tries, count as blocked tries, never as a violation
# (owner, 19 Nov 2026); Groups and Show Me How count them the same way.
POLICY_MESSAGE_SECONDS = 86400  # the page's notes ("... moved to Decided")
policy_lock = threading.RLock()   # held while building and while a choice is saved
policy_cache = {"at": 0, "data": None}
policy_internet = {"at": 0, "items": [], "explained": [], "explained_rows": [], "countries": 0, "error": None}

# What a well-known port is usually for, in words.
LOCAL_PORT_SERVICES = {
    "tcp 22": "SSH (remote login)", "tcp 53": "DNS", "udp 53": "DNS", "tcp 80": "Web page (HTTP)",
    "tcp 443": "Web page (HTTPS)", "tcp 445": "Windows file sharing (SMB)", "tcp 548": "Mac file sharing (AFP)",
    "tcp 554": "Camera video (RTSP)", "tcp 873": "Synology backup (rsync)", "udp 1900": "Device discovery (SSDP)",
    "tcp 2020": "Camera control (ONVIF)", "tcp 3389": "Remote Desktop", "tcp 5000": "Synology DSM",
    "tcp 5001": "Synology DSM (HTTPS)", "udp 5353": "Device discovery (mDNS)", "tcp 6690": "Synology Drive",
    "tcp 8009": "Casting (Chromecast)", "tcp 8883": "Smart-device messages (MQTT)", "tcp 9100": "Printing",
    "tcp 631": "Printing (IPP)", "tcp 9999": "TP-Link Kasa control", "tcp 32400": "Plex media server",
    "tcp 55443": "Amazon Echo multi-room", "tcp 7000": "AirPlay", "tcp 7100": "AirPlay",
    "udp 137": "Windows name lookup (NetBIOS)", "udp 138": "Windows network browsing (NetBIOS)",
    "tcp 139": "Windows file sharing, old style (NetBIOS)", "tcp 7680": "Windows Update sharing between PCs",
    "tcp 7575": "Watching recorded security video on the NAS (phone app)",
    "udp 8610": "Canon printer and scanner search", "udp 8612": "Canon printer and scanner search",
}


# Why Might This Be Blocked / Get Through / Be Needed? (owner, 18 Nov 2026):
# at most three short lines on a card or a group (tags Known, Possible, Ruled
# Out), worked out from what the dashboard already has: what your rules say,
# what the router named, what else is on for the devices, the tries and how
# they spread. Every line, with how to check it, is under More. Claude gets
# the same. "Needed" is for traffic the router blocks as your rules say: what
# it is for, and what stops working without it.
LOCAL_PORT_NEEDED = {
    "udp 8610": "finding the Canon printer or scanner from this client (printer setup, scan to PC)",
    "udp 8612": "finding the Canon printer or scanner from this client",
    "tcp 9100": "printing to it", "tcp 631": "printing to it (IPP)", "tcp 445": "opening its shared folders",
    "tcp 139": "opening its shared folders (old style)", "udp 137": "finding PCs by name (old Windows networking)",
    "udp 138": "Windows network browsing", "tcp 7680": "sharing Windows updates between PCs (saves internet use; not required)",
    "tcp 8009": "casting to it", "udp 1900": "apps finding it on the network (discovery)",
    "udp 5353": "apps finding it on the network (discovery)", "tcp 554": "watching or recording its video",
    "tcp 2020": "setting up or controlling the camera", "tcp 9999": "controlling the Kasa client (app or Alexa)",
    "tcp 3389": "remote desktop to it", "tcp 5000": "opening the NAS's admin page", "tcp 5001": "opening the NAS's admin page",
    "tcp 6690": "Synology Drive sync", "tcp 7575": "watching recorded video in the phone app",
    "tcp 873": "Synology backup", "tcp 55443": "Echo multi-room music", "tcp 7000": "AirPlay", "tcp 7100": "AirPlay",
    "tcp 32400": "Plex", "tcp 8883": "smart-device messages", "tcp 22": "logging in to it (SSH)",
    "tcp 80": "its web page", "tcp 443": "its web page",
}


def policy_why(cards):
    """{"title", "lines": [{tag, text, check}]} for one card or a group of
    look-alike cards, or None when there's nothing to explain."""
    if not cards:
        return None
    first = cards[0]
    allowed = sum(c.get("allowed_flows") or 0 for c in cards)
    blocked = sum(c.get("blocked_flows") or 0 for c in cards)
    total = allowed + blocked
    if not total:
        return None
    rules = policy_summary([c.get("rules") or "unclear" for c in cards])
    one = len(cards) == 1
    targets = {c["dst"]["mac"] for c in cards}
    tname = first["dst"]["name"] if len(targets) == 1 else f"the {len(targets)} targets"
    pct = lambda n: f"{round(100 * n / total)}%"
    lines = []
    also = [(c[side]["name"], x) for c in cards for side in ("src", "dst") for x in ((c.get("also_on") or {}).get(side) or {}).get("local") or []]
    seen, uniq = set(), []
    for name, x in also:
        if (name, x["what"]) not in seen:
            seen.add((name, x["what"]))
            uniq.append((name, x))
    if rules == "allowed" and blocked:
        title = "Why Might This Be Blocked?"
        deciding = first.get("deciding") or "your rules"
        named = sorted({x for c in cards for x in c.get("blocked_by") or [] if x and "not named" not in x})
        lines.append({"tag": "Known", "text": f"{deciding} allows it, yet the router blocked {pct(blocked)} of {total} tries"
                      + ("" if named else "; the router names nothing for it"),
                      "check": "The router's records say what blocked a try when it knows; here they don't." if not named else ""})
        if named:
            lines.append({"tag": "Known", "text": "The router says: " + "; ".join(named[:3]), "check": "Open it on Rules or Groups to see what it does."})
        for name, x in uniq:
            if x["effect"] == "can block":
                lines.append({"tag": "Possible", "text": f"{name}: {x['what']}", "check": f"Turn it off on {name} for a while and see whether the blocks stop."})
        if len(cards) > 1:
            shares = [(c.get("blocked_flows") or 0) / max(1, (c.get("allowed_flows") or 0) + (c.get("blocked_flows") or 0)) for c in cards]
            lo, hi = min(shares), max(shares)
            if len(targets) == 1 and hi - lo <= .15 and lo > 0:
                lines.append({"tag": "Possible", "text": f"Something on {tname}'s side: all {len(cards)} lose {round(100 * lo)}–{round(100 * hi)}%",
                              "check": f"Every client loses about the same share, which points at {tname} (busy, asleep, or a setting on it), not at one starter."})
            else:
                full = sum(1 for s in shares if s >= .99)
                if full:
                    lines.append({"tag": "Possible", "text": f"{full} of {len(cards)} cards lose every try: look at those first",
                                  "check": "A card that loses everything usually has its own cause (an address change, a setting on that client)."})
        elif blocked < total:
            lines.append({"tag": "Possible", "text": f"Something on {tname}'s side refuses some tries (busy, asleep, or its own limits)",
                          "check": f"Use it and see whether it fails at times."})
        for name, x in uniq:
            if x["effect"] == "internet only":
                lines.append({"tag": "Ruled Out", "text": f"{name}: {x['what']}", "check": "Its local part is what would block traffic between your own clients."})
    elif rules == "blocked" and allowed:
        title = "Why Might This Get Through?"
        deciding = first.get("deciding") or "your rules"
        lines.append({"tag": "Known", "text": f"{deciding} blocks it, yet the router let {pct(allowed)} of {total} tries through", "check": ""})
        if allowed < blocked:   # mostly blocked, a few "allowed": the summary record fits
            lines.append({"tag": "Possible", "text": "The router's summary line: after a burst of blocked tries it logs one small \"allowed\" record",
                          "check": "Such records stay tiny and come a minute or two after the blocks; real traffic grows."})
        for name, x in uniq:
            if x["effect"] == "lifts blocks":
                lines.append({"tag": "Possible", "text": f"{name}: {x['what']} (nothing is enforced for it)", "check": "Turn it back on in the Firewalla app."})
        named = sorted({x for c in cards for x in c.get("allowed_by") or [] if x})
        if named:
            lines.append({"tag": "Known", "text": "The router says allowed by: " + "; ".join(named[:3]), "check": "That rule wins over the block: see Rules."})
        for name, x in uniq:
            if x["effect"] == "internet only":
                lines.append({"tag": "Ruled Out", "text": f"{name}: {x['what']}", "check": ""})
    elif not allowed:
        title = "Why Might This Be Needed?"
        port = first.get("port_key")
        need = LOCAL_PORT_NEEDED.get(port) if all(c.get("port_key") == port for c in cards) else None
        what = first.get("what") or ""
        lines.append({"tag": "Known", "text": what if one else f"{len({c['src']['mac'] for c in cards})} clients → {tname} · {what}",
                      "check": "From the port and the clients' makers: the router doesn't see inside the traffic."})
        if need:
            lines.append({"tag": "Possible", "text": f"Blocked, it stops {need}", "check": "If that works for you now, it isn't needed here."})
        elif str(port or "").endswith(" high"):
            lines.append({"tag": "Possible", "text": "An app trying a direct connection; most fall back to their cloud relay when it is blocked",
                          "check": "If the app works anyway, nothing is lost."})
    else:
        return None
    return {"title": title, "lines": lines[:8]}


def local_port_label(protocol, port):
    """('udp', '57047') -> ('udp high', 'UDP random ports'); no port -> same network."""
    protocol = str(protocol or "").lower()
    if not port:
        return "same", "same network"
    if port.isdigit() and int(port) >= 32768:
        return f"{protocol} high", f"{protocol.upper()} random ports"
    return f"{protocol} {port}", f"{protocol.upper()} {port}"


def policy_state_load():
    """{since, decisions, items, removed, verdicts, settled}. since: traffic before
    it is not looked at (a new or reset file starts now). decisions: per
    connection, {intent, status decided | review | rule_change, kind keep |
    chose | false_alarm, ...}. items: open violations, {status review |
    rule_change, snapshot}. removed: connection or item key -> when it was
    removed; only traffic after that brings it back, as new. verdicts:
    "src|dst|port" -> [what the rules say, when that last changed].
    settled: [{at, label}] of cards
    settled by default, 30 days (for the digest). pattern_out: pattern id ->
    the connection keys you took out of that pattern (Take Out).
    row_picks: the choice a row returned from Review brings back, shown on
    its Allow / Block (connection key -> allow | block). flow: the items past New Connections, id -> {stage
    review | action | confirm, kind, keys, refs (the Claude refs it
    carries), tried, watch, ...}; each of its connections has a decision
    with "flow" = that id. nc_refs: connection key -> the Claude refs a
    returned row brings back to New Connections. messages: [{at, text}]."""
    state_ = policy_read_json(POLICY_STATE_FILE)
    fresh = not state_ or "since" not in state_
    if fresh:
        state_ = {"since": time.time()}
    for key in ("decisions", "items", "removed", "verdicts", "pattern_out", "row_picks", "flow", "nc_refs"):
        state_.setdefault(key, {})
    state_.setdefault("settled", [])
    state_.setdefault("messages", [])
    if fresh:
        policy_state_save(state_)
    return state_


def policy_state_save(st):
    temporary = POLICY_STATE_FILE + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(st, handle, indent=1)
    os.replace(temporary, POLICY_STATE_FILE)


# STOP MONITORING (owner, 23 Nov 2026, D-919): for a time you can't keep up
# with Policy, so nothing piles up. While stopped: no new New Connections
# cards, no new Violations, no nightly review, and no Policy alerts (digest,
# Needs You, menu *). Cards already listed stay, Pending Confirmation keeps
# watching, traffic is still recorded. On resume the stopped time is
# skipped: a connection seen only then never gets a card; one that carries
# on after the resume gets one. Stays stopped until you turn it back on.
# st["monitor"]: {stopped: when or None, pauses: [[start, end]], listed:
# the New Connections keys on the page when it was stopped}.
POLICY_PAUSES_KEPT = 20


def policy_monitor(st):
    return st.setdefault("monitor", {"stopped": None, "pauses": [], "listed": []})


def policy_paused_only(st, key, first, last):
    """True when a connection's traffic began inside a stopped time and
    nothing came after that time ended (or it hasn't ended): no card. One
    listed when monitoring was stopped keeps its card."""
    m = st.get("monitor") or {}
    if not first or key in (m.get("listed") or ()):
        return False
    if m.get("stopped") and first >= m["stopped"]:
        return True
    return any(s <= first < e and (last or 0) < e for s, e in m.get("pauses") or [])


def policy_peer_names(node, names):
    """Titles, labels and messages kept from before a VPN peer had its name
    (21 Nov 2026: "NAS -> AWG_PEER:<KEY>") get the name. Only words for
    people are changed; keys and refs keep the peer's key. True when
    anything changed."""
    changed = False
    for field, value in (node.items() if isinstance(node, dict) else enumerate(node)):
        if isinstance(value, (dict, list)):
            changed = policy_peer_names(value, names) or changed
        elif isinstance(value, str) and field in ("title", "label", "text", "name") and "_PEER:" in value:
            new = value
            for key, name in names.items():
                new = new.replace(key, name)
            if new != value:
                node[field], changed = new, True
    return changed


def policy_side_of(sides, groups, mac, recorded_groups, intf):
    """A device's place on the map: its Firewalla group (current membership
    first, then the groups recorded with the flow), else its network."""
    side = sides.get(mac) or {}
    ids = side.get("groups") or json.loads(recorded_groups or "[]")
    name = side.get("name") or recent_flow_device_name(mac if ":" in mac else "", mac)
    gid = next((str(g) for g in ids if str(g) in groups), None)
    if gid:
        return {"id": "g" + gid, "name": groups[gid].get("name") or gid}, name
    network = side.get("network") or intf or ""
    label = internet_interface_name(network) if network else "No network"
    return {"id": "n" + (network or "none"), "name": f"{label} (no group)"}, name


def policy_summary(verdicts):
    """Pair verdicts -> what the rules say for the whole: allowed, blocked,
    partly (some pairs each way) or unclear (any pair's rules conflict, or
    a device the dashboard doesn't know)."""
    kinds = set(verdicts)
    if not kinds or kinds & {"unclear", "unknown"}:
        return "unclear"
    return kinds.pop() if len(kinds) == 1 else "partly"


def policy_verdict(result):
    if not result:
        return "unknown"
    return "unclear" if result["uncertain"] else result["verdict"]


def policy_blocked_text(value, groups):
    """A recorded blocked_by -> words: 'rule:123' or 'ap:50'."""
    kind, _, ref = str(value or "").partition(":")
    if kind == "rule":
        rule = policy_rule_for_pid(ref)
        return f"#{ref} {access_rule_text(rule)}" if rule else f"rule #{ref}"
    if kind == "ap" and ref:
        g = groups.get(ref) or {}
        name = g.get("name") or f"group {ref}"
        what = " / ".join(x for x, on in (("VqLAN", g.get("vqlan")), ("Isolation", g.get("isolation"))) if on) or "isolation"
        return f"{what} on {name}"
    return value or "not named by the router"


def policy_maker(devices, mac):
    device = devices.get(mac) or {}
    return device.get("vendor") or device.get("model") or ""


def policy_what(c):
    """What a connection is for, in plain words: the port's usual use, else
    what kind of traffic it is and the two devices' makers."""
    service = LOCAL_PORT_SERVICES.get(c["port_key"])
    if service:
        return service
    makers = f"{c['src']['maker'] or 'unknown maker'} → {c['dst']['maker'] or 'unknown maker'}"
    if c["port_key"] == "same":
        return f"Same network, no port reported (file sharing, discovery or casting) · {makers}"
    if c["port_key"].endswith(" high"):
        return f"Random ports (an app picks a new one each time) · {makers}"
    return f"{c['port']}: no well-known use · {makers}"


def policy_port_of(port_key):
    """'tcp 8009' -> ('tcp', 8009); 'udp high' -> ('udp', 'high'); 'same' -> None."""
    protocol, _, number = port_key.partition(" ")
    if protocol == "same" or not (number == "high" or number.isdigit()):
        return None
    return protocol, "high" if number == "high" else int(number)


def policy_own_port(port_key):
    """A card's own port as (protocol, ports): 'tcp 8009' -> ('tcp', '8009'),
    'tcp high' -> ('tcp', '32768-65535'), 'same' -> ('any', 'any')."""
    protocol, _, number = str(port_key or "").partition(" ")
    if protocol not in ("tcp", "udp"):
        return "any", "any"
    return protocol, "32768-65535" if number == "high" else number or "any"


def policy_fp_flows(kind, pairs):
    """Violating flows of these device pairs over everything recorded."""
    return sum(p["allowed_flows" if kind == "through" else "blocked_flows"] for p in pairs)


def policy_summary_only(pair):
    """A pair whose "allowed" records are only the router's summary of
    blocked tries: blocked tries, and allowed records under 2 KB each (per
    router record, not per connection started)."""
    allowed = [r for r in pair["rows"] if r["outcome"] == "allowed"]
    records = sum(r["records"] for r in allowed)
    return bool(pair["blocked_flows"] and records and sum(r["bytes"] for r in allowed) <= ACCESS_SUMMARY_BYTES * records)


# BLOCKED BETWEEN CLIENTS, ONE DEFINITION (owner, 23 Nov 2026, D-913): every
# page that counts blocked tries between your clients sorts them the same
# way, here. "missing": at a client Missing Clients had as missing then;
# "unreached": the router couldn't deliver it (no reason named, nothing
# sent) to a client your rules allow (D-906); "nobody": at an address no
# client has or at Firewalla's own equipment, nothing sent and no reason
# named (D-946, D-950); "real": every other
# blocked try. Only real blocks are counted as blocked; the others are shown
# as tries at clients not answering. Counts are connections started (D-883).
policy_allow_keys = set()   # connection keys your rules allow, from the last Policy build
_known_ips = {"at": 0, "ips": set()}


def local_no_client(address):
    """True when address is an IPv4 address that no client of yours has (and
    isn't the NAS pair's shared address): the router names a flow's end by
    its address only then (owner, 23 Nov 2026, D-946)."""
    text = str(address or "")
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", text):
        return False
    if time.time() - _known_ips["at"] > 60:
        _known_ips["ips"] = {str(d.get("ip") or "") for d in state.get("devices") or []} | {shared for shared, _ in ACCESS_HA_PAIRS}
        _known_ips["at"] = time.time()
    return text not in _known_ips["ips"]


def local_block_kind(src, dst, protocol, port, blocked_by, nbytes, first, last):
    """One blocked traffic row: "real", "nobody", "missing" or "unreached"
    (see above)."""
    if blocked_by or nbytes:
        return "real"
    # A try at an address no client has (a printer search sweeping every
    # address of a network, 23 Nov 2026: 86% of a day's blocked tries) is
    # undeliverable, not a block (D-946).
    if local_no_client(dst):
        return "nobody"
    # Nor is one at Firewalla's own router, switches or access points, which
    # don't offer the service tried (a printer search reaching the AP7s on
    # LAN Admin, 23 Nov 2026) (D-950).
    if access_is_gear({"mac": str(dst or "").upper()}):
        return "nobody"
    if any(a <= (last or 0) and (b is None or (first or 0) <= b) for a, b in missing_periods.get(dst, [])):
        return "missing"
    if f"{src}|{dst}|{local_port_label(protocol, port)[0]}" in policy_allow_keys:
        return "unreached"
    return "real"


def local_blocked_counts(hours=24, now=None):
    """{"real", "unanswered"}: blocked tries between your clients in the last
    hours (the hourly rows from the hour it began), sorted by local_block_kind."""
    now = now or time.time()
    out = {"real": 0, "unanswered": 0}
    flush_local_traffic()
    with local_traffic_connection() as connection:
        for src, dst, protocol, port, blocked_by, nbytes, first, last, n in connection.execute(
                "SELECT src_mac, dst_mac, protocol, port, blocked_by, bytes_sent + bytes_received, first_ts, last_ts, COALESCE(starts, flows)"
                " FROM local_traffic_hourly WHERE outcome = 'blocked' AND hour >= ?", (int((now - hours * 3600) // 3600 * 3600),)):
            out["real" if local_block_kind(src, dst, protocol, port, blocked_by, nbytes, first, last) == "real" else "unanswered"] += n or 0
    return out


def policy_unreached_row(outcome, blocked_by, total):
    """A blocked row the router couldn't deliver: no rule or reason named and
    nothing sent, as it logs a try at a device that doesn't answer (off, or
    off the network for a while: 21 Nov 2026, 23 Kasa devices off Wi-Fi for
    20 minutes made 56 violations). Where your rules allow the pair it is no
    violation and no blocked try (owner, 23 Nov 2026, D-906)."""
    return outcome == "blocked" and not blocked_by and not total


def policy_add_counts(c, p, outcome, flows, total, flows_24h, bytes_24h, last, src_ips, dst_ips):
    """One traffic row's counts into its connection and device pair."""
    for field, value in (("flows", flows), ("bytes", total), ("flows_24h", flows_24h), ("bytes_24h", bytes_24h)):
        c[field] += value or 0
    c[outcome + "_flows"] += flows or 0
    c[outcome + "_24h"] += flows_24h or 0
    for side, found in ((0, src_ips), (1, dst_ips)):
        p["ips"][outcome][side].update(x for x in (found or "").split(",") if x)
    p["flows"] += flows or 0
    p["bytes"] += total or 0
    p[outcome + "_flows"] += flows or 0
    p["last_" + outcome] = max(p["last_" + outcome], last or 0)


def policy_remove(st, key, now):
    """A connection (or internet item) off the page, with its decision and
    open items; only traffic after now brings it back, as new."""
    st["removed"][key] = now
    st["decisions"].pop(key, None)
    for item_key in [k for k in st["items"] if k == key or k.startswith(f"v|{key}|")]:
        del st["items"][item_key]


def policy_query(connection, since, day_start, where="", args=()):
    """Local traffic per device pair, port and outcome, from hourly rows
    that ended after <since>. Counts are connections started, not router
    records (owner, 23 Nov 2026: the router writes a record about once a
    minute while a connection stays open, D-883): "starts", or the records
    on rows from before it was kept. The records come last, for the bytes
    per record of the router's summary records (policy_summary_only)."""
    return connection.execute(f"""
        SELECT src_mac, dst_mac, protocol, port, outcome, MAX(src_groups), MAX(dst_groups),
               MAX(src_intf), MAX(dst_intf), SUM(COALESCE(starts, flows)), SUM(bytes_sent) + SUM(bytes_received),
               SUM(CASE WHEN hour >= ? THEN COALESCE(starts, flows) ELSE 0 END),
               SUM(CASE WHEN hour >= ? THEN bytes_sent + bytes_received ELSE 0 END),
               MIN(first_ts), MAX(last_ts), GROUP_CONCAT(DISTINCT allowed_by), GROUP_CONCAT(DISTINCT blocked_by),
               COUNT(DISTINCT CASE WHEN hour >= ? THEN hour END),
               GROUP_CONCAT(DISTINCT src_ip), GROUP_CONCAT(DISTINCT dst_ip), SUM(flows)
        FROM local_traffic_hourly
        WHERE hour >= ? AND last_ts > ?{where}
        GROUP BY src_mac, dst_mac, protocol, port, outcome""",
        (day_start, day_start, day_start, int(since // 3600 * 3600), since, *args)).fetchall()


def policy_done(decision, intent, item_key, label, now):
    """A Rule Change your rules now do: Decided ("changed"), with what was
    done in Firewalla if a Show Me How change came from the card."""
    changes = (policy_read_json(HOWTO_FILE) or {}).get("changes") or []
    change = next((c for c in sorted(changes, key=lambda c: -(c.get("started") or 0)) if c.get("item") == item_key), None)
    done = {"at": now, **((change.get("done") if change and change.get("done") else howto_done_facts(change)) if change else {})}
    return {**{k: v for k, v in decision.items() if k in ("at", "evidence")}, "intent": intent, "at": decision.get("at") or now,
            "label": label, "kind": "changed", "status": "decided", "done": done}


def policy_build(now=None):
    now = now or time.time()
    sides, groups = access_sides()
    # Just after a restart the router's devices and groups aren't read yet:
    # every device would look like it has no group and every connection
    # would be judged without its group's settings. Nothing is built (or
    # saved) until they arrive.
    if not sides or not groups:
        return {"loading": True, "updated_at": now, "recording_since": None,
                "counts": {"triage": 0, "decided": 0, "to_review": 0, "rule_changes": 0, "new_violations": 0, "review": 0, "blocked_24h": 0},
                "triage": [], "decided": [], "review": [], "patterns": [], "explained": [], "countries_blocked": [], "internet_error": None,
                "rule_pids": {}, "page": {"new": [], "flow": [], "violations": [], "messages": [], "decided_count": 0}}
    # VPN peers (another site, a phone on the VPN) are ends of a connection
    # too, and a rule on a private address decides traffic to a site behind
    # one (21 Nov 2026: without them such a connection read Unclear for ever
    # and never left Review).
    peers = access_peer_sides()
    sides = {**peers, **sides}
    rules = access_local_rules() + access_address_rules()
    devices = {str(d.get("mac") or "").upper(): d for d in state.get("devices") or []}
    day_start = int((now - 86400) // 3600 * 3600)
    with policy_lock:
        st = policy_state_load()
    dirty = policy_peer_names(st, {key: p["name"] for key, p in peers.items()})
    # Removed connections older than the recording itself are gone anyway.
    for key, at in list(st["removed"].items()):
        if now - at > LOCAL_TRAFFIC_RETENTION_SECONDS + 86400:
            del st["removed"][key]
            dirty = True

    def keys_of(src, dst, protocol, port, src_groups, dst_groups, src_intf, dst_intf):
        """A connection is one device pair on one port (15 Nov 2026; it was
        a group pair): its key, and the key of its two groups."""
        a, a_name = policy_side_of(sides, groups, src, src_groups, src_intf)
        b, b_name = policy_side_of(sides, groups, dst, dst_groups, dst_intf)
        port_key, port_label = local_port_label(protocol, port)
        return f"{src}|{dst}|{port_key}", f"{a['id']}|{b['id']}|{port_key}", a, a_name, b, b_name, port_key, port_label

    # Traffic since the Policy page started (or was reset); for a removed
    # connection, only traffic after its removal.
    flush_local_traffic()
    with local_traffic_connection() as connection:
        found = policy_query(connection, st["since"], day_start)
        rows, recut = [], set()
        for row in found:
            key = keys_of(*row[:4], *row[5:9])[0]
            if key in st["removed"]:
                recut.add((key, row[0], row[1], row[2]))
            else:
                rows.append(row)
        for key, src, dst, protocol in recut:
            rows += [row for row in policy_query(connection, st["removed"][key], day_start,
                                                 " AND src_mac = ? AND dst_mac = ? AND protocol = ?", (src, dst, protocol))
                     if keys_of(*row[:4], *row[5:9])[0] == key]
        oldest = connection.execute("SELECT MIN(first_ts) FROM local_traffic_hourly").fetchone()[0]
    oldest = max(oldest or st["since"], st["since"])

    # Tries to a missing device (Status, Missing Devices: offline while
    # others keep trying it) are left out: blocked with no rule or reason
    # named and nothing sent, inside a time it was missing. They say nothing
    # about your rules (owner, 19 Nov 2026).
    def unanswered(row):
        src, dst, protocol, port, outcome, total, first, last, blocked_by = row[0], row[1], row[2], row[3], row[4], row[10], row[13], row[14], row[16]
        return outcome == "blocked" and local_block_kind(src, dst, protocol, port, blocked_by, total, first, last) == "missing"
    left_out = {}
    for row in [r for r in rows if unanswered(r)]:
        x = left_out.setdefault(row[1], {"mac": row[1], "name": policy_side_of(sides, groups, row[1], row[6], row[8])[1],
                                         "tries": 0, "sources": set()})
        x["tries"] += row[9] or 0
        x["sources"].add(row[0])
    rows = [r for r in rows if not unanswered(r)]
    # An item already in Review or Violations for such tries goes (unless a
    # rule change was chosen for it) once no other blocked tries are left for
    # it. Its allowed traffic doesn't keep it (owner, 22 Nov 2026: Echo Master
    # Bedroom -> Fan Kasa Office stayed a violation, its 2 tries listed a
    # minute before the fan was missing, because 441 tries got through).
    for item_key, record in list(st["items"].items()):
        parts = item_key.split("|")
        if (len(parts) == 5 and parts[4] == "blocked" and parts[2] in left_out and record.get("status") == "review"
                and not any(r[4] == "blocked" and keys_of(*r[:4], *r[5:9])[0] == "|".join(parts[1:4]) for r in rows)):
            del st["items"][item_key]
            dirty = True

    # Connections, each one device pair.
    conns = {}
    for (src, dst, protocol, port, outcome, src_groups, dst_groups, src_intf, dst_intf, flows, total,
         flows_24h, bytes_24h, first, last, allowed_by, blocked_by, hours_24, src_ips, dst_ips, records) in rows:
        key, group_key, a, a_name, b, b_name, port_key, port_label = keys_of(src, dst, protocol, port, src_groups,
                                                                             dst_groups, src_intf, dst_intf)
        c = conns.setdefault(key, {
            "key": key, "group_key": group_key, "port_key": port_key, "port": port_label,
            "src": {"mac": src, "name": a_name, "maker": policy_maker(devices, src)},
            "dst": {"mac": dst, "name": b_name, "maker": policy_maker(devices, dst)},
            "src_group": a, "dst_group": b,
            "flows": 0, "bytes": 0, "flows_24h": 0, "bytes_24h": 0, "allowed_flows": 0, "blocked_flows": 0,
            "allowed_24h": 0, "blocked_24h": 0, "first_seen": first, "last_seen": last, "hours_24": 0, "pairs": {},
        })
        c["first_seen"] = min(c["first_seen"] or first, first or c["first_seen"])
        c["last_seen"] = max(c["last_seen"] or 0, last or 0)
        c["hours_24"] = max(c["hours_24"], hours_24 or 0)
        p = c["pairs"].setdefault((src, dst), {
            "id": f"{src}|{dst}", "src": {"mac": src, "name": a_name}, "dst": {"mac": dst, "name": b_name},
            "flows": 0, "bytes": 0, "allowed_flows": 0, "blocked_flows": 0, "last_allowed": 0, "last_blocked": 0,
            "allowed_by": set(), "blocked_by": set(), "rows": [],
            # The addresses each side used, allowed and blocked apart (owner,
            # 22 Nov 2026: which of the NAS pair's addresses a blocked try came from).
            "ips": {"allowed": [set(), set()], "blocked": [set(), set()]}, "held": [], "unreached": 0})
        unreached = policy_unreached_row(outcome, blocked_by, total)
        p["rows"].append({"port": port, "outcome": outcome, "flows": flows or 0, "records": records or 0, "bytes": total or 0,
                          "first": first, "last": last, "credited": bool(allowed_by), "unreached": unreached})
        p["allowed_by"].update(x for x in (allowed_by or "").split(",") if x)
        p["blocked_by"].update(x for x in (blocked_by or "").split(",") if x)
        if unreached:
            # Counted once the pair's rules are known: kept out when they allow it.
            p["held"].append((c, flows or 0, flows_24h or 0, last or 0, src_ips, dst_ips))
            continue
        policy_add_counts(c, p, outcome, flows, total, flows_24h, bytes_24h, last, src_ips, dst_ips)
    for c in conns.values():
        c["what"] = policy_what(c)

    # What the rules say, per device pair. The router's credits count for
    # the pair on every port: a long video stream that started before a
    # rule change stays credited to the old rule, while the pair's other
    # connections name the rule that covers it now.
    credits = {}
    for c in conns.values():
        for pair_key, p in c["pairs"].items():
            credits.setdefault(pair_key, set()).update(p["allowed_by"])
    # Checked per connection port: a target list can allow only some ports.
    # Each pair also gets "since": when what decides it last changed (the
    # newest of its rules' made / changed / switched-on times, or the build
    # in which its verdict flipped, which also catches a deleted rule or a
    # VqLAN / Isolation switch). Traffic before that isn't judged against
    # the new rules, so changing a rule makes no false violation.
    verdicts, seen_keys = st["verdicts"], set()

    def rules_since(result, key):
        nonlocal dirty
        times = [0]
        for step in (result or {}).get("steps") or []:
            r = policy_rule_for_pid(step["pid"]) if step.get("pid") else None
            if r:
                times += [r.get(k) or 0 for k in ("created_at", "updated_at", "last_activated_at")]
        verdict = policy_verdict(result)
        if verdict in ("allowed", "blocked"):
            known = verdicts.get(key)
            if not known or known[0] != verdict:
                verdicts[key], dirty = [verdict, now if known else 0], True
        seen_keys.add(key)
        return max(times + [(verdicts.get(key) or [None, 0])[1]])

    iso = access_isolated()
    for c in conns.values():
        port = policy_port_of(c["port_key"])
        for (src, dst), p in c["pairs"].items():
            x, y = sides.get(src), sides.get(dst)
            result = check_local_access(x, y, groups, rules, credits[(src, dst)], port=port, isolated=iso) if x and y else None
            p["rules"] = policy_verdict(result)
            p["deciding"] = result["deciding"] if result else None
            p["steps"] = result["steps"] if result else []
            p["since"] = rules_since(result, f"{src}|{dst}|{c['port_key']}")
            # Tries the router couldn't deliver (D-906): no count where your
            # rules allow the pair (the device was off or off the network, not
            # your rule failing); elsewhere they are blocked tries as before.
            for c_, n, n_24h, last, src_ips, dst_ips in p.pop("held"):
                if p["rules"] == "allowed":
                    p["unreached"] += n
                    p["last_unreached"] = max(p.get("last_unreached") or 0, last)
                else:
                    policy_add_counts(c_, p, "blocked", n, 0, n_24h, 0, last, src_ips, dst_ips)
            # The router's summary line after blocked tries (small "allowed"
            # records, policy_summary_only) is counted as blocked tries on the
            # cards too, as by the violation check (owner, 19 Nov 2026; D-916:
            # 23 Nov, Tapo cameras -> Phone B read "13% let through").
            if policy_summary_only(p):
                n, n_24h = p["allowed_flows"], c["allowed_24h"]
                p.update(allowed_flows=0, blocked_flows=p["blocked_flows"] + n, summary_lines=n,
                         last_blocked=max(p["last_blocked"], p["last_allowed"]), last_allowed=0)
                c["allowed_flows"] -= n
                c["blocked_flows"] += n
                c.update(allowed_24h=0, blocked_24h=c["blocked_24h"] + n_24h)
        c["unreached"] = sum(p["unreached"] for p in c["pairs"].values())
        c["pair_list"] = list(c["pairs"].values())
        c["pair_rules"] = policy_summary([p["rules"] for p in c["pair_list"]])
        c["reality"] = "both" if c["allowed_flows"] and c["blocked_flows"] else "allowed" if c["allowed_flows"] else "blocked"

    for key in [k for k in verdicts if k not in seen_keys]:
        del verdicts[key]
        dirty = True

    decisions = st["decisions"]
    # A row's Allow / Block and the Claude refs it
    # carries go with the connection: once it is off the page (no traffic
    # left in the recorder) they were kept for ever. Internet rows aren't in
    # conns (they are judged from the flow history).
    for name in ("row_picks", "nc_refs"):
        for key in [k for k in st.get(name) or {} if k not in conns and not k.startswith("inet|")]:
            del st[name][key]
            dirty = True
    # Every decision is for one connection (owner, 20 Nov 2026), so what
    # your rules say for a connection is what they say for its two devices.
    for c in conns.values():
        c["rules"] = c["pair_rules"]
    # What your rules allow, for local_block_kind (every page's blocked count, D-913).
    policy_allow_keys.clear()
    policy_allow_keys.update(c["key"] for c in conns.values() if c["rules"] == "allowed")

    # Rule names on the page -> their numbers (the names link to the rule popup).
    rule_pids = {}
    for c in conns.values():
        for p in c["pair_list"]:
            if (p.get("deciding") or {}).get("pid"):
                rule_pids[p["deciding"]["text"]] = str(p["deciding"]["pid"])
            for x in p["allowed_by"]:
                if (r := policy_rule_for_pid(x)):
                    rule_pids[access_rule_text(r)] = str(x)

    def pair_out(p):
        return {"src": p["src"], "dst": p["dst"], "flows": p["flows"], "bytes": p["bytes"],
                "allowed_flows": p["allowed_flows"], "blocked_flows": p["blocked_flows"],
                "last_seen": max(p["last_allowed"], p["last_blocked"]), "rules": p["rules"],
                "ips": {k: policy_ips_placed(v, p["src"]["mac"], p["dst"]["mac"], sides) for k, v in p["ips"].items()},
                "allowed_by": [access_rule_text(r) if (r := policy_rule_for_pid(x)) else f"rule #{x} (since removed)"
                               for x in sorted(p["allowed_by"])],
                "blocked_by": [policy_blocked_text(x, groups) for x in sorted(p["blocked_by"])]}

    def conn_out(c, **extra):
        p = pair_out(c["pair_list"][0])
        return {**{k: c[k] for k in ("key", "src", "dst", "src_group", "dst_group", "port", "what", "flows", "bytes",
                                      "flows_24h", "allowed_flows", "blocked_flows", "allowed_24h", "blocked_24h",
                                      "first_seen", "last_seen", "rules", "pair_rules", "reality", "port_key")},
                "allowed_by": p["allowed_by"], "blocked_by": p["blocked_by"],
                "last_allowed": max((x["last_allowed"] for x in c["pair_list"]), default=0),
                "last_blocked": max((x["last_blocked"] for x in c["pair_list"]), default=0),
                "deciding": (c["pair_list"][0].get("deciding") or {}).get("text"),
                # What else is on for its two devices (owner, 18 Nov 2026).
                "also_on": {"src": access_also_on(sides.get(c["src"]["mac"])), "dst": access_also_on(sides.get(c["dst"]["mac"]))},
                **extra}

    def with_why(row):
        row["why"] = policy_why([row])
        return row

    triage, decided, review = [], [], []
    st["settled"] = [x for x in st["settled"] if now - x["at"] < POLICY_SETTLED_LOG_SECONDS]

    def settles(c):
        """Settled by default: in New Connections for 7 days untouched (no
        Allow / Block picked), the two devices only, the router doing what
        your rules say. On the rules alone: no Claude answer needed (owner,
        18 Nov 2026; still so in the 19 Nov flow)."""
        return (c["rules"] in ("allowed", "blocked") and c["reality"] == c["rules"] and c["key"] not in st["row_picks"]
                and now - (c["first_seen"] or now) >= POLICY_SETTLE_SECONDS)
    TAB = {"review": "to_review", "rule_change": "rule_changes", "confirm": "confirming"}
    clear = bool(sides and groups)   # rule and group data have arrived
    missing_ready = bool((state.get("missing") or {}).get("updated_at"))   # Missing Devices' first pass is done

    def remove(key):
        nonlocal dirty
        policy_remove(st, key, now)
        dirty = True

    def keep_snapshot(record, value):
        """What an open item shows, kept so it stays listed when its traffic stops."""
        nonlocal dirty
        if record.get("snapshot") != value:
            record["snapshot"], dirty = value, True

    def rules_match(intent, rules_now):
        return rules_now == ("allowed" if intent == "allow" else "blocked")

    def label(c):
        return f"{c['src']['name']} → {c['dst']['name']} · {c['port']}"

    def review_row(record, item_key, live, **extra):
        return {**record["snapshot"], "item": item_key, "tab": TAB[record["status"]],
                "since": record.get("status_at") or record.get("at"), "live": live, **extra}

    # The flow moves on by itself first: Pending Action -> Pending
    # Confirmation once your rules do it, the watch, back to Review.
    if clear and policy_flow_step(st, conns, now):
        dirty = True

    for c in conns.values():
        key = c["key"]
        decision = decisions.get(key)
        fp = (decision or {}).get("fp")

        # Decided: removed once a rule change contradicts it for the devices
        # seen (after a while, so a moment of missing rule data removes
        # nothing). Meanwhile its older traffic isn't judged against the new
        # rules.
        seen_rules = policy_summary([c["pair_rules"]])
        # Accept All and cards that joined a group take what happened even where
        # your rules are unclear (an address with no device): only rules saying
        # the opposite contradict them (18 Nov 2026).
        loose = bool(decision and decision.get("kind") in ("accept", "auto", "nodev"))
        contradicted = bool(decision and decision.get("status") == "decided" and clear
                            and (rules_match("block" if decision["intent"] == "allow" else "allow", seen_rules) if loose
                                 else not rules_match(decision["intent"], seen_rules)))
        if contradicted:
            if "contra_at" not in decision:
                decision["contra_at"], dirty = now, True
            elif now - decision["contra_at"] >= POLICY_CONTRADICT_SECONDS:
                remove(key)
                continue
        elif decision and decision.pop("contra_at", None):
            dirty = True

        # Violations: the router did the opposite of what your rules say.
        # Once listed, one stays until you choose. Not while the connection
        # is an item in Review, Pending Action or Pending Confirmation (that
        # item is where it is being worked on), and not for the router's
        # summary records (tiny "allowed" records after blocked tries).
        violation_open = held = False
        working = bool(decision and decision.get("flow") and decision.get("status") != "decided")
        for kind, test in () if contradicted or working else (
                ("through", lambda p: p["rules"] == "blocked" and p["allowed_flows"] and not policy_summary_only(p)
                 and now - p["last_allowed"] < POLICY_QUIET_SECONDS and p["last_allowed"] > p["since"]),
                ("blocked", lambda p: p["rules"] == "allowed" and p["blocked_flows"]
                 and now - p["last_blocked"] < POLICY_QUIET_SECONDS and p["last_blocked"] > p["since"])):
            item_key = f"v|{key}|{kind}"
            pairs = [p for p in c["pair_list"] if test(p)]
            # Not judged until Missing Devices has had its first pass after a
            # start: until then tries at an offline device aren't left out yet
            # and looked like violations (22 Nov 2026, Speakers → Dimmer Hot Tub
            # after a restart). Such a connection is held back meanwhile, not
            # shown anywhere else either.
            if not missing_ready:
                held = held or bool(pairs or st["items"].get(item_key))
                continue
            record = st["items"].get(item_key)
            if pairs and not record:
                # Not while monitoring is stopped, nor for tries only in a stopped time (D-919).
                newest_try = max(p["last_allowed" if kind == "through" else "last_blocked"] for p in pairs)
                if policy_paused_only(st, item_key, newest_try, newest_try):
                    continue
                # Keep My Rule: back only if it happens again after it.
                if fp and fp["kind"] == kind and all(p["last_allowed" if kind == "through" else "last_blocked"] <= fp["at"] for p in pairs):
                    continue
                # Quiet This Pattern: a known, harmless repeat is recorded, not listed.
                if kind == "blocked" and policy_quiet_match(st, c, pairs, now):
                    dirty = True
                    continue
                record = st["items"][item_key] = {"status": "review", "at": now}
                dirty = True
            if not record:
                continue
            violation_open = True
            if pairs:
                over = sorted({x for p in pairs for x in (pair_out(p)["allowed_by"] if kind == "through" else pair_out(p)["blocked_by"])})
                keep_snapshot(record, {
                    **conn_out(c), "kind": kind, "label": label(c),
                    "violation_pairs": [pair_out(p) for p in pairs],
                    "violation_flows": policy_fp_flows(kind, pairs),
                    "violation_last": max(p["last_allowed" if kind == "through" else "last_blocked"] for p in pairs),
                    "policy_violated": sorted({p["deciding"]["text"] for p in pairs if p.get("deciding")}),
                    "overridden_by": over or ["not named by the router"],
                    "cause": policy_violation_cause(kind, pairs, sides),
                    "violation_rules": policy_rules_table(pairs[0], kind),
                    "earlier": (decision or {}).get("evidence") or [],
                    # Change My Rule: Allow (got through) or Block (got blocked).
                    "fix_intent": "allow" if kind == "through" else "block"})
            elif record.get("snapshot"):
                # No longer live (its tries are older than the rules' last
                # change, or quiet): the rules table still follows today's
                # rules for the same pair (owner, 22 Nov 2026).
                listed = {(x["src"]["mac"], x["dst"]["mac"]) for x in record["snapshot"].get("violation_pairs") or []}
                same = [p for p in c["pair_list"] if (p["src"]["mac"], p["dst"]["mac"]) in listed]
                if same:
                    now_ips = {(p["src"]["mac"], p["dst"]["mac"]): pair_out(p)["ips"] for p in same}
                    keep_snapshot(record, {**record["snapshot"], "violation_rules": policy_rules_table(same[0], kind),
                                           "violation_pairs": [{**x, "ips": now_ips.get((x["src"]["mac"], x["dst"]["mac"])) or x.get("ips")}
                                                               for x in record["snapshot"].get("violation_pairs") or []]})
            if record.get("snapshot"):
                review.append(review_row(record, item_key, bool(pairs), rules=c["rules"]))
        if held:
            continue

        # YOUR CHOICE: your choice differs from your rules (or they're unclear).
        if decision and decision.get("status") in TAB:
            keep_snapshot(decision, {**conn_out(c), "kind": "conflict", "intent": decision["intent"], "label": label(c),
                                     "decided_at": decision.get("at")})
            review.append(review_row(decision, f"c|{key}", True, joined=decision.get("joined"), reopened=decision.get("reopened")))
            continue
        if violation_open:
            continue
        if decision:
            shown = {k: decision.get(k) for k in ("intent", "at", "kind", "reason", "done", "joined", "how", "why", "refs", "tried", "watch", "evidence")}
            decided.append(conn_out(c, decision=shown))
        elif policy_paused_only(st, key, c["first_seen"], c["last_seen"]):
            continue   # Seen only while monitoring was stopped (D-919): no card, not settled either.
        elif settles(c):
            intent = "allow" if c["rules"] == "allowed" else "block"
            decision = decisions[key] = {"intent": intent, "at": now, "label": label(c), "kind": "default", "status": "decided"}
            st["settled"].append({"at": now, "label": label(c)})
            dirty = True
            decided.append(conn_out(c, decision={k: decision.get(k) for k in ("intent", "at", "kind")}))
        elif now - (c["last_seen"] or 0) <= POLICY_TRIAGE_SECONDS:
            triage.append(conn_out(c, tag="new"))

    # Open items whose connection has no traffic left in the recording stay listed.
    for key, decision in decisions.items():
        if key not in conns and decision.get("status") in TAB and decision.get("snapshot"):
            review.append(review_row(decision, f"c|{key}", False))
    for item_key, record in st["items"].items():
        if (not item_key.startswith("v|internet|") and item_key[2:].rsplit("|", 1)[0] not in conns
                and record.get("snapshot")):
            review.append(review_row(record, item_key, False))

    # Internet: blocked countries reached with no allow rule of yours.
    live_internet = set()
    for item in policy_internet["items"]:
        item_key = f"v|internet|{item['key']}"
        if (item.get("last_seen") or 0) <= max(st["since"], st["removed"].get(item_key, 0)):
            continue
        record = st["items"].get(item_key)
        if not record and policy_paused_only(st, item_key, item.get("last_seen"), item.get("last_seen")):
            continue   # Monitoring stopped, or reached only then (D-919).
        if not record:
            record = st["items"][item_key] = {"status": "review", "at": now}
            dirty = True
        keep_snapshot(record, {
            **item, "kind": "internet", "label": f"Country {item['country']} reached",
            "policy_violated": [f"#{r['pid']} {r['text']}" for r in item["rules"]],
            "overridden_by": ["no allow rule on these connections"], "fix_intent": "allow",
            "steps": [f"Rules › add an allow rule for {', '.join(item['destinations'][:3]) or 'these destinations'}"
                      f"{' from ' + item['devices'][0]['name'] if len(item['devices']) == 1 else ''}, "
                      f"so your country block ({', '.join('#' + str(r['pid']) for r in item['rules'])}) no longer covers it."]})
        live_internet.add(item_key)
    for item_key, record in list(st["items"].items()):
        if item_key.startswith("v|internet|") and record.get("snapshot"):
            review.append(review_row(record, item_key, item_key in live_internet))

    order = {"to_review": 0, "rule_changes": 1, "confirming": 2}
    review.sort(key=lambda r: (order[r["tab"]], r["kind"] == "conflict", -(r.get("violation_last") or r.get("last_seen") or 0)))
    triage.sort(key=lambda c: -(c["last_seen"] or 0))
    # (A new connection is never decided by joining a Decided pattern: it
    # comes to New Connections. Owner, 20 Nov 2026.)
    for row in triage + decided + review:
        if row.get("kind") != "internet" and row.get("src"):
            with_why(row)
    # (New Connections has no pattern groups: there a group is one source
    # and one target, policy_page. Decided ones are still found, for the
    # nightly review.)
    patterns = []
    for x in policy_patterns(decided, {}):
        for r in decided:
            if r.get("pattern") == x["id"]:
                r["pattern"] = "decided:any:" + x["id"]
        patterns.append(dict(x, id="decided:any:" + x["id"], stage="decided", why=policy_why([r for r in decided if r["key"] in x["keys"]]),
                             items=[None] * len(x["keys"]), kinds=["decided"]))
    page = policy_page(st, conns, triage, patterns, review, decided, now)
    if dirty:
        with policy_lock:
            policy_state_save(st)
    stage_n = lambda s: sum(1 for f in page["flow"] if f["stage"] == s)
    blocked_now = local_blocked_counts(24, now)
    counts = {
        # The page's five rings: rows in New Connections, items after it.
        "new": sum(len(x["rows"]) for x in page["new"]), "new_items": len(page["new"]),
        "review_items": stage_n("review"), "action": stage_n("action"), "confirm": stage_n("confirm"),
        "not_working": sum(1 for f in page["flow"] if (f.get("watch") or {}).get("bad")),
        "violations": len(page["violations"]),
        # (Read by Status, Overview, the menu and the digest.)
        # Every decision you made, as the Decided page lists them (D-915), not
        # only the ones with traffic in the recording.
        "triage": sum(len(x["rows"]) for x in page["new"]), "decided": policy_decided_total(st),
        "to_review": stage_n("review"), "rule_changes": stage_n("action") + stage_n("confirm"),
        "new_violations": len(page["violations"]), "review": len(page["flow"]) + len(page["violations"]),
        "quiet_due": sum(1 for q in page.get("quiet") or [] if q["due"]),
        # The one count of blocked tries between clients (D-913), as on Blocked Between Clients.
        "blocked_24h": blocked_now["real"], "unanswered_24h": blocked_now["unanswered"],
    }
    # For the menu's * (owner, 18 Nov 2026): red while something new came in
    # since you last looked at Policy (a new card, a new violation, a card
    # joining a group, Claude answering about a card), yellow while there are
    # only open items. "newest_at" and "claude_at" are when each last happened.
    # Violations have their own page and * (owner, 22 Nov 2026): "violations_newest_at".
    violation_kinds = ("through", "blocked", "internet")
    newest = max([c.get("first_seen") or 0 for c in triage] + [r.get("since") or 0 for r in review if r.get("kind") not in violation_kinds]
                 + [(f.get("watch") or {}).get("bad_at") or 0 for f in page["flow"]] or [0])
    newest_violation = max([r.get("since") or 0 for r in review if r.get("kind") in violation_kinds]
                           + [q["review_at"] or 0 for q in page.get("quiet") or [] if q["due"]] or [0])
    # stopped: when Stop Monitoring was turned on (D-919): Status, the menu
    # and the digest show Policy as stopped, not as work waiting.
    state["policy"] = {**counts, "updated_at": now, "newest_at": newest, "violations_newest_at": newest_violation,
                       "claude_at": policy_claude_at(), "stopped": (st.get("monitor") or {}).get("stopped")}
    return {
        "updated_at": now, "recording_since": oldest, "counts": counts,
        "triage": triage, "decided": decided, "review": review, "patterns": patterns, "page": page,
        "explained": policy_internet["explained"], "countries_blocked": policy_internet["countries"],
        "internet_error": policy_internet["error"], "rule_pids": rule_pids,
        "left_out": sorted(({**x, "sources": len(x["sources"])} for x in left_out.values()), key=lambda x: -x["tries"]),
    }


# ============================================================
# PATTERNS (owner, 18 Nov 2026): New Connections cards that have something in
# common, grouped so the pattern shows instead of hiding among single cards.
# Each card is in at most one pattern, found in this order:
#   scan    one device tries 5+ different addresses on one port;
#   nodev   one address with no device, tried by several devices, on several
#           ports or several times (one try, once, is no pattern);
#   target  several devices fail (some tries blocked) to reach one device on
#           one port while your rules allow it: look at the target;
#   source  one device fails to reach several devices while your rules allow it;
#   disagree  several cards for one group pair where the router did other
#           than your rules say.
# Burst (10+ tries within 15 minutes) and No Device are also tags on a card.
# A card you Take Out of a pattern stays out of it (pattern_out) but can be in
# another; Put Back returns it.
# ============================================================
POLICY_PATTERN_IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
POLICY_SCAN_MIN = 5
POLICY_BURST_SECONDS = 15 * 60
POLICY_BURST_FLOWS = 10
POLICY_PATTERN_WORDS = {"scan": "Scan", "nodev": "No Client", "target": "Problem At One Target",
                        "source": "Problem At One Source", "disagree": "Router Disagrees"}


def policy_patterns(cards, taken_out):
    out = {pid: set(keys) for pid, keys in taken_out.items()}
    nodev = lambda c: bool(POLICY_PATTERN_IP.match(str(c["dst"]["mac"])))
    failing = lambda c: c["rules"] == "allowed" and c["blocked_flows"] > 0
    disagrees = lambda c: (c["rules"] == "allowed" and c["blocked_flows"] > 0) or (c["rules"] == "blocked" and c["allowed_flows"] > 0)
    used, found = set(), []

    def bucket(cs, key):
        b = {}
        for c in cs:
            if c["key"] not in used:
                b.setdefault(key(c), []).append(c)
        return b

    def add(kind, pid, members, title, words):
        members = [c for c in members if c["key"] not in out.get(pid, set()) and c["key"] not in used]
        if not members:
            return
        used.update(c["key"] for c in members)
        found.append({"id": pid, "kind": kind, "tag": POLICY_PATTERN_WORDS[kind], "title": title, "words": words,
                      "keys": [c["key"] for c in members], "first": min(c["first_seen"] or 0 for c in members),
                      "last": max(c["last_seen"] or 0 for c in members),
                      "rules": policy_summary([c["rules"] for c in members]),
                      "uniform": len({c["reality"] for c in members}) == 1 and members[0]["reality"] != "both"
                                 and len({c["port_key"] for c in members}) == 1 and len({c["dst"]["mac"] for c in members}) == 1,
                      "taken_out": sorted(out.get(pid, set()))})
        for c in members:
            c["pattern"] = pid

    # An address with no device that several devices try is its own No Device
    # group, even when one of them is scanning - unless every device trying it
    # is scanning (two PCs running the same printer search, 18 Nov 2026).
    scanners = {k for k, cs in bucket(cards, lambda c: (c["src"]["mac"], c["port_key"])).items()
                if len({c["dst"]["mac"] for c in cs}) >= POLICY_SCAN_MIN and 2 * sum(1 for c in cs if nodev(c) or not c["allowed_flows"]) >= len(cs)}
    shared = {a for a, cs in bucket([c for c in cards if nodev(c)], lambda c: c["dst"]["mac"]).items()
              if len({c["src"]["mac"] for c in cs}) > 1 and any((c["src"]["mac"], c["port_key"]) not in scanners for c in cs)}
    for (src, port_key), cs in bucket([c for c in cards if c["dst"]["mac"] not in shared], lambda c: (c["src"]["mac"], c["port_key"])).items():
        # A search, not a busy device: most of its tries blocked or aimed at no
        # device (Speakers talking to many Speakers aren't scanning, 18 Nov 2026).
        if len({c["dst"]["mac"] for c in cs}) >= POLICY_SCAN_MIN and 2 * sum(1 for c in cs if nodev(c) or not c["allowed_flows"]) >= len(cs):
            add("scan", f"scan|{src}|{port_key}", cs, f"{cs[0]['src']['name']} → {len(cs)} addresses · {cs[0]['port']}",
                f"{sum(nodev(c) for c in cs)} with no client · {cs[0]['dst_group']['name']}")
    for addr, cs in bucket([c for c in cards if nodev(c)], lambda c: c["dst"]["mac"]).items():
        if len(cs) > 1 or sum(c["flows"] for c in cs) > 1:
            who = sorted({c["src"]["name"] for c in cs})
            add("nodev", f"nodev|{addr}", cs, f"{', '.join(who[:3])}{' …' if len(who) > 3 else ''} → {addr} (no client)",
                f"{len(who)} client{'s' if len(who) != 1 else ''} · {len({c['port_key'] for c in cs})} port{'s' if len({c['port_key'] for c in cs}) != 1 else ''} · {sum(c['flows'] for c in cs)} tries")
    for (dst, port_key), cs in bucket([c for c in cards if failing(c)], lambda c: (c["dst"]["mac"], c["port_key"])).items():
        if len({c["src"]["mac"] for c in cs}) >= 2:
            add("target", f"target|{dst}|{port_key}", cs, f"{len(cs)} clients → {cs[0]['dst']['name']} · {cs[0]['port']}",
                f"The router blocked {sum(c['blocked_flows'] for c in cs)} of {sum(c['flows'] for c in cs)} tries · look at {cs[0]['dst']['name']}")
    for src, cs in bucket([c for c in cards if failing(c)], lambda c: c["src"]["mac"]).items():
        if len({c["dst"]["mac"] for c in cs}) >= 2:
            add("source", f"source|{src}", cs, f"{cs[0]['src']['name']} → {len(cs)} clients",
                f"The router blocked {sum(c['blocked_flows'] for c in cs)} of {sum(c['flows'] for c in cs)} tries · look at {cs[0]['src']['name']}")
    for (a, b), cs in bucket([c for c in cards if disagrees(c)], lambda c: (c["src_group"]["id"], c["dst_group"]["id"])).items():
        if len(cs) >= 2:
            add("disagree", f"disagree|{a}|{b}", cs, f"{cs[0]['src_group']['name']} → {cs[0]['dst_group']['name']} · {len(cs)} connections",
                "The router did other than your rules say")
    for c in cards:
        tags = [POLICY_PATTERN_WORDS[p["kind"]] for p in found if p["id"] == c.get("pattern")]
        if nodev(c) and "No Client" not in tags:
            tags.append("No Client")
        if c["flows"] >= POLICY_BURST_FLOWS and (c["last_seen"] or 0) - (c["first_seen"] or 0) <= POLICY_BURST_SECONDS:
            tags.append("Burst")
        c["tags"] = tags
    return found


# ============================================================
# NIGHTLY DECIDED REVIEW (owner, 18 Nov 2026). At 03:00 Claude looks at the
# Decided groups and cards whose traffic changed in the last 24 hours
# compared with the previous 30 days: the router did other than you decided,
# 5 times the daily average (or the first traffic in 30 days, at least 5
# connections; one that stays open counts once), or a port not seen in those 30 days. At most 20 a night, the most
# changed first. For each, Claude carries on (the card stays Decided, marked
# Checked By Claude) or reopens it: the whole group goes back to Review with
# Claude's new assessment, for you to decide again. Claude never decides.
# Separately, decisions with no traffic for 90 days are listed (no Claude).
# Cards decided in the last 24 hours aren't looked at yet.
# ============================================================
POLICY_REVIEW_HOUR = 3
POLICY_REVIEW_MAX = 20
POLICY_REVIEW_SURGE = 5
POLICY_REVIEW_MIN_TRIES = 5
POLICY_REVIEW_DAYS = 30
POLICY_REVIEW_MIN_DAYS = 3   # whole days counted in connections before "much more than usual" is said
POLICY_QUIET_DAYS = 90


def policy_review_traffic(now):
    """Connections per connection key: last 24 hours by outcome (hourly rows)
    and the 30 days before (daily rows), how many of those days were
    recorded, and the keys seen in the last 90 days. A connection that stays
    open counts once, not once per router record (the "starts" totals, kept
    from 23 Nov 2026; see flows.py). Until "starts" covers the last 24 hours
    and at least one whole day before, days is 0 (nothing compared)."""
    flush_local_traffic()
    cut = int((now - 86400) // 3600 * 3600)
    day_cut = internet_day(now - 86400)
    key = lambda src, dst, protocol, port: f"{src}|{dst}|{local_port_label(protocol, port)[0]}"
    last, prior, seen90 = {}, Counter(), set()
    with local_traffic_connection() as connection:
        since = (connection.execute("SELECT value FROM local_traffic_meta WHERE name = 'starts_since'").fetchone() or [now])[0]
        since_day = internet_day(internet_day(since) + 86400 + 43200)   # the first whole day with starts
        # Apart: blocked tries the router couldn't deliver ("unreached", D-906:
        # no blocked try for an Allow) and allowed records under 2 KB each
        # ("tiny": the router's summary line after blocked tries, D-909, as
        # policy_summary_only); policy_review_units sorts them out.
        for src, dst, protocol, port, outcome, unreached, tiny, flows in connection.execute(
                "SELECT src_mac, dst_mac, protocol, port, outcome,"
                " outcome = 'blocked' AND COALESCE(blocked_by, '') = '' AND bytes_sent + bytes_received = 0,"
                " outcome = 'allowed' AND bytes_sent + bytes_received <= ? * flows,"
                " SUM(COALESCE(starts, flows)) FROM local_traffic_hourly"
                " WHERE hour >= ? GROUP BY 1, 2, 3, 4, 5, 6, 7", (ACCESS_SUMMARY_BYTES, cut)):
            last.setdefault(key(src, dst, protocol, port), Counter())["unreached" if unreached else "tiny" if tiny else outcome] += flows or 0
        for src, dst, protocol, port, flows in connection.execute(
                "SELECT src_mac, dst_mac, protocol, port, SUM(starts) FROM local_traffic_daily WHERE day >= ? AND day < ? GROUP BY 1, 2, 3, 4",
                (max(since_day, internet_day(day_cut - POLICY_REVIEW_DAYS * 86400 + 43200)), day_cut)):
            prior[key(src, dst, protocol, port)] += flows or 0
        for src, dst, protocol, port in connection.execute(
                "SELECT DISTINCT src_mac, dst_mac, protocol, port FROM local_traffic_daily WHERE day >= ?", (internet_day(now - POLICY_QUIET_DAYS * 86400),)):
            seen90.add(key(src, dst, protocol, port))
        first = connection.execute("SELECT MIN(day) FROM local_traffic_daily").fetchone()[0]
    days = min(POLICY_REVIEW_DAYS, max(0, round((day_cut - max(first or day_cut, since_day)) / 86400)))
    if cut < since // 3600 * 3600 + 3600 or days < POLICY_REVIEW_MIN_DAYS:
        days = 0   # the last 24 hours aren't all counted in connections yet, or too few days to compare with
    # "Not seen in 90 days" can only be said once the totals reach back 90
    # days: until then (or after the totals were reset) nothing is quiet.
    if first is None or first > internet_day(now - POLICY_QUIET_DAYS * 86400):
        seen90 = None
    return last, prior, days, seen90


def policy_review_units(data, now, traffic=None):
    """The Decided groups and cards that changed (see above), most changed
    first: [{key, keys, label, intent, signals, facts}], and how many changed."""
    last, prior, days, _ = traffic or policy_review_traffic(now)
    random = lambda k: k.endswith((" high", "|same"))

    def card_numbers(c):
        keys = {c["key"]}
        t = Counter()
        for k in keys:
            t.update(last.get(k) or {})
        # Tries the router couldn't deliver (the device off or off the
        # network): nothing for an Allow (23 Nov 2026: four Echo → Fan Kasa
        # Office cards reopened for the fan's nightly power cut), blocked
        # tries for a Block.
        unreached = t.pop("unreached", 0)
        if (c.get("decision") or {}).get("intent") != "allow" and unreached:
            t["blocked"] += unreached
        # Small allowed records beside blocked tries, with no bigger allowed
        # ones: the router's summary line, so blocked tries (as Policy's own
        # violation check; 23 Nov 2026: 6 such records from Tapo cameras to
        # Phone B reopened a Block as "15 of 137 let through", D-909).
        # Only for a Block: small records are real traffic for an Allow (an
        # Echo's Kasa command is about 650 bytes).
        tiny = t.pop("tiny", 0)
        if tiny:
            block = (c.get("decision") or {}).get("intent") != "allow"
            t["blocked" if block and t.get("blocked") and not t.get("allowed") else "allowed"] += tiny
        before = sum(prior.get(k, 0) for k in keys)
        ports_now = {k.rsplit("|", 1)[1] for k in keys if sum((last.get(k) or {}).values()) and not random(k)}
        ports_before = {k.rsplit("|", 1)[1] for k in keys if prior.get(k)}
        return t, before, ports_now - ports_before

    units = []
    in_group = {}
    for pat in data.get("patterns") or []:
        if pat.get("stage") == "decided":
            for k in pat["keys"]:
                in_group[k] = pat
    groups = {}
    for c in data.get("decided") or []:
        d = c.get("decision") or {}
        if (d.get("at") or now) > now - 86400:
            continue   # decided in the last day: nothing to compare yet
        pat = in_group.get(c["key"])
        groups.setdefault(("pattern:" + pat["id"]) if pat else c["key"], []).append((c, pat))
    for ukey, members in groups.items():
        t, before, new_ports, cards = Counter(), 0, set(), []
        for c, _ in members:
            ct, cb, cp = card_numbers(c)
            t += ct
            before += cb
            new_ports |= cp
            cards.append({"connection": f"{c['src']['name']} → {c['dst']['name']} ({c['port']})", "what": c.get("what"),
                          "your_rules": c["rules"], "last_24h": {"allowed": ct.get("allowed", 0), "blocked": ct.get("blocked", 0)},
                          "daily_average_previous_30_days": round(cb / days, 1) if days else None,
                          "allowed_by": c.get("allowed_by"), "blocked_by": c.get("blocked_by")})
        first, pat = members[0]
        intent = (first.get("decision") or {}).get("intent")
        signals = []
        if (intent == "allow" and t.get("blocked")) or (intent == "block" and t.get("allowed")):
            signals.append(f"the router {'blocked' if intent == 'allow' else 'allowed'} {t.get('blocked' if intent == 'allow' else 'allowed')} "
                           f"of {sum(t.values())} connections in 24 hours, though you decided {'Allow' if intent == 'allow' else 'Block'}")
        total, average = sum(t.values()), (before / days if days else None)
        if days and total >= POLICY_REVIEW_MIN_TRIES and total >= POLICY_REVIEW_SURGE * (average or 0):
            signals.append(f"{total} connections in 24 hours, the first in {days} days" if not before
                           else f"{total} connections in 24 hours, {round(total / average)} times the daily average of {round(average, 1)}")
        if days and new_ports and before:   # (a card with no traffic before is "the first in N days")
            signals.append("new port" + ("s" if len(new_ports) > 1 else "") + ": " + ", ".join(sorted(new_ports)))
        if not signals:
            continue
        label = pat["title"] if pat else f"{first['src']['name']} → {first['dst']['name']} · {first['port']}"
        units.append({"key": ukey, "keys": [c["key"] for c, _ in members], "label": label, "intent": intent,
                      "signals": signals, "score": (bool(signals[0].startswith("the router")), total / ((average or 0) + 0.5)),
                      "facts": {"key": ukey, "group": pat["title"] if pat else None, "cards": cards[:30],
                                "your_decision": "Allow" if intent == "allow" else "Block",
                                "decided": time.strftime("%Y-%m-%d", time.localtime((first.get("decision") or {}).get("at") or now)),
                                "how_decided": {"default": "settled by default (rules alone)", "auto": "joined a decided group",
                                                "accept": "accepted as the router handled it", "changed": "changed in Firewalla",
                                                "nodev": "no client at that address: decided as the router handled it",
                                                "false_alarm": "false alarm"}.get((first.get("decision") or {}).get("kind"), "by you"),
                                "what_changed": signals, "days_recorded_before": days}})
    units.sort(key=lambda u: u["score"], reverse=True)
    return units


def policy_drop_quiet(st, seen90, now):
    """Decisions quiet for 90 days are dropped (owner, 20 Nov 2026): decided
    at least 90 days ago and no traffic between the two devices on that port
    since. Its next traffic comes to New Connections as new. Internet
    decisions stay (their traffic isn't in the local totals). Returns the
    dropped decisions' labels. seen90 None: the totals don't reach back 90
    days yet, so nothing is dropped."""
    if seen90 is None:
        return []
    quiet = sorted((k for k, d in st["decisions"].items()
                    if d.get("status") == "decided" and not k.startswith("inet|")
                    and (d.get("at") or now) <= now - POLICY_QUIET_DAYS * 86400 and k not in seen90),
                   key=lambda k: st["decisions"][k].get("at") or 0)
    labels = []
    for key in quiet:
        labels.append(st["decisions"].pop(key).get("label") or key)
        for item_key in [k for k in st["items"] if k == key or k.startswith(f"v|{key}|")]:
            del st["items"][item_key]
    return labels


def policy_review_due(now):
    """From 03:00 once a day: the nightly review (asked through Claude's
    queue), and the decisions quiet for 90 days are dropped."""
    if time.localtime(now).tm_hour < POLICY_REVIEW_HOUR:
        return
    today = time.strftime("%Y-%m-%d", time.localtime(now))
    with policy_lock:
        st = policy_state_load()
    if (st.get("decided_review") or {}).get("day") == today:
        return
    # Not while monitoring is stopped (D-919); after a resume it runs at the
    # next check (the traffic it compares was recorded all along).
    if (st.get("monitor") or {}).get("stopped"):
        return
    data = policy_data()
    if data.get("loading"):
        return
    traffic = policy_review_traffic(now)
    units = policy_review_units(data, now, traffic)
    from assistant import claude_decided_queue
    asked = claude_decided_queue(units[:POLICY_REVIEW_MAX], now) if units else 0
    with policy_lock:
        st = policy_state_load()
        st["decided_review"] = {"day": today, "at": now, "changed": len(units), "asked": asked,
                                "not_asked": max(0, len(units) - POLICY_REVIEW_MAX) if asked else len(units),
                                "carried_on": 0, "reopened": [], "answered_at": None}
        dropped = policy_drop_quiet(st, traffic[3], now)
        if dropped:
            st["dropped"] = {"at": now, "labels": dropped}
        policy_state_save(st)


def policy_review_result(results, now):
    """Claude's answers to the nightly review: [(unit, verdict)]. Reopen =
    every card of the unit back to Review (your choice kept, Reopened By
    Claude); carry on = it stays Decided."""
    reopened, carried = [], 0
    with policy_lock:
        st = policy_state_load()
        for unit, verdict in results:
            if verdict == "reopen":
                for k in unit["keys"]:
                    d = st["decisions"].get(k)
                    if d and d.get("status") == "decided":
                        d.update(status="review", status_at=now, reopened=now)
                        d.pop("snapshot", None)
                reopened.append(unit["label"])
            else:
                carried += 1
        r = st.setdefault("decided_review", {})
        r.update(answered_at=now, carried_on=carried, reopened=reopened)
        policy_state_save(st)
    policy_data(fresh=True)


# ============================================================
# THE FLOW (owner, 19 Nov 2026): the items past New Connections. One item
# is one collection of connections (a New Connections item's rows that need
# a rule change), kept in st["flow"] with a stable id, so its Claude
# conversation (refs), what was tried and its watch go with it:
#   review   Return (rows back to New Connections with their choices),
#            Show Me How (one set of Firewalla changes per item: split
#            first), I'm Doing This -> action
#   action   waiting to see the change in your rules -> confirm
#   confirm  watched: 24 h AND 10 connections (rarer traffic up to 7 days);
#            clean -> Decided by itself; traffic the opposite way -> NOT
#            WORKING; once your rules are back as before -> review, with
#            what was tried
# kind: chose (your Allow / Block), make_work (a violation's Make My Rule
# Work: your rule stays, the likely cause is fixed), internet (a device
# reaching a blocked country: the rule steps are given as words).
# Traffic counts come from the local traffic totals: what was added since
# the watch started (hourly rows only grow).
# ============================================================
def policy_counts_since(keys, since_hour):
    """{key: {"allowed", "blocked", "unreached", "tiny"}} for these connection
    keys in the hourly rows from since_hour; "unreached" = the blocked ones the
    router couldn't deliver (policy_unreached_row), part of "blocked"; "tiny" =
    the allowed ones under 2 KB per router record (the router's summary line
    after blocked tries, D-916), part of "allowed"."""
    flush_local_traffic()
    out = {k: {"allowed": 0, "blocked": 0, "unreached": 0, "tiny": 0} for k in keys}
    with local_traffic_connection() as connection:
        for src, dst in {tuple(k.split("|")[:2]) for k in keys}:
            for protocol, port, outcome, flows, unreached, tiny in connection.execute(
                    "SELECT protocol, port, outcome, SUM(COALESCE(starts, flows)),"
                    " SUM(CASE WHEN outcome = 'blocked' AND COALESCE(blocked_by, '') = '' AND bytes_sent + bytes_received = 0"
                    " THEN COALESCE(starts, flows) ELSE 0 END),"
                    " SUM(CASE WHEN outcome = 'allowed' AND bytes_sent + bytes_received <= ? * flows THEN COALESCE(starts, flows) ELSE 0 END)"
                    " FROM local_traffic_hourly WHERE src_mac=? AND dst_mac=? AND hour >= ? GROUP BY 1, 2, 3",
                    (ACCESS_SUMMARY_BYTES, src, dst, since_hour)):
                k = f"{src}|{dst}|{local_port_label(protocol, port)[0]}"
                if k in out and outcome in out[k]:
                    out[k][outcome] += flows or 0
                    out[k]["unreached"] += unreached or 0
                    out[k]["tiny"] += tiny or 0
    return out


def policy_flow_new(st, kind, keys, refs, title, now, stage="review", **extra):
    """A new item in the flow: its id."""
    fid = os.urandom(5).hex()
    st["flow"][fid] = {"id": fid, "kind": kind, "stage": stage, "keys": list(keys), "refs": list(dict.fromkeys(refs)),
                       "title": title, "created": now, "moved_at": now, "tried": [], **extra}
    return fid


def policy_message(st, now, text, undo=None):
    """A note at the top of the page; undo: {connection key: its Claude refs}
    for a New Connections Allow / Block (Undo for POLICY_UNDO_SECONDS)."""
    st["messages"] = [m for m in st["messages"] if now - m["at"] < POLICY_MESSAGE_SECONDS][-19:] + [
        {"at": now, "text": text, **({"undo": undo} if undo else {})}]


def policy_internet_done(f):
    """Does your rule set do an internet item's change yet? Block: the allow
    rule that let the device through is gone, or a block rule for the site
    covers the device. Allow: the country is now reached only through an
    allow rule of yours."""
    x = f.get("inet") or {}
    if x.get("mode") == "allow_country":
        return x.get("key") in {e["key"] for e in policy_internet["explained"]}
    rules = [r for r in (state.get("policy_rules") or {}).get("rules") or [] if r.get("disabled") is not True]
    if not any(str(r.get("pid")) == str(x.get("pid")) for r in rules):
        return True
    dest = str(x.get("dest") or "").lower()
    for r in rules:
        target = str(r.get("target") or "").lower().lstrip("*.")
        on = r.get("applies_on") or {}
        if (r.get("action") == "block" and target and (dest == target or dest.endswith("." + target))
                and (on.get("kind") == "all_devices" or str(on.get("id") or "").upper() == str(x.get("mac") or "").upper())):
            return True
    return False


def policy_internet_wrong(f, since):
    """An internet item's traffic the wrong way since <since>: connections."""
    x = f.get("inet") or {}
    if x.get("mode") == "allow_country":
        return sum(i["flows"] for i in policy_internet["items"] if i["key"] == x.get("key") and (i.get("last_seen") or 0) > since)
    return sum(r["flows"] for r in policy_internet.get("explained_rows") or []
               if r["mac"] == x.get("mac") and r["dest"] == x.get("dest") and (r.get("last_seen") or 0) > since)


def policy_howto_done(h):
    """Do your rules already do a Show Me How request (D-921)? Each port on
    its own: the rule checker tries only the first of a list."""
    from access import howto_plan
    for port in (h.get("port") or "").split(","):
        plan = howto_plan(h["act"], h["a"], h["b"], h.get("proto"), port, False)
        if not plan or not plan["directions"] or not plan["directions"][0].get("done"):
            return False
    return True


def policy_rule_done(f):
    """An Open But Unused item (owner, 19 Nov 2026): is the change in your
    rules yet? The rule (or port forward) gone, paused or edited, or the
    client no longer covered by it; or (D-921) your rules now block what its
    Show Me How request asks, whichever way you did it."""
    x = f.get("rule") or {}
    if f.get("howto"):
        try:
            if policy_howto_done(f["howto"]):
                return True
        except Exception as exc:
            print("Policy Show Me How check error:", exc)
    if str(x.get("id", "")).startswith("f|"):
        maps = (feature_settings.get("box") or {}).get("port_forward_maps") or []
        return not any(f"{m['proto']}|{m['port']}|{m['to_mac'] or m['to_ip']}" == x["id"][2:] and m.get("enabled") for m in maps)
    r = next((r for r in (state.get("policy_rules") or {}).get("rules") or [] if str(r.get("pid")) == str(x.get("pid"))), None)
    if not r or r.get("disabled") is True:
        return True
    # A Narrow It choice (D-920): done when each of its clients is off the
    # rule, or the rule (its target list) grants it no more than it keeps.
    # Judged from the rule itself: editing its target list doesn't change the rule.
    if x.get("macs") is not None:
        from access import open_unused_grants
        exact = open_unused_grants(r)[1]
        sides = access_sides()[0]
        keep = set(x.get("keep") or [])
        return all(not sides.get(m) or not access_covers(r.get("applies_on"), sides[m]) or (exact is not None and set(exact) <= keep)
                   for m in x["macs"])
    if str(r.get("updated_at") or r.get("created_at") or "") != str(x.get("sig") or ""):
        return True
    if x.get("mac"):
        side = access_sides()[0].get(x["mac"])
        return not side or not (access_covers(r.get("applies_on"), side) or (r.get("purpose") == "ap_allow" and access_covers(r.get("matching"), side)))
    return False


def policy_rules_judge():
    """-> a function: what your rules say ("allowed", "blocked", or None
    when it can't tell) for a connection key "src|dst|port" that has no
    traffic rows, by the same check a connection with traffic gets. The
    clients, groups and rules are read once, on first use."""
    ctx = {}

    def judge(key):
        src, _, rest = str(key).partition("|")
        dst, _, port_key = rest.partition("|")
        if not ctx:
            sides, groups = access_sides()
            ctx.update(sides={**access_peer_sides(), **sides}, groups=groups,
                       rules=access_local_rules() + access_address_rules(), iso=access_isolated())
        x, y = ctx["sides"].get(src), ctx["sides"].get(dst)
        if not x or not y:
            return None
        verdict = policy_verdict(check_local_access(x, y, ctx["groups"], ctx["rules"], port=policy_port_of(port_key), isolated=ctx["iso"]))
        return verdict if verdict in ("allowed", "blocked") else None
    return judge


def policy_flow_step(st, conns, now):
    """Moves the flow on by itself (every build). True when st changed."""
    decisions, changed = st["decisions"], False
    # Open But Unused items made before D-921 get their Show Me How request.
    for f in st["flow"].values():
        if f["kind"] == "rule" and not f.get("howto") and f["stage"] == "review" and str((f.get("rule") or {}).get("id", "")).startswith(("r|", "c|")):
            from access import open_unused_howto_for
            try:
                new = open_unused_howto_for(f["rule"])
                if new != f.get("howto"):
                    f["howto"], changed = new, True
            except Exception as exc:
                print("Policy Show Me How request error:", exc)
    # A choice waiting with no item of its own (the nightly review's reopen,
    # or one made before 19 Nov 2026): an item of its own.
    for key, d in list(decisions.items()):
        if d.get("status") in ("review", "rule_change", "confirm") and d.get("flow") not in st["flow"]:
            reopen = {"reopened": d["reopened"]} if d["status"] == "review" and d.get("reopened") else {}
            d["flow"] = policy_flow_new(st, "chose", [key], [key], d.get("label") or key, now,
                                        stage="review" if d["status"] == "review" else "action", **reopen)
            d["status"] = "review" if d["status"] == "review" else "rule_change"
            changed = True
    judge = policy_rules_judge()
    for fid, f in list(st["flow"].items()):
        keys = [k for k in f["keys"] if (decisions.get(k) or {}).get("flow") == fid and decisions[k].get("status") != "decided"]
        if not keys:
            del st["flow"][fid]
            changed = True
            continue
        if keys != f["keys"]:
            f["keys"], changed = keys, True
        intent = {k: decisions[k]["intent"] for k in keys}
        want = lambda k: "allowed" if intent[k] == "allow" else "blocked"
        if f["kind"] == "internet":
            done, live = policy_internet_done(f), True
        elif f["kind"] == "rule":
            done, live = policy_rule_done(f), True
        else:
            # What your rules say for each connection: from its traffic rows,
            # or, when it has none left in the 7 days kept, from the rule
            # checker itself (24 Nov 2026: without rows it could never count
            # as done, so the item waited in Pending Action for ever).
            says = {k: conns[k]["rules"] if k in conns else judge(k) for k in keys}
            known = [k for k in keys if says[k] in ("allowed", "blocked")]
            live = bool(known)
            done = live and all(says[k] == want(k) for k in known)
        status = lambda s: [decisions[k].update(status=s, status_at=now) for k in keys]
        # Reopened by the nightly review: in Review for you to decide again,
        # even though your rules already do what you chose (23 Nov 2026, D-908:
        # nine reopened at 03:00 went straight to Pending Confirmation, so you
        # never saw them and their watch began again). The same for one you
        # sent back from Pending Confirmation (D-917).
        if f["stage"] in ("review", "action") and done and f["kind"] != "make_work" and not (f["stage"] == "review" and (f.get("reopened") or f.get("sent_back"))):
            # Your rules now do it (with or without I'm Doing This).
            hour = int(now // 3600 * 3600)
            f.update(stage="confirm", moved_at=now, watch={"since": now, "hour": hour, "bad": False, "wrong": [],
                                                            "base": policy_counts_since(keys, hour) if f["kind"] not in ("internet", "rule") else {}})
            status("confirm")
            policy_message(st, now, f"{f['title']}: your rules now do it, so it moved to Pending Confirmation.")
            changed = True
            continue
        if f["stage"] != "confirm":
            continue
        w = f.setdefault("watch", {"since": f["moved_at"], "hour": int(f["moved_at"] // 3600 * 3600), "bad": False, "wrong": [], "base": {}})
        if not done and live:
            # Your rules are back as before (the undo, or another change).
            if w.get("bad"):
                f["tried"].append({"at": now, "way": (f.get("way") or {}).get("title") or "a rule change",
                                   "fix": (f.get("way") or {}).get("id"), "since": w["since"], "wrong": w.get("wrong") or []})
                text = f"{f['title']}: your rules are back as before, so it is back in Review with what was tried."
            else:
                text = f"{f['title']}: your rules changed back, so it is back in Review."
            f.update(stage="review", moved_at=now)
            f.pop("watch", None)
            status("review")
            policy_message(st, now, text)
            changed = True
            continue
        # The watch: connections since it started, the right way and the wrong way.
        if f["kind"] == "internet":
            wrong_n = policy_internet_wrong(f, w["since"])
            right_n, rows = 0, ([{"key": keys[0], "right": 0, "wrong": wrong_n}] if wrong_n else [])
        elif f["kind"] == "rule":
            right_n, wrong_n, rows = 0, 0, []   # the access is gone: nothing left to go the wrong way
        else:
            counts = policy_counts_since(keys, w["hour"])
            rows = []
            for k in keys:
                base = (w.get("base") or {}).get(k) or {"allowed": 0, "blocked": 0}
                n = {o: max(0, counts[k][o] - base.get(o, 0)) for o in ("allowed", "blocked", "unreached", "tiny")}
                # A try the router couldn't deliver (the device off or off the
                # network) isn't traffic going the wrong way for an Allow
                # (owner, 23 Nov 2026, D-906). For a Block, the router's summary
                # line (only small allowed records, beside blocked tries now or
                # before) is blocked tries, not traffic let through (D-916).
                summary = (want(k) == "blocked" and n["allowed"] and n["tiny"] >= n["allowed"]
                           and (n["blocked"] or (conns.get(k) or {}).get("blocked_flows")))
                if summary:
                    n["blocked"], n["allowed"] = n["blocked"] + n["allowed"], 0
                wrong = n["allowed"] if want(k) == "blocked" else max(0, n["blocked"] - n["unreached"])
                rows.append({"key": k, "right": n[want(k)], "wrong": wrong})
            right_n, wrong_n = sum(r["right"] for r in rows), sum(r["wrong"] for r in rows)
        watched = now - w["since"]
        new = {"right": right_n, "wrong_n": wrong_n}
        if not wrong_n and w.get("bad"):
            # Marked Not Working on traffic since counted another way (the
            # router's summary line, D-916): back to watching.
            new.update(bad=False, bad_at=None)
            policy_message(st, now, f"{f['title']}: what looked like the wrong way was the router's summary line after blocked tries, so it is watched again.")
        if wrong_n and not w.get("bad"):
            new["bad"] = True
            new["bad_at"] = now
            policy_message(st, now, f"{f['title']}: NOT WORKING: traffic went the other way since the change.")
        new["wrong"] = [r for r in rows if r["wrong"]]
        if any(w.get(k) != v for k, v in new.items()):
            w.update(new)
            changed = True
        clean = not w.get("bad") and ((watched >= POLICY_WATCH_SECONDS and (right_n >= POLICY_WATCH_CONNECTIONS or f["kind"] in ("internet", "rule")))
                                       or watched >= POLICY_WATCH_MAX_SECONDS)
        if clean:
            note = ("no traffic seen since the change" if not right_n and f["kind"] not in ("internet", "rule")
                    else f"watched {round(watched / 3600)} h, nothing went the wrong way" if f["kind"] in ("internet", "rule")
                    else f"watched {round(watched / 3600)} h, {right_n} connections as expected")
            for k in keys:
                d = decisions[k]
                decisions[k] = {**policy_done(d, d["intent"], "flow:" + fid, d.get("label") or k, now),
                                **{x: d[x] for x in ("why", "refs", "picked_at") if x in d},
                                "how": "make_work" if f["kind"] == "make_work" else "changed", "watch": note,
                                "refs": f["refs"] + ["flow:" + fid], "tried": f["tried"]}
            del st["flow"][fid]
            policy_message(st, now, f"{f['title']}: {note}. Moved to Decided.")
            changed = True
    return changed


# The likely cause of a violation, for its card and Make My Rule Work
# (owner, 19 Nov 2026). Only what the dashboard can name from your rules
# and the router's records; else None (then Ask Claude or the Access Test).
def policy_ips_placed(found, src_mac, dst_mac, sides):
    """[source addresses, dest addresses, crossed]: each address the router
    recorded, put with the device it belongs to. The router's record can pair
    them the other way round from the devices (owner, 22 Nov 2026: NAS ->
    PC B TCP 445 blocked, recorded with the PC's 192.168.6.51 as the
    source): crossed = True then, and which side started it is in doubt."""
    def known(mac):
        x = sides.get(mac) or {}
        return set(x.get("ips") or []) | ({x["ip"]} if x.get("ip") else set())
    mine, theirs = known(src_mac), known(dst_mac)
    out, crossed = [set(), set()], False
    for side, ips in enumerate(found):
        for ip in ips:
            to = 0 if ip in mine and ip not in theirs else 1 if ip in theirs and ip not in mine else side
            crossed = crossed or to != side
            out[to].add(ip)
    return [sorted(out[0]), sorted(out[1]), crossed]


# ------------------------------------------------------------
# QUIET THIS PATTERN (owner, 22 Nov 2026): a Got Blocked violation known to
# be harmless and expected to repeat. Its fingerprint: the two clients
# (either way round: the router's record can be crossed), the port, the
# rule the router named (or none), no data moved, and at most
# POLICY_QUIET_MAX_DAY tries in 24 hours. A repeat that fits all of it is
# recorded under the pattern; anything else is a violation as before. Each
# pattern asks for a check-in after POLICY_QUIET_REVIEW_DAYS (it keeps
# matching meanwhile); Stop Quieting ends it. Kept in the Policy state
# ("quiet_patterns"; an old "quiet" entry there is something else), the last POLICY_QUIET_KEEP_MATCHES matches each.
# ------------------------------------------------------------
POLICY_QUIET_MAX_DAY = 5
POLICY_QUIET_REVIEW_DAYS = 30
POLICY_QUIET_KEEP_MATCHES = 50


def policy_quiet_named(pairs):
    """The rules the router named for these pairs' blocked tries."""
    return sorted({str(x)[5:] for p in pairs for x in p.get("blocked_by") or () if str(x).startswith("rule:")})


def policy_quiet_match(st, c, pairs, now):
    """True (and the match recorded) when these blocked tries fit a quieted pattern."""
    named = policy_quiet_named(pairs)
    moved = sum(r["bytes"] for p in pairs for r in p.get("rows") or [] if r.get("outcome") == "blocked")
    for q in (st.get("quiet_patterns") or {}).values():
        if (q["kind"] == "blocked" and q["port_key"] == c["port_key"] and q["rules"] == named and not moved
                and all({p["src"]["mac"], p["dst"]["mac"]} == set(q["pair"]) for p in pairs)
                and (c.get("blocked_24h") or 0) <= q.get("max_day", POLICY_QUIET_MAX_DAY)):
            newest = max(p["last_blocked"] for p in pairs)
            if newest > (q.get("last_at") or 0):
                q["matches"] = (q.get("matches") or [])[-(POLICY_QUIET_KEEP_MATCHES - 1):] + [
                    {"at": newest, "tries": sum(p["blocked_flows"] for p in pairs), "tries_24h": c.get("blocked_24h") or 0}]
                q["match_count"] = (q.get("match_count") or 0) + 1
                q["last_at"] = newest
            return True
    return False


def policy_quiet_new(st, r, v, now):
    """A quieted pattern from a Got Blocked violation (its review row r, card v)."""
    pairs = r.get("violation_pairs") or []
    won = [x["pid"] for x in ((v.get("rules") or {}).get("rows") or []) if x.get("result") == "won" and x.get("pid")]
    macs = sorted({m for p in pairs for m in (p["src"]["mac"], p["dst"]["mac"])})
    qid = f"q{int(now)}"
    q = st.setdefault("quiet_patterns", {})[qid] = {
        "id": qid, "created": now, "review_at": now + POLICY_QUIET_REVIEW_DAYS * 86400, "kind": "blocked",
        "pair": macs[:2], "names": sorted({n for p in pairs for n in (p["src"]["name"], p["dst"]["name"])}),
        "port_key": r.get("port_key"), "port": r.get("port"), "rules": sorted(won),
        "rule_text": [x["text"] for x in ((v.get("rules") or {}).get("rows") or []) if x.get("result") == "won"],
        "max_day": POLICY_QUIET_MAX_DAY, "matches": [], "match_count": 0, "last_at": max((p["last_seen"] for p in pairs), default=now),
        "title": v["title"]}
    return q


def policy_quiet_rows(st, now):
    """The Violations page's Quieted Patterns, newest first."""
    rows = []
    for q in (st.get("quiet_patterns") or {}).values():
        rows.append({**{k: q.get(k) for k in ("id", "title", "names", "port", "rules", "rule_text", "max_day", "created",
                                               "review_at", "match_count", "last_at")},
                     "matches": (q.get("matches") or [])[-10:], "due": now >= (q.get("review_at") or 0)})
    rows.sort(key=lambda x: -(x["created"] or 0))
    return rows


@app.post("/api/policy/quiet")
def api_policy_quiet(payload: dict = Body(default={})):
    """A quieted pattern ({id, action}): stop (Stop Quieting: its repeats
    are violations again) or renew (Keep Quieting: the next check-in in
    POLICY_QUIET_REVIEW_DAYS)."""
    f_ = Fields(payload)
    qid, action = f_.text("id", 40, strip=False), f_.choice("action", ("stop", "renew"))
    with policy_lock:
        st = policy_state_load()
        q = (st.get("quiet_patterns") or {}).get(qid)
        if not q or not action:
            return {"ok": False, "error": "That pattern is gone."}
        now = time.time()
        if action == "stop":
            del st["quiet_patterns"][qid]
            msg = f"{q['title']}: no longer quieted. Its next tries come to Violations."
        else:
            q["review_at"] = now + POLICY_QUIET_REVIEW_DAYS * 86400
            msg = f"{q['title']}: still quieted. Next check-in in {POLICY_QUIET_REVIEW_DAYS} days."
        policy_message(st, now, msg)
        policy_state_save(st)
        policy_data(fresh=True)
    return {"ok": True, "message": msg}


def policy_rules_table(p, kind):
    """What Overrode It? as a table (owner, 22 Nov 2026): every rule and
    setting between the pair, rules in Firewalla's order (Device/Group,
    Network, All Devices; Allow before Block), then VqLAN and Isolation.
    Each says what it did: won (the rule the router named), expected to win
    (what the order says should win, when the router named another), lifted
    by (a VqLAN or Isolation an Allowed Devices entry opens), not applied
    (same network: the router never sees it), or applies, doesn't decide."""
    raw = p.get("blocked_by") if kind == "blocked" else p.get("allowed_by")
    named = [str(x)[5:] if str(x).startswith("rule:") else str(x) for x in raw or ()
             if kind != "blocked" or str(x).startswith("rule:")]
    expected = str((p.get("deciding") or {}).get("pid") or "")
    rows, n, seen = [], 0, set()
    steps = p.get("steps") or []
    for st in [x for x in steps if x.get("kind") == "rule"]:
        n += 1
        pid = str(st.get("pid") or "")
        seen.add(pid)
        result = ("won" if pid in named else "expected" if pid == expected and named
                  else "not_applied" if st.get("not_applied") else "applies")
        rows.append({"order": n, "pid": pid, "text": st.get("text"), "on": st.get("on"), "level": st.get("level"),
                     "action": st.get("effect"), "result": result})
    for pid in [x for x in named if x not in seen]:
        # The router named a rule the dashboard didn't match to this pair.
        r = policy_rule_for_pid(pid)
        n += 1
        rows.append({"order": n, "pid": pid, "text": access_rule_text(r) if r else f"Rule {pid}",
                     "on": ((r or {}).get("applies_on") or {}).get("label"), "level": None,
                     "action": (r or {}).get("action"), "result": "won", "unmatched": True})
    for st in [x for x in steps if x.get("kind") in ("vqlan", "isolation")]:
        text = st.get("text") or ""
        on = (f"Group: {text.split(' on ', 1)[1]}" if st["kind"] == "vqlan" and " on " in text
              else f"Group: {text.split(' in ', 1)[1]}" if " in " in text
              else f"Device: {text.split(' on ', 1)[1]}" if " on " in text else None)
        rows.append({"order": None, "pid": None, "text": text, "on": on, "level": "group" if on and on.startswith("Group") else "device",
                     "action": "block", "result": "lifted" if st.get("lifted_by") else "applies",
                     "lifted_by": str(st.get("lifted_by") or "")})
    won = next((x for x in rows if x["result"] == "won"), None)
    return {"rows": rows, "named": bool(named), "against_order": bool(won and expected and won["pid"] != expected)}


def policy_blocked_what(r):
    """A got-blocked violation's line. When the router named a block rule
    and nothing this way got through, it says what the router does (owner,
    22 Nov 2026: NAS DS923+ Main -> PC B TCP 445, blocked by #829 though
    Allowed Devices #858 looked like it allows it)."""
    violated = "; ".join(r.get("policy_violated") or []) or "your rules"
    named = [x for x in r.get("overridden_by") or [] if x.startswith("#")]
    pairs = r.get("violation_pairs") or []
    if named and pairs and not any(p["allowed_flows"] for p in pairs):
        return (f"The router blocks connections {r['src']['name']} starts to {r['dst']['name']} on {r['port']} "
                f"({'; '.join(named)}), although your rules looked like {violated} allows it.")
    return f"Your rules allow this ({violated}), but the router blocked some."


def policy_violation_cause(kind, pairs, sides):
    named = " ".join(x for p in pairs for x in (p["blocked_by"] if kind == "blocked" else p["allowed_by"])).lower()
    if kind == "blocked" and ("active protect" in named or "alarm" in named or "intel" in named):
        return {"id": "active_protect", "text": "Active Protect blocked it: its alarm rules beat every allow rule",
                "steps": ["Firewalla app › Alarms: find the alarm for these two clients and choose Allow (or Mute) for it, so its block rule goes",
                          "Or Rules: find the block rule the alarm made (it names these clients) and delete it"]}
    if kind == "blocked" and not named:
        p = pairs[0]
        a, b = sides.get(p["src"]["mac"]) or {}, sides.get(p["dst"]["mac"]) or {}
        # Mostly through: the rule works, the few blocked are tries the router
        # couldn't deliver (owner, 22 Nov 2026). Nothing to make work.
        if sum(x["allowed_flows"] for x in pairs) >= sum(x["blocked_flows"] for x in pairs):
            dst = b.get("name") or p["dst"]["name"]
            return {"id": "offline", "fixable": False,
                    "text": f"Most of these got through, so your rule works: the blocked ones are likely tries while {dst} was "
                            f"offline (the router logs those as blocked, naming no rule)",
                    "steps": [f"Clients › Offline lists {dst} while it is offline; Settings › Offline Email Warnings can email you when it is",
                              f"If {dst} drops off often, look at its Wi-Fi signal and access point"]}
        if "wifi" in (a.get("link"), b.get("link")):
            return {"id": "ap7_local", "text": "An allow rule between your own clients may not take effect on AP7 Wi-Fi (Firewalla's own note)",
                    "steps": [f"Firewalla app › {b.get('name') or p['dst']['name']} (or its group) › Allowed Devices › Add Device: {a.get('name') or p['src']['name']}",
                              "Allowed Devices works both ways and is what the access points enforce; your allow rule can stay"]}
    return None


def policy_explained_rows(st, decisions, now):
    """New Connections' internet rows (owner, 19 Nov 2026): a device reaching
    a site in a blocked country only through your own allow rule, one row per
    device and site, until decided (or deleted, until it is seen again)."""
    out = {}
    for r in policy_internet.get("explained_rows") or []:
        key = f"inet|{r['mac']}|{r['dest']}"
        if key in decisions or (r.get("last_seen") or 0) <= max(st["since"], st["removed"].get(key, 0)):
            continue
        if policy_paused_only(st, key, r.get("first_seen"), r.get("last_seen")):
            continue   # Seen only while monitoring was stopped (D-919).
        out.setdefault(f"inet|{r['mac']}|{r['country']}", []).append({**r, "key": key})
    return out


def policy_ports_for_howto(port_key):
    """A connection's port as Show Me How's proto and port (None = any)."""
    proto, ports = policy_own_port(port_key)
    return (proto if proto in ("tcp", "udp") else None), (ports if proto in ("tcp", "udp") and ports != "any" else None)


def policy_sets(rows):
    """A Review item's rows by the set of Firewalla changes they need: one
    action and one port, with exactly the device pairs asked for (one source
    to its targets, or the sources to one target, else per source)."""
    srcs = {r["src"]["mac"] for r in rows}
    dsts = {r["dst"]["mac"] for r in rows}
    sets = {}
    for r in rows:
        key = (r["act"], r["port_key"], r["src"]["mac"] if len(srcs) > 1 and len(dsts) > 1 else "")
        sets.setdefault(key, []).append(r)
    out = []
    for (act, port_key, _), part in sets.items():
        proto, port = policy_ports_for_howto(port_key)
        out.append({"act": act, "keys": [r["key"] for r in part], "proto": proto, "port": port, "port_label": part[0]["port"],
                    "a": ",".join(dict.fromkeys("d:" + r["src"]["mac"] for r in part)),
                    "b": ",".join(dict.fromkeys("d:" + r["dst"]["mac"] for r in part)),
                    "nodev": all(not re.search(":", str(r["dst"]["mac"])) for r in part)})
    return out


def policy_page(st, conns, triage, patterns, review, decided, now):
    """The Policy page as it shows (owner, 19 Nov 2026): New Connections
    items, the flow's items per stage, and Violations."""
    decisions = st["decisions"]
    word = {"allowed": "Allow", "blocked": "Block"}

    def row_of(c, **extra):
        return {"key": c["key"], "src": c["src"], "dst": c["dst"], "port": c["port"], "port_key": c["port_key"],
                "rule": word.get(c["rules"], "Unclear"), "blocked": c["blocked_flows"], "allowed": c["allowed_flows"],
                "last_seen": c["last_seen"], **extra}

    def title_of(rows):
        srcs = list(dict.fromkeys(r["src"]["name"] for r in rows))
        dsts = list(dict.fromkeys(r["dst"]["name"] for r in rows))
        nodev = all(not re.search(":", str(r["dst"].get("mac") or "")) for r in rows)
        return (srcs[0] if len(srcs) == 1 else f"{len(srcs)} clients") + " → " + (
            dsts[0] if len(dsts) == 1 else f"{len(dsts)} {'addresses' if nodev else 'devices'}")

    carried = lambda keys: [ref for k in keys for ref in st["nc_refs"].get(k) or []]
    new_items = []
    # A connection is one source to one target on a set of ports. A
    # connection group is the same source and target with every port they
    # are using among the new connections, a row each. A group is only
    # ever one source and one target (owner, 20 Nov 2026: each port used
    # to be an item of its own, and look-alike connections of several
    # devices were bundled into pattern groups). One port: the connection
    # by itself.
    same_pair = {}
    for c in triage:
        same_pair.setdefault((c["src"].get("mac") or c["src"]["name"], c["dst"].get("mac") or c["dst"]["name"]), []).append(c)
    for (src, dst), cards in same_pair.items():
        if len(cards) == 1:
            c = cards[0]
            new_items.append({"id": c["key"], "tag": "", "title": title_of([c]), "group": False, "first": c["first_seen"],
                              "last": c["last_seen"], "why": c.get("why"), "rows": [row_of(c, pick=st["row_picks"].get(c["key"]))],
                              "refs": [c["key"]] + carried([c["key"]])})
            continue
        cards.sort(key=lambda c: -(c["last_seen"] or 0))
        keys = [c["key"] for c in cards]
        new_items.append({"id": f"pair:{src}|{dst}", "tag": "Connection Group", "title": title_of(cards), "group": True,
                          "first": min(c["first_seen"] or c["last_seen"] or now for c in cards), "last": max(c["last_seen"] or 0 for c in cards),
                          "why": policy_why(cards), "rows": [row_of(c, pick=st["row_picks"].get(c["key"])) for c in cards],
                          "refs": [f"pair:{src}|{dst}"] + keys + carried(keys)})
    # A device reaching a blocked country through your own allow rule.
    for item_id, rows in policy_explained_rows(st, decisions, now).items():
        r0 = rows[0]
        new_items.append({"id": item_id, "tag": "", "title": f"{r0['name']} → {rows[0]['dest'] if len(rows) == 1 else str(len(rows)) + ' sites'} ({r0['country']})",
                          "group": len(rows) > 1, "internet": True, "first": min(r.get("first_seen") or r["last_seen"] for r in rows),
                          "last": max(r["last_seen"] for r in rows),
                          "why": {"title": "Why Might This Be Needed?", "lines": [
                              {"tag": "Known", "text": f"{r0['country']} is a blocked country: this got through only because your allow rule "
                                                       f"\"{r0['allowed_by']['text']}\" lets it", "check": ""}]},
                          "rows": [{"key": r["key"], "src": {"mac": r["mac"], "name": r["name"]}, "dst": {"mac": "", "name": f"{r['dest']} ({r['country']})"},
                                    "port": r.get("port") or "--", "port_key": "", "rule": "Allow", "blocked": 0, "allowed": r["flows"],
                                    "last_seen": r["last_seen"], "pick": st["row_picks"].get(r["key"])} for r in rows],
                          "refs": [item_id]})
    new_items.sort(key=lambda x: (not x["group"], -(x["last"] or 0)))

    # The flow's items.
    howto_changes = {c["id"]: c for c in (policy_read_json(HOWTO_FILE) or {}).get("changes") or []}
    flow_items = []
    review_by_key = {r["key"]: r for r in review if r.get("kind") == "conflict"}
    for fid, f in st["flow"].items():
        rows = []
        for k in f["keys"]:
            d = decisions.get(k) or {}
            c = conns.get(k) or review_by_key.get(k) or (d.get("snapshot") or None)
            act = "Allow" if d.get("intent") == "allow" else "Block"
            if c:
                rows.append(row_of(c, act=act))
            elif d.get("rule"):
                x = d["rule"]
                rows.append({"key": k, "src": {"mac": "", "name": x["rule"]}, "dst": {"mac": "", "name": x["what"]}, "port": x["grants"], "port_key": "",
                             "rule": "Allow", "blocked": 0, "allowed": 0, "last_seen": None, "act": x.get("act") or act})
            elif d.get("inet"):
                x = d["inet"]
                rows.append({"key": k, "src": {"mac": x["mac"], "name": x["name"]}, "dst": {"mac": "", "name": f"{x['dest']} ({x['country']})"},
                             "port": x.get("port") or "--", "port_key": "", "rule": "Allow", "blocked": 0, "allowed": x.get("flows", 0),
                             "last_seen": x.get("last_seen"), "act": act})
        if not rows:
            continue
        w = f.get("watch") or {}
        wrong = []
        for r in w.get("wrong") or []:
            row = next((x for x in rows if x["key"] == r["key"]), None)
            if row:
                wrong.append({"dst": row["dst"]["name"], "port": row["port"], "wrong": r["wrong"], "right": r["right"],
                              "act": row["act"], "last": row["last_seen"]})
        change = howto_changes.get(f.get("change")) or {}
        why = policy_why([conns[k] for k in f["keys"] if k in conns]) if f["kind"] != "internet" else f.get("why")
        flow_items.append({
            "id": fid, "ref": "flow:" + fid, "stage": f["stage"], "kind": f["kind"], "title": f["title"], "created": f["created"],
            "moved_at": f["moved_at"], "rows": rows, "refs": f["refs"] + ["flow:" + fid], "tried": f["tried"], "reopened": f.get("reopened"), "sent_back": f.get("sent_back"),
            "why": why, "way": f.get("way"), "cause": f.get("cause"), "steps": f.get("steps"), "howto": f.get("howto"),
            "plan": policy_internet_plan(f["inet"]) if (f.get("inet") or {}).get("mode") == "block_dest" else policy_rule_plan(f),
            "sets": policy_sets(rows) if f["kind"] == "chose" else [],
            "undo": change.get("undo") or f.get("undo") or [],
            # The whole saved steps (owner, 23 Nov 2026), for ▸ Steps and Print Steps on the card.
            "change_steps": [{**{k: s.get(k) for k in HOWTO_STEP_KEYS if s.get(k) is not None}, "title": s.get("title"), "seen": howto_seen(s["watch"])}
                             for s in change.get("steps") or []] if change and f["stage"] == "action" else [],
            "watch": {"since": w.get("since"), "right": w.get("right", 0), "wrong_n": w.get("wrong_n", 0), "bad": bool(w.get("bad")),
                      "bad_at": w.get("bad_at"), "wrong": wrong, "need_connections": POLICY_WATCH_CONNECTIONS,
                      "need_seconds": POLICY_WATCH_SECONDS, "max_seconds": POLICY_WATCH_MAX_SECONDS, "internet": f["kind"] in ("internet", "rule")} if f["stage"] == "confirm" else None})
    flow_items.sort(key=lambda x: -(x["moved_at"] or 0))

    # Violations.
    violations = []
    for r in review:
        if r.get("kind") in ("through", "blocked"):
            violations.append({
                "item": r["item"], "kind": r["kind"], "title": f"{r['src']['name']} → {r['dst']['name']}", "when": r.get("violation_last"),
                "what": (f"Your rules block this ({'; '.join(r.get('policy_violated') or []) or 'your rules'}), but the router let some through."
                         if r["kind"] == "through" else policy_blocked_what(r)),
                "overridden_by": r.get("overridden_by") or [], "cause": r.get("cause"), "refs": [r["item"], r["key"]],
                "rules": r.get("violation_rules"), "earlier": r.get("earlier") or [],
                "rows": [{"rule": "Block" if r["kind"] == "through" else "Allow", "src": p["src"]["name"], "dst": p["dst"]["name"], "port": r["port"],
                          "allowed": p["allowed_flows"], "blocked": p["blocked_flows"], "last": p["last_seen"],
                          # The addresses of the traffic that broke the rule (blocked tries, or what got through).
                          "src_ip": ", ".join(((p.get("ips") or {}).get("allowed" if r["kind"] == "through" else "blocked") or [[], []])[0]),
                          "dst_ip": ", ".join(((p.get("ips") or {}).get("allowed" if r["kind"] == "through" else "blocked") or [[], []])[1]),
                          "ips_crossed": bool((((p.get("ips") or {}).get("allowed" if r["kind"] == "through" else "blocked") or [[], [], False]) + [False])[2])}
                         for p in r.get("violation_pairs") or []],
                "flows": r.get("violation_flows") or 0, "live": r.get("live")})
        elif r.get("kind") == "internet":
            violations.append({
                "item": r["item"], "kind": "through", "internet": True, "title": f"Country {r['country']} reached", "when": r.get("last_seen"),
                "what": f"Your country block ({'; '.join(r.get('policy_violated') or [])}) covers these clients, but {r['flows']:,} connections got through with no allow rule of yours.",
                "overridden_by": r.get("overridden_by") or [], "cause": None, "refs": [r["item"]], "steps": r.get("steps") or [],
                "rows": [{"rule": "Block", "src": d["name"], "dst": ", ".join((r.get("destinations") or [])[:3]) or "--", "port": "--",
                          "allowed": d["flows"], "blocked": 0, "last": r.get("last_seen")} for d in (r.get("devices") or [])[:10]],
                "flows": r.get("flows") or 0, "live": r.get("live")})
    violations.sort(key=lambda v: -(v["when"] or 0))
    st_messages = [m for m in st["messages"] if now - m["at"] < POLICY_MESSAGE_SECONDS]
    return {"new": new_items, "flow": flow_items, "violations": violations, "messages": st_messages[-5:],
            "decided_count": policy_decided_total(st), "quiet": policy_quiet_rows(st, now)}


POLICY_UNDO_SECONDS = 60   # how long a New Connections Allow / Block can be undone


@app.post("/api/policy/decide")
def api_policy_decide(payload: dict = Body(default={})):
    """New Connections' Allow / Block ({item, keys, pick}) and Concur /
    Non-Concur ({picks: [{item, keys, pick}, ...]}: the rows ticked across
    every card, owner 25 Nov 2026, D-1071): the rows are decided at once
    (owner, 24 Nov 2026, D-1066: Move to Review is gone). Each row is its own
    decision. A row whose pick your rules already do goes to Decided; a row
    to a no-device address the router blocked every try of, picked Block, is
    Decided as blocked; the rest go to Review: one Review item per source and
    target, joining the one already in Review (an internet item: one Review
    item per site). Rows not picked stay. One note and one Undo for the lot."""
    parts = payload.get("picks") if isinstance(payload.get("picks"), list) else [payload]
    parts = [p for p in parts[:200] if isinstance(p, dict)]
    if not parts or any(p.get("pick") not in ("allow", "block") for p in parts):
        return {"ok": False, "error": "Unknown choice"}
    with policy_lock:
        data = policy_data()
        st = policy_state_load()
        now = time.time()
        cards = {c["key"]: c for c in data["triage"]}
        undo, names, decided, to_review = {}, [], 0, 0
        for p in parts:
            f_ = Fields(p)
            item_id, pick = f_.text("item", 300, strip=False), p["pick"]
            item = next((x for x in data["page"]["new"] if x["id"] == item_id), None)
            wanted = set(f_.strings("keys", 400, 300))
            rows = [r for r in (item or {}).get("rows") or [] if r["key"] in wanted and r["key"] not in undo]
            done = policy_decide_rows(st, cards, item, rows, pick, now) if rows else None
            if done:
                undo.update(done[0])
                names.append(done[1])
                decided += done[2]
                to_review += done[3]
        if not undo:
            return {"ok": False, "error": "That connection is gone (decided or quiet for 7 days)." if len(parts) == 1
                    else "Those connections are gone (decided or quiet for 7 days)."}
        name = names[0] if len(names) == 1 else f"{len(undo)} connections"
        text = name + ": " + ", ".join(x for x in (f"{decided} to Decided" if decided else "", f"{to_review} to Review" if to_review else "") if x) + "."
        policy_message(st, now, text, undo=undo)
        policy_state_save(st)
        policy_data(fresh=True)
    return {"ok": True, "message": text}


def policy_decide_rows(st, cards, item, rows, pick, now):
    """One New Connections item's rows, all picked the same way (see
    api_policy_decide). Returns (undo, name, to Decided, to Review), or None
    when none of the rows is there any more."""
    undo = {r["key"]: st["nc_refs"].get(r["key"]) or [] for r in rows}
    change, decided = [], 0
    for r in rows:
        k, c = r["key"], cards.get(r["key"])
        label = f"{r['src']['name']} → {r['dst']['name']} · {r['port']}"
        keep = {"at": now, "label": label, "status": "decided", "why": item.get("why"), "refs": item["refs"], "picked_at": now}
        if item.get("internet"):
            x = next((e for e in policy_internet.get("explained_rows") or [] if f"inet|{e['mac']}|{e['dest']}" == k), None)
            if not x:
                undo.pop(k, None)
                continue
            if pick == "block":
                change.append((k, {"mac": x["mac"], "name": x["name"], "dest": x["dest"], "country": x["country"],
                                   "pid": x["allowed_by"]["pid"], "rule": x["allowed_by"]["text"], "flows": x["flows"],
                                   "last_seen": x["last_seen"], "port": x.get("port")}))
            else:
                st["decisions"][k] = {**keep, "intent": "allow", "kind": "keep", "inet": {"dest": x["dest"], "country": x["country"],
                                      "name": x["name"], "mac": x["mac"], "rule": x["allowed_by"]["text"]}}
                decided += 1
        elif not c:
            undo.pop(k, None)
            continue
        elif c["rules"] == ("allowed" if pick == "allow" else "blocked"):
            st["decisions"][k] = {**keep, "intent": pick, "kind": "keep"}
            decided += 1
        elif pick == "block" and POLICY_PATTERN_IP.match(str(c["dst"]["mac"])) and c["reality"] == "blocked":
            # No device answers there, so no rule can be made: Decide As
            # Blocked is automatic (owner, 19 Nov 2026).
            st["decisions"][k] = {**keep, "intent": "block", "kind": "nodev"}
            decided += 1
        else:
            change.append((k, None))
        st["row_picks"].pop(k, None)
        st["nc_refs"].pop(k, None)
    if not undo:
        return None
    row_of = {x["key"]: x for x in item["rows"]}
    first = row_of[next(iter(undo))]
    name = f"{first['src']['name']} → {first['dst']['name']}" + (f" · {first['port']}" if len(undo) == 1 else "")
    if change:
        kind = "internet" if item.get("internet") else "chose"
        # An internet item becomes one Review item per site, each with
        # its own site and rule (24 Nov 2026: one item carried only the
        # first site, so once that was blocked the others were filed as
        # blocked too, without being blocked).
        parts = [[x] for x in change] if kind == "internet" else [change]
        pair = [first["src"].get("mac") or first["src"]["name"], first["dst"].get("mac") or first["dst"]["name"]]
        for part in parts:
            r0 = row_of[part[0][0]]
            fid = None if kind == "internet" else next(
                (i for i, f in st["flow"].items() if f["stage"] == "review" and f["kind"] == "chose" and f.get("pair") == pair), None)
            if fid:
                f = st["flow"][fid]
                f["keys"] += [k for k, _ in part if k not in f["keys"]]
                f["refs"] = list(dict.fromkeys(f["refs"] + item["refs"]))
                f["moved_at"] = now
            else:
                title = item["title"] if len(parts) == 1 else f"{r0['src']['name']} → {r0['dst']['name']}"
                fid = policy_flow_new(st, kind, [k for k, _ in part], item["refs"], title, now,
                                      why=item.get("why") if kind == "internet" else None,
                                      **({"inet": {"mode": "block_dest", **part[0][1]}} if kind == "internet" else {"pair": pair}))
            for k, inet in part:
                r = row_of[k]
                st["decisions"][k] = {"intent": pick, "at": now, "label": f"{r['src']['name']} → {r['dst']['name']} · {r['port']}",
                                      "kind": "chose", "status": "review", "status_at": now, "flow": fid, "why": item.get("why"),
                                      "picked_at": now, **({"inet": inet} if inet else {})}
    return undo, name, decided, len(change)


@app.post("/api/policy/undo")
def api_policy_undo(payload: dict = Body(default={})):
    """Undo on a New Connections Allow / Block note ({at}: the note's time),
    within POLICY_UNDO_SECONDS: its rows go back to New Connections with no
    choice, out of Decided or out of their Review item (owner, 24 Nov 2026,
    D-1066). A row that has moved on since (past Review) stays where it is."""
    try:
        at = float(payload.get("at"))
    except (TypeError, ValueError):
        return {"ok": False, "error": "Nothing to undo."}
    with policy_lock:
        st = policy_state_load()
        now = time.time()
        m = next((x for x in st["messages"] if x["at"] == at and x.get("undo")), None)
        if not m or now - at > POLICY_UNDO_SECONDS:
            return {"ok": False, "error": "Too late to undo: Delete it from Decided, or Return it from Review."}
        back = 0
        for k, refs in m["undo"].items():
            d = st["decisions"].get(k) or {}
            if d.get("picked_at") != at:
                continue
            if d.get("status") == "review":
                f = st["flow"].get(d.get("flow")) or {}
                if f.get("stage") != "review":
                    continue
                f["keys"] = [x for x in f["keys"] if x != k]
                if not f["keys"]:
                    del st["flow"][d["flow"]]
            elif d.get("status") != "decided":
                continue
            del st["decisions"][k]
            if refs:
                st["nc_refs"][k] = refs
            back += 1
        m.pop("undo")
        text = f"Undone: {back} back in New Connections." if back else "Nothing to undo: it has moved on."
        policy_message(st, now, text)
        policy_state_save(st)
        policy_data(fresh=True)
    return {"ok": True, "message": text}


def policy_internet_plan(x):
    """Show Me How for blocking a site a device reaches through your allow
    rule, in Show Me How's own shape (one direction, one way, its steps with
    the MSP and phone app look-alikes and their real screens), so the Policy
    panel draws it like any plan (owner, 19 Nov 2026). Its planner is for
    your own devices; this rule is on the device itself, so nothing else
    changes."""
    r = policy_rule_for_pid(x["pid"]) or {}
    on = r.get("applies_on") or {}
    # (Rule names: at most 32 characters; a long site name keeps its last three parts.)
    name = f"Block {x['dest']}" if len(x["dest"]) <= 26 else f"Block {'.'.join(x['dest'].split('.')[-3:])}"[:32]
    if str(on.get("id") or "").upper() == str(x["mac"]).upper():
        step = {"title": f"Delete or narrow your allow rule \"{x['rule']}\" on {x['name']}",
                "msp": {"path": ["Rules", x["rule"]], "fields": [["Rule", x["rule"], None], ["On", x["name"], None]]},
                "note": f"Delete it, or change it so it no longer covers {x['dest']}: your country block then covers {x['name']} again.",
                "picture": "msp-rule-details.jpg", "undo": f"Put your allow rule \"{x['rule']}\" back as it was."}
        fix = {"id": "allow-rule", "title": "Your allow rule", "work": "Change 1 rule", "detail": "the allow rule is on this client only"}
    else:
        step = {"title": f"Create the Block rule On {x['name']}", "msp": {"path": ["Rules", "Create Rule"], "fields": [
                    ["Name", name, name], ["Action", "Block", None], ["Matching", f"Domain › {x['dest']}", x["dest"]],
                    ["On", f"FWG Pro (Router) + {x['name']}", None], ["Direction", "Outbound only", None], ["Schedule", "Always", None]]},
                "app": howto_app("rule", name=name, action="block", matching_path=f"Set a target › Domain › {x['dest']}",
                                 matching_label="Domain", matching_value=x["dest"], target=x["dest"], on_kind="device", on=x["name"],
                                 direction="outbound"),
                "note": f"Then Create. A rule on the client itself beats your allow rule \"{x['rule']}\", which is set wider (a group, a network or all clients).",
                "picture": "msp-rule-create.jpg", "undo": f"Delete the rule \"{name}\" On {x['name']}."}
        fix = {"id": "domain-block", "title": "A Block rule for the site", "work": "Create 1 rule", "detail": f"on {x['name']} only, for {x['dest']}"}
    fix.update(offer=True, steps=[step], result={"ok": 1, "of": 1, "also_count": 0, "missed": [], "impacts": []})
    return {"act": "block", "words": "", "both": False, "directions": [{
        "label": "A → B", "a": [{"name": x["name"]}], "b": [{"name": x["dest"]}], "pairs": 1, "cut": False, "today": [], "need": 1, "done": False,
        "units": [], "extra": [], "extra_count": 0, "fixes": [fix], "impacts": [], "clean": True, "exact": True}]}


def policy_rule_plan(f):
    """Show Me How for an Open But Unused item the planner can't work out (an
    internet allow rule, a port forward), in Show Me How's own shape like
    policy_internet_plan, so it shows as a way with its screen (D-921).
    None for one the planner does (it has "howto")."""
    if f["kind"] != "rule" or f.get("howto"):
        return None
    x, steps, undo = f.get("rule") or {}, f.get("steps") or [], f.get("undo") or []
    if str(x.get("id", "")).startswith("f|"):
        step = {"title": steps[0] if steps else "Delete the port forward", "note": " · ".join(steps[1:]), "undo": undo[0] if undo else ""}
        fix = {"id": "forward", "title": "Delete the port forward", "work": "Change 1 port forward", "detail": x.get("what") or ""}
    else:
        r = policy_rule_for_pid(x.get("pid")) or {}
        name = access_rule_text(r) if r else str(x.get("what") or "the rule")
        step = {"title": f"Delete (or pause) rule #{x.get('pid')} {name}", "msp": {"path": ["Rules", name], "fields": [["Rule", name, None], ["Then", "Delete, or Pause it first to try", None]]},
                "note": " · ".join(steps[1:]) or "What it allowed is then decided by your other rules.", "picture": "msp-rule-details.jpg", "undo": undo[0] if undo else ""}
        fix = {"id": "delete-rule", "title": "Delete the rule", "work": "Change 1 rule", "detail": x.get("grants") or ""}
    fix.update(offer=True, steps=[step], result={"ok": 1, "of": 1, "also_count": 0, "missed": [], "impacts": []})
    return {"act": "block", "words": "", "both": False, "directions": [{
        "label": "A → B", "a": [{"name": str(x.get("what") or "")}], "b": [{"name": str(x.get("grants") or "")}], "pairs": 1, "cut": False, "today": [], "need": 1,
        "done": False, "units": [], "extra": [], "extra_count": 0, "fixes": [fix], "impacts": [], "clean": True, "exact": True}]}


@app.post("/api/policy/flow")
def api_policy_flow(payload: dict = Body(default={})):
    """An item in the flow ({id, action}): return (keys: some rows, else
    all; Review only), split (by set of Firewalla changes), doing (I'm Doing
    This; fix = the way picked), delete (any stage; keys: some rows, else
    the item: owner, 21 Nov 2026), back (Pending Confirmation, Make My Rule
    Work only: it isn't working)."""
    f_ = Fields(payload)
    fid, action = f_.text("id", 40, strip=False), f_.choice("action", ("return", "split", "doing", "delete", "back"))
    with policy_lock:
        data = policy_data()
        st = policy_state_load()
        f = st["flow"].get(fid)
        item = next((x for x in data["page"]["flow"] if x["id"] == fid), None)
        if not f or not item or not action:
            return {"ok": False, "error": "That item is gone."}
        now = time.time()
        msg = ""
        if action == "return":
            if f["stage"] != "review":
                return {"ok": False, "error": "Only items in Review can go back to New Connections."}
            keys = [k for k in f_.strings("keys", 400, 300) or f["keys"] if k in f["keys"]]
            for k in keys:
                d = st["decisions"].pop(k, {})
                st["row_picks"][k] = d.get("intent") or "allow"
                st["nc_refs"][k] = list(dict.fromkeys(f["refs"] + ["flow:" + fid]))
            f["keys"] = [k for k in f["keys"] if k not in keys]
            if not f["keys"]:
                del st["flow"][fid]
            msg = f"{f['title']}: {len(keys)} back in New Connections, with your choices."
        elif action == "split":
            sets = item["sets"]
            if len(sets) < 2:
                return {"ok": False, "error": "It needs only one set of instructions."}
            whole = f["title"]   # the first part is the item itself: its title changes in the loop
            for i, s in enumerate(sets):
                nid = fid if i == 0 else policy_flow_new(st, f["kind"], s["keys"], f["refs"], whole, now)
                part = st["flow"][nid]
                part.update(keys=list(s["keys"]), title=f"{whole} · {s['act']} {s['port_label']}", refs=list(f["refs"]),
                            tried=list(f["tried"]), created=f["created"], split_from=fid if nid != fid else None)
                for k in s["keys"]:
                    st["decisions"][k]["flow"] = nid
            msg = f"{whole}: split into {len(sets)} items, one per set of rule changes."
        elif action == "doing":
            if f["stage"] != "review":
                return {"ok": False, "error": "It isn't in Review."}
            if f["kind"] == "chose" or (f["kind"] == "rule" and f.get("howto")):
                # An Open But Unused item asks the planner the same way (D-921).
                if f["kind"] == "chose" and len(item["sets"]) != 1:
                    return {"ok": False, "error": "Split it first: it needs more than one set of instructions."}
                s = item["sets"][0] if f["kind"] == "chose" else {**f["howto"], "act": "Allow" if f["howto"]["act"] == "allow" else "Block"}
                from access import api_howto_start
                r = api_howto_start({"act": "allow" if s["act"] == "Allow" else "block", "a": s["a"], "b": s["b"], "proto": s["proto"] or "",
                                     "port": s["port"] or "", "both": False, "fixes": [f_.text("fix", 80, strip=False)],
                                     "let": f_.text("let", 60000, strip=False),
                                     "title": f["title"], "source": "Policy", "item": "flow:" + fid, "back": "#policy"})
                if not r.get("ok"):
                    return r
                f["change"] = r["id"]
                f["way"] = {"id": f_.text("fix", 80, strip=False), "title": f_.text("way", 200, strip=False) or "a rule change"}
                f.update(stage="action", moved_at=now)
                for k in f["keys"]:
                    st["decisions"][k].update(status="rule_change", status_at=now)
                msg = f"{f['title']} has been moved to Pending Action."
            elif f["kind"] == "make_work":
                # Your rule already says it: the watch is what checks the fix.
                hour = int(now // 3600 * 3600)
                f.update(stage="confirm", moved_at=now, way={"id": (f.get("cause") or {}).get("id"), "title": (f.get("cause") or {}).get("text")},
                         watch={"since": now, "hour": hour, "bad": False, "wrong": [], "base": policy_counts_since(f["keys"], hour)})
                for k in f["keys"]:
                    st["decisions"][k].update(status="confirm", status_at=now)
                msg = f"{f['title']} has been moved to Pending Confirmation: the dashboard watches whether the fix works."
            else:
                plan = policy_internet_plan(f["inet"]) if (f.get("inet") or {}).get("mode") == "block_dest" else policy_rule_plan(f)
                fix = plan["directions"][0]["fixes"][0] if plan else None
                f.update(stage="action", moved_at=now, way={"id": fix["id"] if fix else "words", "title": fix["work"] if fix else "the steps in words"},
                         undo=[x["undo"] for x in fix["steps"]] if fix else [])
                for k in f["keys"]:
                    st["decisions"][k].update(status="rule_change", status_at=now)
                msg = f"{f['title']} has been moved to Pending Action."
        elif action == "delete":
            keys = [k for k in f_.strings("keys", 400, 300) or f["keys"] if k in f["keys"]]
            if not keys:
                return {"ok": False, "error": "That connection isn't in this item."}
            for k in keys:
                policy_remove(st, k, now)
            f["keys"] = [k for k in f["keys"] if k not in keys]
            what = f["title"] if not f["keys"] else f"{len(keys)} of {f['title']}"
            if not f["keys"]:
                if f.get("change"):
                    from access import api_howto_remove
                    api_howto_remove({"id": f["change"]})
                del st["flow"][fid]
            msg = (f"Deleted: {what}. It shows on the Open But Unused page again." if f["kind"] == "rule"
                   else f"Deleted: {what}. It comes back to New Connections only if new traffic is seen.")
        elif action == "back":
            # Any item in Pending Confirmation (owner, 23 Nov 2026, D-917):
            # one that isn't working keeps what was tried; any other waits in
            # Review as sent back by you, even though your rules already match.
            if f["stage"] != "confirm":
                return {"ok": False, "error": "Only an item in Pending Confirmation can go back."}
            w = f.pop("watch", None) or {}
            if w.get("bad"):
                f["tried"].append({"at": now, "way": (f.get("way") or {}).get("title") or "a fix", "fix": (f.get("way") or {}).get("id"),
                                   "since": w["since"], "wrong": w.get("wrong") or []})
                msg = f"{f['title']}: back in Review with what was tried."
            else:
                f["sent_back"] = now
                msg = f"{f['title']}: back in Review, sent back by you."
            f.update(stage="review", moved_at=now)
            for k in f["keys"]:
                st["decisions"][k].update(status="review", status_at=now)
        if msg:
            policy_message(st, now, msg)
        policy_state_save(st)
        policy_data(fresh=True)
    return {"ok": True, "message": msg}


@app.post("/api/policy/delete")
def api_policy_delete(payload: dict = Body(default={})):
    """Delete for rows that aren't in a flow item ({keys}): New Connections
    rows and Decided rows (owner, 21 Nov 2026: Delete at every stage). The
    connection goes off Policy with its choice or decision; only new traffic
    brings it back, to New Connections."""
    with policy_lock:
        data = policy_data()
        st = policy_state_load()
        new_rows = {r["key"]: r for item in (data.get("page") or {}).get("new") or [] for r in item.get("rows") or []}
        keys = [k for k in dict.fromkeys(Fields(payload).strings("keys", 400, 300))
                if k in new_rows or (st["decisions"].get(k) or {}).get("status") == "decided"]
        if not keys:
            return {"ok": False, "error": "That connection is gone."}
        now = time.time()
        r = new_rows.get(keys[0])
        first = f"{r['src']['name']} → {r['dst']['name']} · {r['port']}" if r else st["decisions"][keys[0]].get("label") or keys[0]
        for k in keys:
            policy_remove(st, k, now)
            st["row_picks"].pop(k, None)
            st["nc_refs"].pop(k, None)
        msg = (f"Deleted: {first}{f' and {len(keys) - 1} more' if len(keys) > 1 else ''}. "
               f"{'They come' if len(keys) > 1 else 'It comes'} back to New Connections only if new traffic is seen.")
        policy_message(st, now, msg)
        policy_state_save(st)
        policy_data(fresh=True)
    return {"ok": True, "message": msg}


@app.post("/api/policy/violation")
def api_policy_violation(payload: dict = Body(default={})):
    """A violation ({item, action}): keep (Keep My Rule: it clears and comes
    back only if it happens again), make_work (to Review, your rule
    unchanged, Show Me How fixes the likely cause), change (Change My Rule:
    to Review with the opposite action: Got Through -> Allow, Got Blocked
    -> Block)."""
    f_ = Fields(payload)
    key, action = f_.text("item", 300, strip=False), f_.choice("action", ("keep", "make_work", "change", "quiet"))
    with policy_lock:
        data = policy_data()
        v = next((x for x in data["page"]["violations"] if x["item"] == key), None)
        r = next((x for x in data["review"] if x.get("item") == key), None)
        if not v or not r or not action:
            return {"ok": False, "error": "That violation is gone."}
        st = policy_state_load()
        now = time.time()
        internet = r["kind"] == "internet"
        # The card as it was when you chose (owner, 22 Nov 2026): kept with
        # the decision (the last 5), shown on Decided and on the same pair's
        # next violation, so a later look has the details.
        dkey = key if internet else r["key"]
        earlier = list((st["decisions"].get(dkey) or {}).get("evidence") or [])
        evidence = {"at": now, "how": action, "kind": v["kind"], "title": v["title"], "what": v["what"],
                    "overridden_by": v.get("overridden_by") or [], "cause": (v.get("cause") or {}).get("text"),
                    "rules": v.get("rules"), "rows": v.get("rows") or [], "internet": bool(v.get("internet"))}
        if action == "keep":
            if internet:
                policy_remove(st, key, now)   # back only with traffic after now
            else:
                st["decisions"][r["key"]] = {
                    "intent": "block" if r["kind"] == "through" else "allow", "at": now, "label": r["label"],
                    "kind": "false_alarm", "status": "decided", "how": "kept_my_rule", "refs": v["refs"],
                    "why": r.get("why"), "fp": {"at": now, "kind": r["kind"]}}
                del st["items"][key]
            msg = f"{v['title']}: kept your rule. It comes back only if it happens again."
        elif action == "quiet":
            if internet or r["kind"] != "blocked":
                return {"ok": False, "error": "Only a Got Blocked violation between two of your clients can be quieted."}
            q = policy_quiet_new(st, r, v, now)
            st["decisions"][r["key"]] = {
                "intent": "allow", "at": now, "label": r["label"], "kind": "false_alarm", "status": "decided",
                "how": "quieted", "refs": v["refs"], "why": r.get("why"), "fp": {"at": now, "kind": r["kind"]}, "quiet": q["id"]}
            del st["items"][key]
            msg = f"{v['title']}: quieted. The same tries are recorded under Quieted Patterns; anything different still comes here."
        elif action == "make_work":
            if internet or not v.get("cause"):
                return {"ok": False, "error": "The dashboard can't name a likely cause for this one: Ask Claude, or use the Access Test."}
            # Allowed Devices for the AP7 cause: the planner's own ways and pictures (D-921).
            howto = None
            if v["cause"].get("id") == "ap7_local" and r["key"].count("|") >= 2:
                src, dst, port_key = r["key"].split("|", 2)
                proto, port = policy_ports_for_howto(port_key)
                howto = {"act": "allow", "a": "d:" + src, "b": "d:" + dst, "proto": proto or "", "port": port or "", "words": f"Allow · {r.get('label') or v['title']}"}
            fid = policy_flow_new(st, "make_work", [r["key"]], v["refs"], v["title"], now, cause=v["cause"], steps=v["cause"]["steps"],
                                  violation=r["kind"], howto=howto)
            st["decisions"][r["key"]] = {"intent": "block" if r["kind"] == "through" else "allow", "at": now, "label": r["label"],
                                         "kind": "make_work", "status": "review", "status_at": now, "flow": fid, "why": r.get("why")}
            del st["items"][key]
            msg = f"{v['title']}: moved to Review to make your rule work."
        else:
            if internet:
                x = {"mode": "allow_country", "key": r["key"]}
                fid = policy_flow_new(st, "internet", [key], v["refs"], v["title"], now, inet=x, steps=r.get("steps") or [],
                                      why={"title": "Why Might This Be Needed?", "lines": [{"tag": "Known", "text": v["what"], "check": ""}]})
                st["decisions"][key] = {"intent": "allow", "at": now, "label": r["label"], "kind": "chose", "status": "review",
                                        "status_at": now, "flow": fid, "inet": {"mac": "", "name": ", ".join(d["name"] for d in r["devices"][:3]),
                                                                                "dest": ", ".join(r.get("destinations") or [])[:200], "country": r["country"]}}
                st["removed"][key] = now
                st["items"].pop(key, None)
            else:
                intent = "allow" if r["kind"] == "through" else "block"
                fid = policy_flow_new(st, "chose", [r["key"]], v["refs"], v["title"], now)
                st["decisions"][r["key"]] = {"intent": intent, "at": now, "label": r["label"], "kind": "chose", "status": "review",
                                             "status_at": now, "flow": fid, "why": r.get("why")}
                del st["items"][key]
            msg = f"{v['title']}: moved to Review to change your rule."
        if dkey in st["decisions"]:
            st["decisions"][dkey]["evidence"] = (earlier + [evidence])[-5:]
        policy_message(st, now, msg)
        policy_state_save(st)
        policy_data(fresh=True)
    return {"ok": True, "message": msg}


def policy_claude_at():
    """When Claude last answered about a Policy card or group: its own
    answer, or a reply in a conversation on one."""
    answers = (policy_read_json(CLAUDE_STATE_FILE) or {}).get("answers") or {}
    at = max([a.get("at") or 0 for k, a in answers.items() if k.startswith("policy:")] or [0])
    try:
        from assistant import questions_db, questions_lock
        with questions_lock, questions_db() as c:
            row = c.execute("""SELECT MAX(m.at) FROM messages m JOIN threads t ON t.id = m.thread_id
                               WHERE m.role = 'claude' AND t.item_kind IN ('policy', 'reach')""").fetchone()
        at = max(at, row[0] or 0)
    except Exception:
        pass
    return at


def policy_data(fresh=False):
    """The Policy page's data. The worker builds it every POLICY_BUILD_SECONDS
    plus the time its other jobs take, so a kept copy counts as current for
    POLICY_KEEP_SECONDS: a page only builds it itself when the worker is
    behind (with one limit for both, every page request in that gap built
    it again)."""
    old = lambda: not policy_cache["data"] or time.time() - policy_cache["at"] > POLICY_KEEP_SECONDS
    if fresh or old():
        with policy_lock:
            if fresh or old():   # asked again: a request that waited here for another's build uses that one
                policy_cache["data"] = policy_build()
                # (Still waiting for the router's groups: build again next time.)
                policy_cache["at"] = 0 if policy_cache["data"].get("loading") else time.time()
    return policy_cache["data"]


def internet_policy_violations(sides, since):
    rules = [r for r in (state.get("policy_rules") or {}).get("rules") or []
             if r.get("disabled") is not True and r.get("action") == "block" and r.get("type") == "country"
             and r.get("target")]
    by_country = {}
    for rule in rules:
        by_country.setdefault(str(rule["target"]).upper(), []).append(rule)
    if not by_country:
        return [], [], 0, []
    with flow_history_reader() as connection:
        rows = connection.execute(f"""
            SELECT UPPER(country), device_mac, MAX(device), allowed_pid, SUM(COALESCE(starts, count)),
                   SUM(COALESCE(upload_bytes, 0) + COALESCE(download_bytes, 0)), MAX(event_at),
                   COALESCE(destination, remote_ip), MIN(event_at)
            FROM flow_records
            WHERE kind = 'normal' AND event_at >= ? AND UPPER(country) IN ({','.join('?' * len(by_country))})
            GROUP BY UPPER(country), device_mac, allowed_pid, COALESCE(destination, remote_ip)""", (since, *by_country)).fetchall()
    # explained_rows: one per device and site reached only through your own
    # allow rule (New Connections' internet rows, owner 19 Nov 2026).
    open_items, explained, explained_rows = {}, {}, []
    for country, mac, device, allowed_pid, count, total, last, destinations, first in rows:
        side = sides.get(str(mac or "").upper())
        covering = [r for r in by_country[country]
                    if (r.get("applies_on") or {}).get("kind") == "all_devices"
                    or (side and access_covers(r.get("applies_on"), side))]
        if not covering:
            continue
        key = (country, allowed_pid) if allowed_pid else country
        target = explained if allowed_pid else open_items
        item = target.setdefault(key, {
            "key": f"country|{country}", "kind": "internet", "country": country,
            "rules": [{"pid": r.get("pid"), "text": r.get("display_name") or r.get("name")
                       or ("Region blocking" if r.get("purpose") == "region_blocking" else "Country block")}
                      for r in covering],
            "flows": 0, "bytes": 0, "last_seen": 0, "devices": {}, "destinations": set(),
        })
        if allowed_pid:
            allowing = policy_rule_for_pid(allowed_pid)
            item["allowed_by"] = {"pid": allowed_pid, "text": access_rule_text(allowing) if allowing else f"Rule {allowed_pid}"}
        item["flows"] += count or 0
        item["bytes"] += total or 0
        item["last_seen"] = max(item["last_seen"], last or 0)
        name = (side or {}).get("name") or device or mac or "Unknown client"
        entry = item["devices"].setdefault(mac or name, {"mac": mac, "name": name, "flows": 0})
        entry["flows"] += count or 0
        if destinations:
            item["destinations"].add(destinations)
        if allowed_pid and mac:
            explained_rows.append({"country": country, "mac": str(mac).upper(), "name": name, "dest": destinations or "--",
                                   "allowed_by": item["allowed_by"], "flows": count or 0, "bytes": total or 0,
                                   "first_seen": first, "last_seen": last or 0})
    for item in list(open_items.values()) + list(explained.values()):
        item["devices"] = sorted(item["devices"].values(), key=lambda d: -d["flows"])
        item["destinations"] = sorted(item["destinations"])[:8]
    return list(open_items.values()), list(explained.values()), len(by_country), explained_rows


def policy_worker():
    """Keeps the Policy page (and the counts Status and Needs Attention use)
    up to date: local traffic every minute, internet every 5 minutes."""
    time.sleep(60)   # let the rules, groups and devices arrive first
    while True:
        now = time.time()
        if now - policy_internet["at"] >= POLICY_INTERNET_SECONDS:
            try:
                sides, _ = access_sides()
                items, explained, countries, rows = internet_policy_violations(sides, now - 86400)
                policy_internet.update({"items": items, "explained": explained, "explained_rows": rows, "countries": countries, "error": None})
            except Exception as exc:
                policy_internet["error"] = str(exc)
                print("Policy internet check error:", exc)
            policy_internet["at"] = now
        try:
            policy_data(fresh=True)
        except Exception as exc:
            print("Policy page error:", exc)
            traceback.print_exc()
        try:
            howto_mark_done()   # Show Me How changes finish even while its page is closed
        except Exception as exc:
            print("Show Me How check error:", exc)
        try:
            msp_changes_check()
        except Exception as exc:
            print("Firewalla change log error:", exc)
        if now - (policy_internet.get("unused_at") or 0) >= POLICY_INTERNET_SECONDS:
            try:
                open_unused_track(now)   # internet allow rules and port forwards: last used
            except Exception as exc:
                print("Open But Unused tracking error:", exc)
            policy_internet["unused_at"] = now
        try:
            policy_review_due(now)
        except Exception as exc:
            print("Nightly Decided review error:", exc)
            traceback.print_exc()
        time.sleep(POLICY_BUILD_SECONDS)


@app.get("/api/policy-page")
def api_policy_page():
    """The Policy page (owner, 19 Nov 2026): New Connections, Review, Pending
    Action, Pending Confirmation and Violations, with Claude's answers to
    Ask Claude on its items (the conversations on them come from
    /api/questions/on-items, as on every page). Decided has its own page."""
    with claude_lock:
        claude = claude_public(claude_load(), "policy")
    data = policy_data()
    with policy_lock:
        monitor = dict(policy_monitor(policy_state_load()))
    monitor.pop("listed", None)
    return {**{k: data.get(k) for k in ("loading", "updated_at", "recording_since", "counts", "page", "rule_pids", "left_out", "internet_error")},
            "claude": claude, "monitor": monitor}


@app.post("/api/policy/monitoring")
def api_policy_monitoring(payload: dict = Body(default={})):
    """Stop Monitoring (D-919): {stopped: "on" | "off"}."""
    stop = Fields(payload).choice("stopped", ("on", "off"))
    if not stop:
        return {"ok": False, "error": "Say on or off."}
    data = policy_data()
    with policy_lock:
        st = policy_state_load()
        m, now = policy_monitor(st), time.time()
        if stop == "on" and not m.get("stopped"):
            # The cards on the page now keep their place while stopped.
            m["listed"] = sorted({c["key"] for c in data.get("triage") or []}
                                 | {r["key"] for rows in policy_explained_rows(st, st["decisions"], now).values() for r in rows})
            m["stopped"] = now
            policy_message(st, now, "Monitoring stopped: no new cards, violations, nightly review or Policy alerts until you turn it back on.")
        elif stop == "off" and m.get("stopped"):
            m["pauses"] = (m.get("pauses") or [])[-(POLICY_PAUSES_KEPT - 1):] + [[m["stopped"], now]]
            m["stopped"] = None
            policy_message(st, now, "Monitoring is back on. Traffic seen only while it was stopped was skipped.")
        policy_state_save(st)
        policy_data(fresh=True)
        out = dict(m)
    out.pop("listed", None)
    return {"ok": True, "monitor": out, "message": "Monitoring stopped." if out.get("stopped") else "Monitoring is on."}


# ============================================================
# DECIDED (owner, 19 Nov 2026): its own page, never reopened. Every
# decision with what was kept when it was made (the Why lines, your choice,
# how it was decided, what was done in Firewalla, what was tried, the watch,
# the Claude conversation), so Ask Claude can see why a change was made.
# ============================================================
POLICY_HOW_WORDS = {
    "keep": "{a} (Matches Rules)", "accept": "Kept Router Rule ({a})", "changed": "{a} (Rule Changed)",
    "make_work": "Made My Rule Work ({a})", "kept_my_rule": "Kept My Rule (Violation)", "quieted": "Quieted This Pattern (Violation)", "false_alarm": "Kept My Rule (Violation)",
    "default": "Settled by Default ({a})", "auto": "Joined a Decided Group ({a})", "nodev": "No Client There ({a})",
    "chose": "{a} (Your Choice)",
}


def policy_decision_words(d):
    """A decision as the Decided page's Your Decision column says it."""
    a = "Allowed" if d.get("intent") == "allow" else "Blocked"
    how = d.get("how") or d.get("kind") or "chose"
    return POLICY_HOW_WORDS.get(how, "{a}").format(a=a)


def policy_decided_total(st):
    """How many decisions are Decided: the one count for every page (D-915)."""
    return sum(1 for d in st["decisions"].values() if d.get("status") == "decided")


def policy_decided_rows(data, st):
    """Every decision, newest first: the Decided page's rows."""
    live = {c["key"]: c for c in data.get("decided") or []}
    rows = []
    for key, d in st["decisions"].items():
        if d.get("status") != "decided":
            continue
        c, inet = live.get(key), d.get("inet") or {}
        if c:
            src, dst, port = c["src"], c["dst"], c["port"]
        elif inet:
            src, dst, port = {"mac": inet.get("mac") or "", "name": inet.get("name") or "--"}, {"mac": "", "name": f"{inet.get('dest')} ({inet.get('country')})"}, "--"
        else:
            # No traffic left in the 7-day recording: its saved label.
            label = str(d.get("label") or key)
            pair, _, port = label.rpartition(" · ")
            a, _, b = (pair or label).partition(" → ")
            parts = key.split("|")
            src, dst = {"mac": parts[0] if len(parts) == 3 else "", "name": a or "--"}, {"mac": parts[1] if len(parts) == 3 else "", "name": b or "--"}
            port = port or "--"
        done = d.get("done") or {}
        rows.append({
            "key": key, "at": d.get("at"), "src": src, "dst": dst, "port": port, "intent": d.get("intent"),
            "decision": policy_decision_words(d), "flows": c["flows"] if c else 0, "last_seen": c["last_seen"] if c else None,
            "rules_now": c["rules"] if c else None, "why": d.get("why") or (c or {}).get("why"),
            "done": {"at": done.get("at"), "lines": done.get("lines") or [], "undo": done.get("undo") or []} if done else None,
            "tried": d.get("tried") or [], "watch": d.get("watch"), "reason": d.get("reason"), "joined": d.get("joined"),
            "refs": list(dict.fromkeys((d.get("refs") or []) + [key, "c|" + key])),
            "evidence": d.get("evidence") or [],   # the violation cards when you chose (owner, 22 Nov 2026)
        })
    rows.sort(key=lambda r: -(r["at"] or 0))
    return rows


@app.get("/api/decided-page")
def api_decided_page():
    """The Decided page: every decision, with Claude's answers on their
    items (the conversations come from /api/questions/on-items), Claude's
    nightly look at Decided and the decisions last dropped as quiet for 90
    days."""
    with claude_lock:
        claude = claude_public(claude_load(), "policy")
    data = policy_data()
    with policy_lock:
        st = policy_state_load()
    return {"loading": data.get("loading"), "updated_at": data.get("updated_at"), "rows": policy_decided_rows(data, st),
            "decided_review": st.get("decided_review"), "dropped": st.get("dropped"), "claude": claude,
            "rule_pids": data.get("rule_pids") or {}}


def policy_howto_progress():
    """Rule Changes cards with a Show Me How change in progress (I'm Doing
    This from the card): item -> {id, seen, of, started}."""
    with howto_lock:
        changes = howto_load()["changes"]
    return {c["item"]: {"id": c["id"], "seen": sum(1 for x in c.get("steps") or [] if howto_seen(x["watch"])),
                        "of": len(c.get("steps") or []), "started": c.get("started")}
            for c in changes if c.get("item") and c.get("status") != "done"}
