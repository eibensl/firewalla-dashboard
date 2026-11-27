# Local access: the Access Test, prediction against traffic, Show Me How and
# the change history.

import hashlib
import ipaddress
import json
import os
import re
import threading
import time
from datetime import datetime
from fastapi import Body

from core import (
    Fields, INTERFACE_METADATA, app, msp, policy_read_json, public_error, router_ips,
    router_macs, router_ready, state,
)
from router import (
    access_device_protect, feature_settings, internet_interface_name, policy_rule_for_pid,
)
from flows import (
    flush_local_traffic, local_traffic_connection,
)


# ============================================================
# THE RULE CHECKER: can device A reach device B on the local network?
#
# Worked out from the router's rules and group settings, for a
# connection started by A and one started by B, naming what decides it.
# How Firewalla decides, as modelled here:
#   1. VqLAN (group isolated from other groups) and Isolation (members
#      isolated from each other) are opened only by a VqLAN allowed list:
#      rules with purpose "ap_allow". One such rule between the two sides
#      opens the path both ways, for every group in the way (Speakers <->
#      FireTV flows pass on the Speakers' list alone).
#   2. Rules: tier first (rule "seq", 1 before 2 before 3), then the most
#      specific (on a device, a group, a network, all devices); at the
#      same level an allow beats a block.
#   3. Nothing in the way: allowed.
# Only rules acting on local traffic count: "intranet" blocks ("X to All
# Others": matching Local Networks, which includes X itself - hence the
# "X to X" allows), network allows and the VqLAN allowed lists. Device
# "mac" blocks and Device Active Protect act on internet traffic (the
# Internet row of the client view).
# An ordinary allow rule ("Wired to Wired") does not open a VqLAN: if it
# did, every VqLAN on a network with an "X to X" allow would do nothing.
# Where a verdict rests on rule order alone (a block beating a matching
# allow because it is in an earlier tier or more specific) it is marked
# uncertain, and so is an allowed verdict for a device whose Device
# Active Protect is active for local traffic (it may hold the device to
# what it has learned) when no such traffic was seen. Rule tiers: on
# 13 Nov 2026 only the Device Active Protect rules had one (3).
# "Seen" comes from the local traffic recorder, with the rule the router
# said allowed each flow.
# ============================================================

ACCESS_LOCAL_RULE_TYPES = {"intranet", "network", "tag", "device"}
ACCESS_LEVELS = {"device": 0, "peer": 0, "group": 1, "network": 2}   # anything else: all devices (3)
ACCESS_LEVEL_NAMES = ["device", "group", "network", "all devices"]


# High-availability pairs, FIREWALLA_HA_PAIRS: "<shared address>=<MAC>,<MAC>"
# (; between pairs), for two NAS units sharing one address that follows the
# active node; Firewalla then lists that node at the shared address and its
# own address drops out. Unset: none.
ACCESS_HA_PAIRS = [
    (shared.strip(), {m.strip().upper() for m in macs.split(",") if m.strip()})
    for shared, _, macs in (part.partition("=") for part in os.environ.get(
        "FIREWALLA_HA_PAIRS", "").split(";"))
    if shared.strip() and macs]


def access_ha(sides):
    """Marks the HA pairs' devices: own address (its reservation), the shared
    one on the active node, and ips = every address it answers on now."""
    for shared, macs in ACCESS_HA_PAIRS:
        for mac in macs & set(sides):
            side = sides[mac]
            active = side.get("ip") == shared
            own = next(iter(howto_reserved(mac)), None) or (None if active else side.get("ip"))
            partner = next((sides[m]["name"] for m in macs - {mac} if m in sides), None)
            side["ha"] = {"shared": shared, "own": own, "role": "active" if active else "standby", "partner": partner}
            side["ips"] = [ip for ip in (own, shared if active else None) if ip]
            side["ip_text"] = (f"{own or '?'} · shared {shared} (active now)" if active
                               else f"{own or '?'} · standby for {shared}")


def access_sides():
    """Every device as the model sees it (MAC -> name, IP, network,
    groups) and the groups by id. ips: every address it answers on (an HA
    pair's active node has two); ip_text: how to show them."""
    groups = {g["id"]: g for g in (state.get("groups") or {}).get("groups") or []}
    member_of = {}
    for g in groups.values():
        for mac in g.get("members") or []:
            member_of.setdefault(mac, []).append(g["id"])
    sides = {}
    wifi = {str(m).upper() for m in (state.get("wifi_stations") or {})}
    for device in state.get("devices") or []:
        mac = str(device.get("mac") or "").upper()
        if mac:
            sides[mac] = {
                "mac": mac, "name": device.get("name") or device.get("ip") or mac, "ip": device.get("ip"),
                "network": device.get("interface_uuid"),
                "network_name": internet_interface_name(device.get("interface_uuid")) if device.get("interface_uuid") else "--",
                "online": bool(device.get("online")), "groups": member_of.get(mac, []),
            }
            sides[mac]["ips"] = [sides[mac]["ip"]] if sides[mac]["ip"] else []
            sides[mac]["ip_text"] = sides[mac]["ip"] or ""
            # How it connects: "wifi" (an AP7 reports it), "wired" (online, no
            # AP reports it), "lan" (offline: when it comes back it is on the
            # same LAN, wired or Wi-Fi - rules only reach a device while it is
            # connected, user 16 Nov 2026), None (a VPN network - wg0, awg0,
            # tun_fwvpn: routed through the box, so rules apply). Only a
            # bridged LAN (br*) is switched.
            lan = str((INTERFACE_METADATA.get(str(sides[mac]["network"])) or {}).get("interface") or "").startswith("br")
            sides[mac]["link"] = None if not lan else ("wifi" if mac in wifi else "wired") if sides[mac]["online"] else "lan"
    access_segments(sides, wifi)
    access_ha(sides)
    return sides, groups


def access_segments(sides, wifi):
    """Wired clients sharing one Firewalla switch port with no access point
    or Firewalla unit on it: a switch or hub that isn't Firewalla's sits
    between them, and VqLAN and Isolation need a Firewalla switch, AP or
    box port (Firewalla's VqLAN article), so traffic between them never
    reaches anything Firewalla has. Marks them segment = "<switch> port
    <n>". (Part 2 of the safety plan, 24 Nov 2026; none on your network
    then: the ports with many clients are AP ports.)"""
    by_port = {}
    for mac, where in (state.get("wired_clients") or {}).items():
        mac = str(mac).upper()
        if isinstance(where, dict) and where.get("switch_id") is not None:
            by_port.setdefault((where["switch_id"], str(where.get("port"))), []).append(mac)
    switches = state.get("switches") or {}
    for (sid, port), macs in by_port.items():
        if any(m in sides and access_is_gear(sides[m]) for m in macs):
            continue
        wired = [m for m in macs if m in sides and m not in wifi]
        if len(wired) < 2:
            continue
        name = (switches.get(sid) or {}).get("name") or "a switch"
        for m in wired:
            sides[m]["segment"] = f"{name} port {port}"


def access_peer_sides():
    """Every VPN peer as a side (21 Nov 2026), keyed the way a flow names it
    ("AWG_PEER:<KEY>"): a phone on the VPN, or another site's router with the
    networks behind it (nets). A peer is in no group and is routed through
    the box, so rules apply. Only the Policy page's rule check adds them:
    access_sides stays your clients."""
    sides = {}
    for network, peers in (state.get("vpn_peers") or {}).items():
        for p in peers:
            if not p.get("flow_id") or p["flow_id"].endswith(":"):
                continue
            nets = []
            for text in p.get("allowed_ips") or []:
                try:
                    nets.append(ipaddress.ip_network(str(text), strict=False))
                except ValueError:
                    pass
            sides[p["flow_id"]] = {
                "mac": p["flow_id"], "name": p.get("name") or "VPN Peer", "ip": p.get("ip"),
                "ips": [p["ip"]] if p.get("ip") else [], "ip_text": ", ".join(str(n) for n in nets),
                "network": network, "network_name": internet_interface_name(network),
                "online": bool(p.get("online")), "groups": [], "link": None, "peer": True, "nets": nets,
            }
    return sides


def access_address_rules():
    """Enabled allow / block rules on an address or network of your own (a
    private one): what decides traffic to another site behind a VPN peer
    (#991 NAS -> 192.168.50.1, the cabin router, 21 Nov 2026). They match a
    VPN peer only (access_covers), never a client."""
    out = []
    for rule in (state.get("policy_rules") or {}).get("rules") or []:
        if rule.get("disabled") is True or rule.get("action") not in ("allow", "block") or rule.get("type") not in ("ip", "net"):
            continue
        try:
            if ipaddress.ip_network(str((rule.get("matching") or {}).get("id")), strict=False).is_private:
                out.append(rule)
        except ValueError:
            pass
    return out


def access_local_rules():
    """Enabled rules that act on traffic between local devices."""
    return [
        rule for rule in (state.get("policy_rules") or {}).get("rules") or []
        if rule.get("disabled") is not True and rule.get("action") in ("allow", "block")
        and (rule.get("purpose") == "ap_allow" or rule.get("type") in ACCESS_LOCAL_RULE_TYPES
             or access_target_list_side(rule))
    ]


def access_target_list_side(rule):
    """"matching" or "applies_on" when that side of the rule is a target
    list, else None. Seen on 13 Nov 2026: rule 955 (NAS Units .5 -> a target
    list of the camera IPs, TCP 554/2020, outbound) carries the NAS ->
    camera traffic through both groups' VqLANs, so a target-list allow
    opens VqLAN and Isolation like an allowed list (an ordinary group or
    network allow does not). Only lists you make (ids "TL-…") can name your
    own devices; the rest are internet lists: Device Active Protect's
    learned destinations ("dap_…") and Firewalla's blocklists."""
    for side in ("matching", "applies_on"):
        obj = rule.get(side) or {}
        if obj.get("kind") == "target_list" and str(obj.get("id") or "").startswith("TL-"):
            return side
    return None


access_list_parsed = {}   # id of a list's lines -> (the lines, their entries)


def access_list_entries(rule):
    """A target-list rule's entries, read from the MSP (see FIREWALLA MSP):
    [{"net": address or network (None for a domain), "protocol", "ports":
    [(low, high)] or None for every port}], or None while the list isn't
    known (no MSP data yet)."""
    listed = access_target_list_side(rule)
    # Show Me How tries out lists that don't exist yet (sim_targets).
    tl = ({"targets": rule["sim_targets"]} if rule.get("sim_targets") is not None
          else msp["lists"].get(str((rule.get(listed) or {}).get("id"))))
    if tl is None:
        return None
    # A list's lines are read once and kept for as long as that list is in
    # use (20 Nov 2026): this is asked for every rule on every pair, and an
    # Access Test of two groups read the same addresses thousands of times.
    kept = access_list_parsed.get(id(tl["targets"]))
    if kept and kept[0] is tl["targets"]:
        return kept[1]
    entries = []
    for text in tl["targets"]:
        address, _, ports = str(text).partition(",")
        protocol, _, numbers = ports.partition(":")
        try:
            net = ipaddress.ip_network(address.strip(), strict=False)
        except ValueError:
            net = None   # a domain: never one of your own devices
        ranges = []
        for part in filter(None, numbers.split(",")):
            low, _, high = part.partition("-")
            if low.strip().isdigit():
                ranges.append((int(low), int(high) if high.strip().isdigit() else int(low)))
        entries.append({"net": net, "protocol": protocol.strip().lower() or None, "ports": ranges or None,
                        "text": str(text)})
    if len(access_list_parsed) > 500:
        access_list_parsed.clear()
    access_list_parsed[id(tl["targets"])] = (tl["targets"], entries)
    return entries


def access_entry_covers(entry, side, port):
    """Does a target-list entry cover this device, on this port? port =
    (protocol, number), (protocol, "high") for random high ports,
    (protocol, "any") for every port of one protocol (any of them counts),
    or None when unknown (then an entry limited to ports still counts: the
    pair can reach each other on those ports)."""
    # Any address it answers on (an HA pair's active node: its own and the shared).
    try:
        if not entry["net"] or not any(ipaddress.ip_address(ip) in entry["net"] for ip in side.get("ips") or [side.get("ip")] if ip):
            return False
    except ValueError:
        return False
    if not entry["ports"] or port is None:
        return True
    protocol, number = port
    if entry["protocol"] and entry["protocol"] != protocol:
        return False
    if number == "any":
        return True
    if number == "high":
        return any(high >= 32768 for _, high in entry["ports"])
    return any(low <= number <= high for low, high in entry["ports"])


def access_target_list_match(rule, a, b, port=None):
    """Does a target-list rule cover a connection started by a to b: "yes",
    "no", or "maybe" while the list's entries aren't known. Its other side
    (the one that isn't the list) must cover the device on that end, in the
    rule's direction, and the list must hold the other device's address
    (and the port, when the entry names ports)."""
    listed = access_target_list_side(rule)
    named = rule.get("applies_on" if listed == "matching" else "matching")
    entries = access_list_entries(rule)
    # applies_on is the starting side for an outbound rule.
    starter_is_named = listed == "matching"
    direction = rule.get("direction") or "bidirection"
    ways = []
    if direction in ("outbound", "bidirection"):
        ways.append((a, b) if starter_is_named else (b, a))    # (side the rule names, side on the list)
    if direction in ("inbound", "bidirection"):
        ways.append((b, a) if starter_is_named else (a, b))
    answer = "no"
    for named_side, listed_side in ways:
        if not access_covers(named, named_side):
            continue
        if entries is None:
            answer = "maybe"
        elif any(access_entry_covers(e, listed_side, port) for e in entries):
            return "yes"
    return answer


def access_list_ports(rule, side):
    """The ports a target-list rule allows to this device, in words
    ("TCP 554, 2020"), or "" when its entry for the device names none."""
    for e in access_list_entries(rule) or []:
        if e["ports"] and access_entry_covers(e, side, None):
            numbers = ", ".join(str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in e["ports"])
            return f"{(e['protocol'] or '').upper()} {numbers}".strip()
    return ""


def access_covers(obj, side):
    kind, oid = (obj or {}).get("kind"), str((obj or {}).get("id") or "")
    if kind == "device":
        return oid.upper() == side["mac"]
    if kind == "group":
        return oid in side["groups"]
    if kind == "network":
        return bool(side["network"]) and oid == side["network"]
    if kind == "peer":
        return bool(side.get("peer")) and side["mac"].endswith(":" + oid.upper())
    if kind in ("ip", "net"):
        # An address rule: only a VPN peer is matched by address (the networks behind it).
        try:
            net = ipaddress.ip_network(oid, strict=False)
        except ValueError:
            return False
        return any(net.version == n.version and net.overlaps(n) for n in side.get("nets") or [])
    return kind in ("local_networks", "all_devices")


def access_rule_matches(rule, a, b):
    """Does the rule cover a connection started by a to b?"""
    applies, matching = rule.get("applies_on"), rule.get("matching")
    forward = access_covers(applies, a) and access_covers(matching, b)
    backward = access_covers(applies, b) and access_covers(matching, a)
    direction = rule.get("direction") or "bidirection"
    if direction == "outbound" and rule.get("purpose") != "ap_allow":
        return forward
    if direction == "inbound" and rule.get("purpose") != "ap_allow":
        return backward
    return forward or backward


def access_rule_port_covers(rule, port):
    """A rule limited to ports (its remote_port: #991 Allow 192.168.50.1 TCP
    22) covers only those. port = (protocol, number | "high" | "any") or
    None. True for a rule with no port limit, when the pair is asked about
    as a whole (None), and for "any" (every port: the rule covers some of
    them, as before). (24 Nov 2026: the limit was ignored, so a rule for
    one port counted for every port.)"""
    limit = str(rule.get("remote_port") or "").strip()
    if not limit or port is None:
        return True
    protocol, number = port
    if number in (None, "any"):
        return True
    if rule.get("protocol") and protocol not in (None, "any") and str(rule["protocol"]).lower() != str(protocol).lower():
        return False
    for part in limit.split(","):
        low, dash, high = part.strip().partition("-")
        if not low.isdigit() or (dash and not high.isdigit()):
            continue
        low, high = int(low), int(high) if dash else int(low)
        if number == "high":
            if high >= 32768:
                return True
        elif str(number).isdigit() and low <= int(number) <= high:
            return True
    return False


def access_rule_level(rule):
    return ACCESS_LEVELS.get((rule.get("applies_on") or {}).get("kind"), 3)


def access_allowed_owner(rule):
    """An Allowed Devices entry -> (whose list it is in, what is ticked).
    A device's own page: On = that device, Matching = the device ticked
    (real test 2, 16 Nov 2026: ticking A's PC on B's PC's page made
    #963 On B, Matching A; the other way round made #964 On A).
    A group's list: Matching = the group, On = what is ticked."""
    applies, matching = rule.get("applies_on") or {}, rule.get("matching") or {}
    if applies.get("kind") == "device" and matching.get("kind") == "device":
        return applies, matching
    return matching, applies


def access_rule_text(rule):
    if rule.get("purpose") == "ap_allow":
        owner, ticked = access_allowed_owner(rule)
        return f"Allowed Devices of {owner.get('name') or owner.get('id')}: {ticked.get('name') or ticked.get('id')}"
    match = rule.get("matching") or {}
    listed = ((msp["lists"].get(str(match.get("id"))) or {}).get("name") or HOWTO_LIST_NAMES.get(str(match.get("id")))
              if match.get("kind") == "target_list" else None)
    return (rule.get("display_name") or rule.get("name") or (f"Target List: {listed}" if listed else match.get("label"))
            or f"Rule {rule.get('pid')}")


def access_is_gear(side):
    """Firewalla's own equipment: the router, a switch or an access point,
    by MAC (the switch and AP lists the router sends are keyed by MAC). Any
    other device, even one on the admin network, is an ordinary client."""
    return (side["mac"] in router_macs() or side["mac"] in (state.get("switches") or {})
            or side["mac"] in (state.get("access_points") or {}))


def access_paused(side):
    """Why Firewalla isn't enforcing anything for this device, or None:
    Monitoring Off (device, its group or its network) or Emergency Access
    (device, group, network or the whole box). Both pause rules, VqLAN,
    Isolation and Device Active Protect; Monitoring Off also stops flow
    records (help article 16639311975059)."""
    fs = feature_settings
    dev = (fs.get("devices") or {}).get(side["mac"]) or {}
    net = (fs.get("networks") or {}).get(str(side.get("network"))) or {}
    grps = [(fs.get("groups") or {}).get(str(g)) or {} for g in side.get("groups") or []]
    if dev.get("monitor") is False:
        return f"Monitoring is off on {side['name']}"
    if any(g.get("monitor") is False for g in grps):
        return f"Monitoring is off on {side['name']}'s group"
    if net.get("monitor") is False or net.get("monitoring") is False:
        return f"Monitoring is off on {side['name']}'s network"
    if dev.get("emergency"):
        return f"Emergency Access is on for {side['name']}"
    if any(g.get("emergency") for g in grps):
        return f"Emergency Access is on for {side['name']}'s group"
    if net.get("emergency"):
        return f"Emergency Access is on for {side['name']}'s network"
    if (fs.get("box") or {}).get("emergency"):
        return "Emergency Access is on for the whole box"
    return None


def check_local_access(a, b, groups, rules, credited=(), lists_uncertain=True, port=None, isolated=None, paused=None):
    """A connection started by side a to side b: verdict, what decides
    it, and every rule or setting in the way. credited = the rules the
    router named as allowing a -> b traffic (the recorder's allowed_by).
    port = (protocol, number) or (protocol, "high") for the Policy page's
    connections, None for the pair as a whole. A target-list rule covers
    the pair when its list (read from the MSP) holds the device's address
    and port, or when the router credits it; while the list isn't known
    it only "may" cover it. paused = {MAC: why} for devices Firewalla
    isn't enforcing anything for (access_paused; Show Me How passes its
    own copy to try out turning monitoring back on)."""
    credited = {str(p) for p in credited or ()}
    possible = []    # target-list rules that may cover the pair, unconfirmed
    candidates = []
    for r in rules:
        if access_target_list_side(r):
            match = access_target_list_match(r, a, b, port)
            if match == "yes" or (match == "maybe" and str(r.get("pid")) in credited):
                candidates.append(r)
            elif match == "maybe":
                possible.append(r)
        elif access_rule_matches(r, a, b) and access_rule_port_covers(r, port):
            candidates.append(r)
    rank = lambda r: (r.get("seq") if r.get("seq") is not None else 2, access_rule_level(r),
                      0 if r.get("action") == "allow" else 1)
    matched = sorted(candidates, key=rank)
    # A target-list allow opens VqLAN and Isolation only between networks
    # (routed through the box: #955 NAS .5 -> cameras .10, 13 Nov 2026).
    # On one network it doesn't (real test 4, 16 Nov 2026: Allow On PC .5
    # Matching a list with A's PC on TCP 445 never let B's isolated
    # PC through, 0 hits): that traffic is switched, and only Allowed
    # Devices reaches the switch. Assumed the same for VqLAN on one network.
    across = a.get("network") != b.get("network")
    openers = [r for r in matched if r.get("purpose") == "ap_allow"
               or (access_target_list_side(r) and r.get("action") == "allow" and across)]
    group_name = lambda gid: (groups.get(gid) or {}).get("name") or f"Group {gid}"

    barriers = []
    # Firewalla's own equipment (the router, switches and APs, by MAC:
    # access_is_gear) isn't fenced by VqLAN or Isolation: tested by the
    # user on 14 Nov 2026 (the only Admin Devices PC, with VqLAN and then
    # Isolation on, reaches every switch and AP on LAN Admin). Rules decide.
    gear = [s for s in (a, b) if access_is_gear(s)]
    # A VPN peer isn't fenced either: it isn't on your LAN. Seen 21 Nov 2026:
    # the NAS and B's PC, both in VqLAN groups, reached the cabin router
    # through the site-to-site VPN once an address allow rule was there.
    peer = [s for s in (a, b) if s.get("peer")]
    gear = gear or peer
    # Two wired clients on one switch that isn't Firewalla's (access_segments):
    # their traffic never reaches Firewalla, so no VqLAN, Isolation or rule.
    shared = bool(a.get("segment")) and a.get("segment") == b.get("segment") and a.get("network") == b.get("network")
    for inside, outside in ((a, b), (b, a)) if not gear and not shared else ():
        for gid in inside["groups"]:
            if (groups.get(gid) or {}).get("vqlan") and gid not in outside["groups"] \
                    and not any(x["group"] == gid and x["kind"] == "vqlan" for x in barriers):
                barriers.append({"kind": "vqlan", "group": gid, "mac": inside["mac"], "effect": "block",
                                 "text": f"VqLAN on {group_name(gid)}",
                                 "detail": f"{inside['name']} is in {group_name(gid)}, {outside['name']} is not"})
    # Device Isolation on a single device (yours, or switched on by Device
    # Active Protect): isolated = MACs; Show Me How passes its own copy
    # (part of its cache key), every other caller gets today's.
    if isolated is None:
        isolated = access_isolated()
    for side in (a, b) if not gear and not shared else ():
        if side["mac"] in isolated:
            barriers.append({"kind": "isolation", "group": None, "mac": side["mac"], "effect": "block",
                             # Who switched it on (owner, 22 Nov 2026): Device Active Protect, or you.
                             "by_dap": bool(((feature_settings.get("devices") or {}).get(side["mac"]) or {}).get("isolated_by_dap")),
                             "text": f"Device Isolation on {side['name']}",
                             "detail": f"{side['name']} may only reach the internet and its Allowed Devices"})
    for gid in sorted(set(a["groups"]) & set(b["groups"])) if not gear and not shared else ():
        if (groups.get(gid) or {}).get("isolation"):
            barriers.append({"kind": "isolation", "group": gid, "effect": "block",
                             "text": f"Isolation in {group_name(gid)}",
                             "detail": "Members of this group can't reach each other"})
    # What lifts each barrier. An Allowed Devices entry lifts every one,
    # both ways, whichever device's page it is on (re-tested 16 Nov 2026 with
    # every PC firewall off; an earlier "one way" result was A's own
    # Windows firewall). A target-list allow (only between networks, above)
    # lifts VqLAN but never Isolation (real test 8, 16 Nov 2026: Allow On
    # PC Phones .10 Matching a list with B's PC let Phone B through
    # both VqLANs, but not through B's PC's own Isolation; paused, VqLAN
    # blocked again).
    for barrier in barriers:
        lifter = next((r for r in openers if r.get("purpose") == "ap_allow" or barrier["kind"] == "vqlan"), None)
        barrier["lifted_by"] = lifter.get("pid") if lifter else None
    unlifted = [x for x in barriers if not x["lifted_by"]]

    steps = barriers + [{
        "kind": "rule", "pid": r.get("pid"), "text": access_rule_text(r), "effect": r.get("action"),
        "level": ACCESS_LEVEL_NAMES[access_rule_level(r)], "seq": r.get("seq"), "hit_count": r.get("hit_count"),
        "on": (r.get("applies_on") or {}).get("label"),
        # What the rule is set on and what it matches, for Traffic Path's plain words (owner, 22 Nov 2026).
        "on_kind": (r.get("applies_on") or {}).get("kind"), "on_name": (r.get("applies_on") or {}).get("name"),
        "match_kind": (r.get("matching") or {}).get("kind"), "match_name": (r.get("matching") or {}).get("name") or (r.get("matching") or {}).get("id"),
        "match_label": (r.get("matching") or {}).get("label"),
        # A target list limited to ports covers the pair on those only.
        **({"ports": ports} if access_target_list_side(r) and port is None
           and (ports := access_list_ports(r, b) or access_list_ports(r, a)) else {}),
    } for r in matched]

    notes, uncertain = [], False
    if peer:
        notes.append(f"{peer[0]['name']} is a VPN peer: VqLAN and Isolation don't fence it, so your rules decide.")
        for r in matched:
            for obj in (r.get("matching") or {}, r.get("applies_on") or {}):
                if obj.get("kind") in ("ip", "net"):
                    notes.append(f"Rule #{r.get('pid')} {access_rule_text(r)} names {obj.get('id')}: it covers that address only, "
                                 f"not everything behind {peer[0]['name']}.")
    elif gear:
        notes.append(f"{gear[0]['name']} is Firewalla equipment: VqLAN and Isolation don't fence it, so your rules decide.")
    # Two devices on the same network, wired or on AP7 Wi-Fi: their traffic
    # never reaches the router's rules (real tests 7 and 9, 16 Nov 2026: a
    # Block Matching a list with the other device was never hit - two wired
    # PCs through the switches, and Phone B -> the Tab S9 across two
    # AP7s; test 4's Allow likewise). Only VqLAN, Isolation and Allowed
    # Devices, which the switches and APs enforce, decide. Allowed Devices
    # entries aren't rules here. One exception Firewalla states and we
    # haven't tested: Block All Local Networks blocks within a network on
    # AP7 Wi-Fi, so with a Wi-Fi device such a rule makes it uncertain.
    same_net = bool(a.get("network")) and a.get("network") == b.get("network") and not gear
    switched = same_net and a.get("link") in ("wired", "wifi", "lan") and b.get("link") in ("wired", "wifi", "lan")
    on_air = same_net and "wifi" in (a.get("link"), b.get("link"))
    applied = [] if shared else [r for r in matched if r.get("purpose") == "ap_allow"] if switched else matched
    if shared:
        for st in steps[len(barriers):]:
            st["not_applied"] = True
            st["text"] += " (not applied: same non-Firewalla switch)"
        notes.append(f"Both are wired to a switch that isn't Firewalla's, on {a['segment']}: their traffic never reaches "
                     "anything Firewalla has, so no rule, VqLAN, Isolation or Allowed Devices decides it.")
    if switched and not shared:
        for st, r in zip(steps[len(barriers):], matched):
            if r.get("purpose") != "ap_allow":
                st["not_applied"] = True
                st["text"] += " (not applied: same network)"
        if any(r.get("purpose") != "ap_allow" for r in matched):
            notes.append("Both clients are on the same network, so their traffic goes through the switches and access "
                         "points and the router's rules never see it (tested 16 Nov, wired and Wi-Fi): only VqLAN, "
                         "Isolation and Allowed Devices decide.")
        local_blocks = [r for r in matched if r.get("action") == "block" and (r.get("matching") or {}).get("kind") == "local_networks"]
        # Firewalla's own fix for that is an allow rule for the network
        # itself (#824 Wifi to Wifi here): then it's certain again.
        net_allow = any(r.get("action") == "allow" and (r.get("matching") or {}).get("kind") == "network"
                        and str((r.get("matching") or {}).get("id")) == str(a.get("network")) for r in matched)
        if on_air and local_blocks and not net_allow:
            uncertain = True
            notes.append(f"Rule #{local_blocks[0].get('pid')} {access_rule_text(local_blocks[0])} blocks All Local Networks: "
                         "Firewalla says that does block within a network on AP7 Wi-Fi (not tested), unless an allow "
                         "rule for the network lets it through.")
    allows = [r for r in applied if r.get("action") == "allow"]
    if shared:
        verdict = "allowed"
        deciding = {"kind": "segment", "text": f"Same non-Firewalla switch ({a['segment']}): Firewalla never sees it"}
    elif unlifted:
        verdict, decider = "blocked", unlifted[0]
        decider["decides"] = True
        if allows:
            listed = access_target_list_side(allows[0])
            notes.append(f"Rule #{allows[0].get('pid')} {access_rule_text(allows[0])} allows this pair, but "
                         + ("a target-list allow never opens Isolation, and opens VqLAN only between different networks "
                            "(tested 16 Nov): only Allowed Devices opens both." if listed else
                            "an ordinary allow rule doesn't open VqLAN or Isolation: only Allowed Devices does "
                            "(a target-list allow between different networks opens VqLAN, not Isolation)."))
        deciding = {"kind": decider["kind"], "group": decider["group"], "text": decider["text"]}
    elif applied:
        winner = applied[0]
        verdict = "allowed" if winner.get("action") == "allow" else "blocked"
        steps[len(barriers) + matched.index(winner)]["decides"] = True
        deciding = {"kind": "rule", "pid": winner.get("pid"), "text": access_rule_text(winner)}

        if verdict == "blocked" and allows:
            uncertain = True
            notes.append(f"Allow rule #{allows[0].get('pid')} also matches; the block wins because it is "
                         f"{'in an earlier tier' if (winner.get('seq') or 2) < (allows[0].get('seq') or 2) else 'more specific'}.")
    elif switched and matched:
        verdict = "allowed"
        deciding = {"kind": "switched", "text": "Same network: the router's rules don't see it"}
    else:
        verdict = "allowed"
        deciding = {"kind": "none", "text": "Nothing blocks it"}
    # A target-list rule that may cover the pair (its list isn't readable
    # here and no traffic credited to it was seen) and would change the
    # verdict makes the verdict uncertain.
    # Only one that would outrank the rule deciding today (real test 11, 16
    # Nov 2026: a group-level Block didn't beat Phone B's device-level
    # Allowed Devices entry to the NAS).
    # Behind VqLAN or Isolation, an allow list can only matter if every
    # barrier left is VqLAN and the pair crosses networks (it never opens
    # Isolation: real test 8).
    could_open = across and all(x["kind"] == "vqlan" for x in unlifted)
    flips = [r for r in possible if (r.get("action") == "allow") == (verdict == "blocked")
             and (deciding.get("kind") != "rule" or rank(r) < rank(applied[0]))
             and (not unlifted or could_open)] if lists_uncertain and not switched else []
    if flips:
        uncertain = True
        notes.append(f"Rule #{flips[0].get('pid')} {access_rule_text(flips[0])} uses a target list whose entries "
                     f"haven't been read from your MSP yet: it may {flips[0].get('action')} this connection.")
    for step in steps:
        if step.get("ports"):
            notes.append(f"Rule #{step['pid']} {step['text']} covers this pair only on {step['ports']}.")
    # Monitoring Off or Emergency Access on either device: nothing above is
    # enforced for its traffic, nor for the other device's traffic with it.
    if paused is None:
        paused = {x["mac"]: why for x in (a, b) if (why := access_paused(x))}
    off = {x["mac"] for x in (a, b) if x["mac"] in paused}
    if off:
        why = "; ".join(dict.fromkeys(paused[x["mac"]] for x in (a, b) if x["mac"] in off))
        if verdict == "blocked":
            for st in steps:
                st.pop("decides", None)
            notes.insert(0, f"{why}: Firewalla isn't enforcing rules, VqLAN or Isolation for it, so "
                            f"{(deciding.get('text') or 'what blocks this')} doesn't apply while that lasts.")
            # Either device paused lifts the other's blocks too (real tests 5
            # and 10, 16 Nov 2026: Monitoring Off, then Emergency Access, on
            # A's PC let isolated B's PC reach it and be reached).
            verdict = "allowed"
        else:
            notes.insert(0, f"{why}: Firewalla isn't enforcing anything for it while that lasts.")
        deciding = {"kind": "paused", "text": why}
    return {"from": a["mac"], "to": b["mac"], "verdict": verdict, "uncertain": uncertain,
            "deciding": deciding, "steps": steps, "notes": notes}


def access_local_rows(hours=24, mac=None):
    """The hourly local traffic rows of the last hours (with one client, or
    all): (src, dst, outcome, protocol, port, connections, records, bytes,
    last, allowed_by, blocked_by). Connections are connections started
    (D-883); records are the router's, for the summary-line check
    (access_summary_only). A blocked try at a client not answering has the
    outcome "unanswered", not "blocked": the one definition every page uses
    (D-913, policy.local_block_kind)."""
    from policy import local_block_kind   # here: policy imports this module
    since = int((time.time() - hours * 3600) // 3600 * 3600)
    flush_local_traffic()
    with local_traffic_connection() as connection:
        rows = connection.execute(
            "SELECT src_mac, dst_mac, outcome, protocol, port, COALESCE(starts, flows), flows, bytes_sent + bytes_received,"
            " first_ts, last_ts, allowed_by, blocked_by FROM local_traffic_hourly WHERE hour >= ?"
            + (" AND (src_mac = ? OR dst_mac = ?)" if mac else ""), (since, mac, mac) if mac else (since,)).fetchall()
    out = []
    for src, dst, outcome, protocol, port, n, records, size, first, last, allowed_by, blocked_by in rows:
        if outcome == "blocked" and local_block_kind(src, dst, protocol, port, blocked_by, size, first, last) != "real":
            outcome = "unanswered"
        out.append((src, dst, outcome, protocol, port, n or 0, records or 0, size or 0, last, allowed_by, blocked_by))
    return out


def access_seen(mac, hours=24):
    """Recorded local traffic with one device: (initiator, responder) ->
    allowed connections (and their router records), blocked attempts,
    tries at it while not answering, bytes, last seen, main ports and the
    rules the router said allowed them."""
    rows = access_local_rows(hours, mac)
    seen = {}
    for src, dst, outcome, protocol, port, flows, records, total, last, allowed_by, blocked_by in rows:
        entry = seen.setdefault((src, dst), {"flows": 0, "records": 0, "blocked": 0, "unanswered": 0, "bytes": 0, "last_seen": None,
                                             "ports": {}, "allowed_by": set(), "blocked_by": set()})
        entry["blocked_by"].update(p for p in (blocked_by or "").split(",") if p)
        entry[{"blocked": "blocked", "unanswered": "unanswered"}.get(outcome, "flows")] += flows
        if outcome == "allowed":
            entry["records"] += records
        entry["bytes"] += total
        entry["last_seen"] = max(entry["last_seen"] or 0, last or 0)
        label = f"{protocol.upper()} {port}" if protocol else "same network"
        entry["ports"][label] = entry["ports"].get(label, 0) + (total or 0)
        entry["allowed_by"].update(p for p in (allowed_by or "").split(",") if p)
    for entry in seen.values():
        entry["ports"] = [p for p, _ in sorted(entry["ports"].items(), key=lambda kv: -kv[1])[:3]]
        entry["allowed_by"] = sorted(entry["allowed_by"])
        entry["blocked_by"] = sorted(entry["blocked_by"])
    return seen


def access_credited(seen, a, b):
    """Rules the router named as allowing a -> b traffic (from access_seen)."""
    return (seen.get((a["mac"], b["mac"])) or {}).get("allowed_by") or ()


def access_name(mac):
    return next((d.get("name") for d in state.get("devices") or [] if str(d.get("mac") or "").upper() == mac), None) or mac


def access_with_seen(result, seen):
    """Adds what the recorder saw to one direction's verdict, and flags
    allowed traffic the model says should be blocked."""
    entry = seen.get((result["from"], result["to"]))
    result["seen"] = entry
    # Device Active Protect can also hold a device to the local devices it
    # has learned (local state "active"); the rules don't show that, so an
    # allowed verdict nobody has seen is only probable.
    protected = [mac for mac in (result["from"], result["to"])
                 if (access_device_protect.get(mac) or {}).get("local") == "active"]
    if protected and result["verdict"] == "allowed" and not (entry and entry["flows"]):
        result["uncertain"] = True
        result["notes"].append("Device Active Protect is active for local traffic on "
                               + " and ".join(access_name(mac) for mac in protected)
                               + ": it may block local connections it hasn't learned, which the rules don't show.")
    # The router's own record beats the model (owner, 22 Nov 2026: NAS DS923+
    # Main -> PC B, TCP 445). The rules looked like Allowed Devices
    # (#858) allows it, but every try the NAS started was blocked and the
    # router named #829. When every connection one way was blocked and the
    # router named a rule for it, that way is blocked by that rule. Any
    # allowed connection that way, however small, keeps the rules' verdict
    # (22 Nov 2026: two tiny test connections looked like the router's
    # summary records and the NAS showed as blocked).
    named = [x[5:] for x in (entry or {}).get("blocked_by") or () if str(x).startswith("rule:")]
    if result["verdict"] == "allowed" and entry and entry["blocked"] and not entry["flows"] and named:
        rule = policy_rule_for_pid(named[0])
        text = f"#{named[0]} {access_rule_text(rule)}" if rule else f"Rule {named[0]}"
        expected = (result.get("deciding") or {}).get("text") or "your rules"
        result["verdict"], result["uncertain"] = "blocked", False
        result["deciding"] = {"kind": "router", "pid": named[0], "text": text, "expected": expected}
        result["notes"].insert(0, f"The router blocked every connection {access_name(result['from'])} started to "
                                  f"{access_name(result['to'])} in the last 24 hours and named {text}, although your rules "
                                  f"looked like {expected} allows it. This goes by what the router did.")
    result["evidence"] = access_evidence(result["verdict"], entry)
    if result["evidence"]["kind"] == "contradicted":
        result["conflict"] = True
        result["notes"].append(f"The router reported {entry['flows']} allowed connections in the last 24 hours, "
                               f"which this check says should be blocked.")
    return result


# ============================================================
# RULES AGAINST TRAFFIC (owner, 16 Nov 2026)
#
# check_local_access says what the rules do; the local-traffic recorder
# shows what happened. Every answer says which it is:
#   proven       - the recorded traffic agrees (allowed and seen talking,
#                  or blocked and the router recorded the block);
#   unproven     - nothing recorded either way in 24 hours (never tried,
#                  or on one network, where the router sees nothing);
#   contradicted - blocked, yet the router recorded allowed connections.
# The router's summary record after a burst of blocked tries (one tiny
# "allowed" record) is a blocked try, never a contradiction: the same rule
# as Policy's violations (owner, 19 Nov 2026; 22 Nov 2026 for these pages,
# when Rules vs Actual Traffic was dropped for Policy's violations).
# The Groups page's Can Talk To uses it for every pair (groups_reach).
# ============================================================
ACCESS_SUMMARY_BYTES = 2048   # an allowed record this small, after blocked tries, is the router's summary
groups_reach_cache = {"at": 0, "data": None}
groups_reach_lock = threading.Lock()
GROUPS_REACH_SECONDS = 120


def access_summary_only(entry):
    """Its allowed records are only the router's summary of blocked tries."""
    records = (entry or {}).get("records", (entry or {}).get("flows")) or 0   # per router record, not per connection
    return bool((entry or {}).get("blocked") and records and ((entry or {}).get("bytes") or 0) <= ACCESS_SUMMARY_BYTES * records)


def access_evidence(verdict, entry):
    flows, blocked = (entry or {}).get("flows") or 0, (entry or {}).get("blocked") or 0
    if verdict == "blocked":
        kind = "contradicted" if flows and not access_summary_only(entry) else "proven" if blocked or flows else "unproven"
    else:
        kind = "proven" if flows else "unproven"
    return {"kind": kind, "flows": flows, "blocked": blocked, "last_seen": (entry or {}).get("last_seen")}


def access_seen_all(hours=24):
    """Recorded local traffic between every pair: (initiator, responder) ->
    allowed flows and their bytes, blocked attempts, when each was last
    seen, and the rules the router said allowed them."""
    seen = {}
    for src, dst, outcome, _protocol, _port, flows, records, size, last, allowed_by, blocked_by in access_local_rows(hours):
        entry = seen.setdefault((src, dst), {"flows": 0, "records": 0, "blocked": 0, "unanswered": 0, "bytes": 0, "last_seen": None,
                                             "allowed_last": 0, "blocked_last": 0, "allowed_by": set(), "blocked_by": set()})
        entry["blocked_by"].update(p for p in (blocked_by or "").split(",") if p)
        if outcome == "unanswered":   # a try at a client not answering: not a block (D-913)
            entry["unanswered"] += flows
            continue
        side = "blocked" if outcome == "blocked" else "flows"
        entry[side] += flows
        if side == "flows":
            entry["bytes"] += size
            entry["records"] += records
        entry["blocked_last" if side == "blocked" else "allowed_last"] = max(entry["blocked_last" if side == "blocked" else "allowed_last"], last or 0)
        entry["last_seen"] = max(entry["last_seen"] or 0, last or 0)
        entry["allowed_by"].update(p for p in (allowed_by or "").split(",") if p)
    return seen


def groups_reach():
    """Can Talk To for the Groups page: for every group, the groups its
    members can talk to, device by device, by the full check (rules,
    VqLAN, Isolation on groups and single devices, Allowed Devices, target
    lists, same-network switching, Monitoring Off and Emergency Access).
    A pair talks when a connection is allowed both ways; "one way" when
    only one. A device is good (every member of the group talks to it both
    ways), bad (none does, either way) or warn; a group likewise from its
    devices, and one no member can reach is left out. Kept 2 minutes."""
    with groups_reach_lock:
        if groups_reach_cache["data"] and time.time() - groups_reach_cache["at"] < GROUPS_REACH_SECONDS:
            return groups_reach_cache["data"]
        started = time.time()
        sides, groups = access_sides()
        # Just after a start, before the router's devices, groups and rules
        # are read (router_ready): keep the last answer, never an empty one
        # for 2 minutes (25 Nov 2026: every group showed "no group it can
        # reach"). groups None = the page shows "Working it out…".
        if not router_ready() or not sides or not groups:
            return groups_reach_cache["data"] or {"groups": None, "clients": {}, "updated_at": time.time(), "took": 0, "pairs": 0}
        rules, iso, seen = access_local_rules(), access_isolated(), access_seen_all()
        paused = {mac: why for mac, side in sides.items() if (why := access_paused(side))}
        # A client in no group counts here as a group of its own (owner, 22 Nov
        # 2026: the Groups table lists it with its own Can Talk To, and groups
        # that reach it show it). Network equipment isn't a client. The real
        # groups still decide the rules check.
        grouped = {str(m).upper() for g in groups.values() for m in g.get("members") or []}
        alone = {f"c:{mac}": {"id": f"c:{mac}", "name": side["name"], "members": [mac], "isolation": False, "client": True}
                 for mac, side in sides.items() if mac not in grouped and not access_is_gear(side)}
        units = {**groups, **alone}
        members = {gid: [sides[m] for m in (str(x).upper() for x in g.get("members") or []) if m in sides] for gid, g in units.items()}
        done = {}

        def one(a, b):
            key = (a["mac"], b["mac"])
            if key not in done:
                entry = seen.get(key)
                r = check_local_access(a, b, groups, rules, (entry or {}).get("allowed_by") or (), isolated=iso, paused=paused)
                evidence = access_evidence(r["verdict"], entry)
                # "Traffic disagrees": the rules block it, yet real connections
                # got through (not the router's summary of blocked tries).
                # Ports (owner, 25 Nov 2026): an allow through a target list
                # limited to ports (the rule that decides, or the one that
                # opens VqLAN) gets through on those only; None = every port.
                lifters = {x.get("lifted_by") for x in r["steps"] if x.get("lifted_by")}
                ports = [x["ports"] for x in r["steps"] if x.get("ports") and x.get("effect") == "allow"
                         and not x.get("not_applied") and (x.get("decides") or x.get("pid") in lifters)]
                done[key] = (r["verdict"] == "allowed", bool(r["uncertain"]), (r.get("deciding") or {}).get("text") or "",
                             evidence, evidence["kind"] == "contradicted", ports or None)
            return done[key]

        out = {}
        for xid, x in units.items():
            talk = []
            for yid, y in units.items():
                own = xid == yid
                if own and x.get("client"):
                    continue   # a single client has no "its own members"
                devs = []
                for d in members[yid]:
                    both = one_way = none = flows = 0
                    unsure = contra = every_port = reached = False
                    last, why, example, ports = 0, "", None, []
                    for m in members[xid]:
                        if m["mac"] == d["mac"]:
                            continue
                        there, back = one(m, d), one(d, m)
                        n = there[0] + back[0]
                        both, one_way, none = both + (n == 2), one_way + (n == 1), none + (n == 0)
                        unsure = unsure or there[1] or back[1]
                        for r in (there, back):
                            if r[0]:
                                reached = True
                                every_port = every_port or not r[5]
                                ports += [p for p in r[5] or () if p not in ports]
                            flows += r[3]["flows"]
                            last = max(last, r[3]["last_seen"] or 0) if r[3]["flows"] else last
                            if r[4]:
                                contra, example = True, m["mac"]
                            if not r[0] and not why:
                                why = r[2]
                        if n < 2 and not example:
                            example = m["mac"]
                    pairs = both + one_way + none
                    if not pairs:   # the group's only member, seen from its own group
                        tone = "bad" if own and x.get("isolation") else "good"
                    else:
                        tone = "good" if both == pairs else "bad" if none == pairs else "warn"
                    devs.append({"mac": d["mac"], "tone": tone, "one_way": bool(one_way), "unsure": unsure, "flows": flows,
                                 "last_seen": last or None, "contra": contra, "why": "" if tone == "good" else why,
                                 "check": example or next((m["mac"] for m in members[xid] if m["mac"] != d["mac"]), None),
                                 # Where it is reached (owner, 25 Nov 2026): ports = the ports a target
                                 # list limits it to, [] for All Ports; every_port: some members (or
                                 # one way) reach it on every port.
                                 **({"ports": ports, "every_port": every_port} if reached else {})})
                if own and (not devs or not members[xid]):
                    tone = "bad" if x.get("isolation") else "good"
                elif not devs or not members[xid]:
                    continue
                else:
                    tone = "good" if all(v["tone"] == "good" for v in devs) else "warn" if any(v["tone"] != "bad" for v in devs) else "bad"
                if own or tone != "bad":
                    talk.append({"group": yid, "own": own, "tone": tone, "devs": devs})
            # Its own group first, then groups by name, then single clients.
            talk.sort(key=lambda t: (not t["own"], bool((units.get(t["group"]) or {}).get("client")), str((units.get(t["group"]) or {}).get("name") or "").lower()))
            out[str(xid)] = talk
        data = {"groups": out, "clients": {cid: {"name": c["name"], "mac": c["members"][0]} for cid, c in alone.items()},
                "updated_at": time.time(), "took": round(time.time() - started, 2), "pairs": len(done)}
        groups_reach_cache.update({"at": time.time(), "data": data})
        return data


@app.get("/api/groups-reach")
def api_groups_reach():
    return groups_reach()


def access_internet(side):
    """What a client may do on the internet, in one line."""
    rules = [r for r in (state.get("policy_rules") or {}).get("rules") or [] if r.get("disabled") is not True]
    blocks = [r for r in rules if r.get("action") == "block" and r.get("type") == "mac"
              and r.get("purpose") != "dap" and access_covers(r.get("applies_on"), side)]
    if blocks:
        return {"verdict": "blocked", "pid": blocks[0].get("pid"),
                "text": f"Rule #{blocks[0].get('pid')} blocks all its internet traffic"}
    dap = [r for r in rules if r.get("purpose") == "dap" and r.get("action") == "block"
           and access_covers(r.get("applies_on"), side)]
    if dap:
        return {"verdict": "limited", "pid": dap[0].get("pid"),
                "text": "Device Active Protect: only the destinations it has learned"}
    everyone = sum(1 for r in rules if r.get("action") == "block" and (r.get("applies_on") or {}).get("kind") == "all_devices")
    return {"verdict": "allowed", "pid": None,
            "text": f"Allowed · {everyone} rules for every client block some countries, categories and domains"}


def access_side_out(side, groups):
    return {**side, "group_names": [(groups.get(g) or {}).get("name") or g for g in side["groups"]],
            "protect": access_device_protect.get(side["mac"])}


@app.get("/api/access/check")
def api_access_check(a: str, b: str):
    """Can a reach b, and b reach a? Both directions with the deciding
    rule or setting, every step in the way and the traffic seen in 24 h."""
    sides, groups = access_sides()
    side_a, side_b = sides.get(str(a).upper()), sides.get(str(b).upper())
    if not side_a or not side_b:
        return {"error": "Unknown client"}
    if side_a["mac"] == side_b["mac"]:
        return {"error": "Pick two different clients"}
    rules = access_local_rules()
    seen = access_seen(side_a["mac"])
    directions = [access_with_seen(check_local_access(side_a, side_b, groups, rules,
                                                      access_credited(seen, side_a, side_b)), seen),
                  access_with_seen(check_local_access(side_b, side_a, groups, rules,
                                                      access_credited(seen, side_b, side_a)), seen)]
    for d in directions:
        # "made 15 Nov from your Policy decision" when Show Me How made the rule.
        if (pid := (d.get("deciding") or {}).get("pid")):
            d["made"] = change_made_by(pid)
    return {"a": {**access_side_out(side_a, groups), "also_on": access_also_on(side_a)},
            "b": {**access_side_out(side_b, groups), "also_on": access_also_on(side_b)},
            "directions": directions, "updated_at": time.time()}


# ============================================================
# EVERY PAIR (the Access Test of 19 Nov 2026, folded into Show Me How 22
# Nov 2026): A and B are devices, groups or networks; a direction (A → B,
# or both), a protocol and port, and the test condition (expect: allowed
# or blocked). Every pair is checked by the same model as the rest of the
# dashboard: what the rules do, whether the condition is true (pass), the
# traffic seen in 24 hours, and the pair's steps (FAULT = the step that
# keeps the condition from being true). Read only.
# ============================================================
ACCESS_TEST_MAX_PAIRS = 6000   # two groups of 50, both ways (owner tested G14 x G12, 20 Nov 2026)


def access_test_refs(text):
    return [r[:80] for r in str(text or "").split(",") if r][:300]


def access_test_seen(pairs, port):
    """Connections in the last 24 hours per (from, to): {allowed, blocked,
    bytes (of the allowed ones)}, on the port tested (all ports when none
    is). "summary": the allowed ones are only the router's summary of
    blocked tries (access_summary_only)."""
    want = {(a, b) for a, b in pairs}
    out = {}
    proto, number = port if isinstance(port, tuple) else (None, None)
    for src, dst, outcome, protocol, p, flows, records, size, _last, _allowed_by, _blocked_by in access_local_rows(24):
        if (src, dst) not in want:
            continue
        if proto and str(protocol).lower() != proto:
            continue
        if isinstance(number, int) and str(p) != str(number):
            continue
        x = out.setdefault((src, dst), {"allowed": 0, "blocked": 0, "unanswered": 0, "bytes": 0, "records": 0})
        if outcome in ("allowed", "blocked", "unanswered"):
            x[outcome] += flows
        if outcome == "allowed":
            x["bytes"] += size
            x["records"] += records
    for x in out.values():
        x["summary"] = access_summary_only({"flows": x["allowed"], "records": x["records"], "blocked": x["blocked"], "bytes": x["bytes"]})
    return out


def access_test_steps(result, expect):
    """A pair's steps, each tagged OK or FAULT: FAULT is what makes the
    router's answer differ from what you expect (the rule or setting that
    decides it, and for an unexpected allow the allow that opened the way)."""
    verdict = result["verdict"]
    fault = verdict != expect
    lifters = {x.get("lifted_by") for x in result["steps"] if x.get("lifted_by")}
    steps = []
    for x in result["steps"]:
        is_fault = fault and (x.get("decides") or (verdict == "allowed" and x.get("pid") in lifters))
        word = "blocks" if x.get("effect") == "block" else "allows"
        text = x["text"] + (f" · lifted by #{x['lifted_by']}" if x.get("lifted_by") else "") + (f" · {x['detail']}" if x.get("detail") else "")
        steps.append({"tag": "FAULT" if is_fault else "OK", "text": text, "effect": word, "decides": bool(x.get("decides"))})
    if fault and not any(s["tag"] == "FAULT" for s in steps):
        steps.append({"tag": "FAULT", "text": result["deciding"].get("text") or "Nothing blocks it", "effect": "decides", "decides": True})
    return steps


@app.get("/api/access/test")
def api_access_test(a: str = "", b: str = "", dir: str = "ab", proto: str = "any", port: str = "", expect: str = "allowed"):
    """Run an Access Test (see above)."""
    sides, groups = access_sides()
    rules = access_local_rules()
    iso = access_isolated()
    expect = "blocked" if expect in ("blocked", "block") else "allowed"
    check, _, words = howto_port(proto, port)
    # Each side in name order (owner, 20 Nov 2026: the Every Pair grid sorted both ways).
    by_name = lambda xs: sorted(xs, key=lambda s: s["name"].lower())
    srcs, _, a_picked = howto_expand(access_test_refs(a), sides, groups)
    dsts, _, b_picked = howto_expand(access_test_refs(b), sides, groups)
    srcs, dsts = by_name(srcs), by_name(dsts)
    if not srcs or not dsts:
        return {"error": "Pick A and B first."}
    ways = {"ab": ["ab"], "ba": ["ba"], "both": ["ab", "ba"]}.get(dir, ["ab"])
    pairs = []
    for x in srcs:
        for y in dsts:
            if x["mac"] == y["mac"]:
                continue
            for w in ways:
                pairs.append((w, x, y) if w == "ab" else (w, y, x))
    cut = len(pairs) > ACCESS_TEST_MAX_PAIRS
    pairs = pairs[:ACCESS_TEST_MAX_PAIRS]
    seen = access_test_seen([(f["mac"], t["mac"]) for _, f, t in pairs], check)
    out = []
    for w, f, t in pairs:
        r = check_local_access(f, t, groups, rules, port=check, isolated=iso)
        n = seen.get((f["mac"], t["mac"])) or {"allowed": 0, "blocked": 0}
        out.append({"way": w, "from": {"mac": f["mac"], "name": f["name"]}, "to": {"mac": t["mac"], "name": t["name"]},
                    "a": f["mac"] if w == "ab" else t["mac"], "b": t["mac"] if w == "ab" else f["mac"],
                    "verdict": r["verdict"], "pass": r["verdict"] == expect, "uncertain": r["uncertain"],
                    "deciding": r["deciding"].get("text") or "", "pid": r["deciding"].get("pid"),
                    "steps": access_test_steps(r, expect), "notes": r["notes"], "seen": n})
    test = {"a": a_picked, "b": b_picked, "a_devices": [{"mac": s["mac"], "name": s["name"]} for s in srcs],
            "b_devices": [{"mac": s["mac"], "name": s["name"]} for s in dsts], "dir": dir, "words": words, "expect": expect,
            "pairs": out, "cut": cut, "updated_at": time.time()}
    return test


# ============================================================
# OPEN BUT UNUSED (owner, 19 Nov 2026; it replaced the Who Talks to Whom
# matrix): on the Groups page, two tables of access your rules give that
# nothing has used in 30 days.
#   Ports:   a rule (or port forward) granting ports nobody used (Unused:
#            Close It) or only some of them (Partly Used: Narrow It).
#   Clients: a device a rule covers (itself or through its group) that
#            never used it, or not in 30 days (Take It Off / Close It).
# Covers your own allow rules between devices (Allowed Devices / VqLAN
# exceptions, network and target-list allows), internet allow rules, and
# port forwards. Not Firewalla's own Device Active Protect lists. "Used" =
# traffic the router credited to that rule (local: the recorder's daily
# rows, kept a year; internet and port forwards: kept here, from the flow
# history every 5 minutes, since this was built). Two devices on one
# network talk through the switches and access points, so the router never
# sees it: such rules can't be judged and are only counted.
# Keep Open hides a row until its rule changes; Undo brings it back.
# ============================================================
OPEN_UNUSED_FILE = os.environ.get("FIREWALLA_OPEN_UNUSED_FILE", "/data/open_unused.json")
OPEN_UNUSED_DAYS = 30
open_unused_lock = threading.Lock()


def open_unused_load():
    st = policy_read_json(OPEN_UNUSED_FILE) or {}
    for k in ("rules", "forwards", "kept"):
        st.setdefault(k, {})
    return st


def open_unused_save(st):
    temporary = OPEN_UNUSED_FILE + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(st, handle)
    os.replace(temporary, OPEN_UNUSED_FILE)


def open_unused_private(ip):
    try:
        return ipaddress.ip_address(str(ip)).is_private
    except ValueError:
        return False


def open_unused_track(now=None):
    """Internet allow rules and port forwards: when each was last used, per
    port and per device, from the flow history since the last look."""
    from flows import flow_history_reader
    from policy import local_port_label
    now = now or time.time()
    with open_unused_lock:
        st = open_unused_load()
    # From 10 minutes before the last look: a flow can reach the history a
    # few minutes after it happened, and one that arrived after the last
    # look was never counted. Only the newest time per rule and port is
    # kept, so reading the overlap twice changes nothing.
    since = (st.get("checked_at") or now - 86400) - 600
    forwards = [m for m in (feature_settings.get("box") or {}).get("port_forward_maps") or [] if m.get("enabled")]
    with flow_history_reader() as connection:
        rows = connection.execute("""
            SELECT allowed_pid, device_mac, LOWER(protocol), port, MAX(event_at) FROM flow_records
            WHERE kind = 'normal' AND allowed_pid IS NOT NULL AND allowed_pid != '' AND event_at > ?
            GROUP BY 1, 2, 3, 4""", (since,)).fetchall()
        hits = []
        for m in forwards:
            if m["to_port"].isdigit():
                for remote, last in connection.execute("""
                        SELECT remote_ip, MAX(event_at) FROM flow_records WHERE kind = 'normal' AND event_at > ?
                        AND (UPPER(device_mac) = ? OR device_ip = ?) AND port = ? GROUP BY 1""",
                        (since, m["to_mac"], m["to_ip"], int(m["to_port"]))):
                    if remote and not open_unused_private(remote):
                        hits.append((m, last))
    granted = open_unused_granted()
    with open_unused_lock:
        st = open_unused_load()
        st.setdefault("since", now)
        for pid, mac, proto, port, last in rows:
            r = st["rules"].setdefault(str(pid), {"last": 0, "ports": {}, "clients": {}})
            r["last"] = max(r["last"], last or 0)
            key = open_unused_port_label(proto, port, granted.get(str(pid))) if port else (proto or "any").upper()
            r["ports"][key] = max(r["ports"].get(key, 0), last or 0)
            if mac:
                r["clients"][str(mac).upper()] = max(r["clients"].get(str(mac).upper(), 0), last or 0)
        for m, last in hits:
            key = f"{m['proto']}|{m['port']}|{m['to_mac'] or m['to_ip']}"
            f = st["forwards"].setdefault(key, {"last": 0})
            f["last"] = max(f["last"], last or 0)
        # What no longer exists leaves the file (20 Nov 2026: nothing ever
        # did): the times of rules and port forwards that were deleted, and
        # the Keep Open marks on their rows. Only once the router's rules
        # and port forwards have been read (never just after a restart).
        known = state.get("policy_rules") or {}
        if known.get("updated_at"):
            pids = {str(r.get("pid")) for r in known.get("rules") or []}
            st["rules"] = {pid: r for pid, r in st["rules"].items() if pid in pids}
            st["kept"] = {rid: k for rid, k in st["kept"].items() if rid.startswith("f|") or rid.split("|")[1] in pids}
        box = feature_settings.get("box") or {}
        if "port_forward_maps" in box:
            live = {f"{m['proto']}|{m['port']}|{m['to_mac'] or m['to_ip']}" for m in box["port_forward_maps"] or []}
            st["forwards"] = {key: f for key, f in st["forwards"].items() if key in live}
            st["kept"] = {rid: k for rid, k in st["kept"].items() if not rid.startswith("f|") or rid[2:] in live}
        st["checked_at"] = now
        open_unused_save(st)


def open_unused_granted():
    """{rule number: the exact port labels it grants ("TCP 55443"), or None
    when it grants any port or a range}."""
    return {str(r.get("pid")): open_unused_grants(r)[1] for r in (state.get("policy_rules") or {}).get("rules") or []}


def open_unused_port_label(protocol, port, granted):
    """The label a used port is filed under. A random port (32768 and up) is
    "TCP random ports", as everywhere, unless the rule grants that very port
    (a list line "x,tcp:55443"): then it is filed as itself (24 Nov 2026: it
    went under random ports, so a granted high port in daily use always
    read as never used, and Narrow It would take it away)."""
    from policy import local_port_label
    exact = f"{str(protocol or '').upper()} {port}"
    return exact if granted and exact in granted else local_port_label(protocol, str(port or ""))[1]


def open_unused_local(now):
    """What the router credited to each local allow rule: {pid: {last,
    ports: {label: ts}, clients: {mac: ts}, cp: {mac: {label: ts}}}}, and
    since when it is known. cp: each client's own use per port, for the
    Narrow It choices (owner, 23 Nov 2026, D-920)."""
    from flows import flush_local_traffic, local_traffic_connection
    from policy import local_port_label
    flush_local_traffic()
    out = {}
    with local_traffic_connection() as connection:
        rows = connection.execute("""
            SELECT allowed_by, src_mac, dst_mac, protocol, port, MAX(last_ts) FROM local_traffic_daily
            WHERE outcome = 'allowed' AND allowed_by IS NOT NULL AND allowed_by != '' GROUP BY 1, 2, 3, 4, 5""").fetchall()
        rows += connection.execute("""
            SELECT allowed_by, src_mac, dst_mac, protocol, port, MAX(last_ts) FROM local_traffic_hourly
            WHERE outcome = 'allowed' AND allowed_by IS NOT NULL AND allowed_by != '' GROUP BY 1, 2, 3, 4, 5""").fetchall()
        first = connection.execute("SELECT MIN(first_ts) FROM local_traffic_daily").fetchone()[0]
    granted = open_unused_granted()
    for credited, src, dst, proto, port, last in rows:
        for pid in str(credited).split(","):
            r = out.setdefault(pid.strip(), {"last": 0, "ports": {}, "clients": {}})
            r["last"] = max(r["last"], last or 0)
            label = open_unused_port_label(proto, port, granted.get(pid.strip()))
            r["ports"][label] = max(r["ports"].get(label, 0), last or 0)
            for mac in (src, dst):
                r["clients"][str(mac).upper()] = max(r["clients"].get(str(mac).upper(), 0), last or 0)
                cp = r.setdefault("cp", {}).setdefault(str(mac).upper(), {})
                cp[label] = max(cp.get(label, 0), last or 0)
    return out, first or now


def open_unused_is_local(r):
    """True when a rule's target is your own clients (judged from local
    traffic), False for the internet (judged from the flow history). A target
    list counts as local only when it names private addresses (owner, 22 Nov
    2026: T04 PC Allowed Sites and T05 Paramount+ Sites, lists of web sites,
    were filed as Local and shown Unused), and so does a rule on one private
    address (the SSH rules to the cabin router, 192.168.50.1)."""
    if r.get("purpose") == "ap_allow" or r.get("type") in ("network", "intranet", "tag", "device"):
        return True
    side = access_target_list_side(r)
    if side:
        targets = (msp["lists"].get(str((r.get(side) or {}).get("id"))) or {}).get("targets")
        if targets is None:
            return True   # the list isn't read yet: as before
        return any(open_unused_private(str(t).split(",")[0].split("/")[0].strip("[]")) for t in targets)
    if (r.get("matching") or {}).get("kind") == "ip":
        return open_unused_private(str(r.get("target") or "").split(",")[0].split("/")[0])
    return False


def open_unused_members(obj, sides):
    """The devices a rule's On / Matching side covers."""
    kind = (obj or {}).get("kind")
    if kind == "all_devices":
        return list(sides)
    return [m for m, s in sides.items() if access_covers(obj, s)]


def open_unused_grants(r):
    """(what it grants in words, the exact port labels when it names single
    ports, else None = any port)."""
    if r.get("purpose") == "ap_allow":
        return "any port, both ways", None
    if access_target_list_side(r):
        entries = access_list_entries(r) or []
        labels = set()
        for e in entries:
            if not e["ports"] or not e["protocol"]:
                return "any port (its target list)", None
            for low, high in e["ports"]:
                labels.add(f"{e['protocol'].upper()} {low}" if low == high else f"{e['protocol'].upper()} {low}-{high}")
        if not labels:
            return "the ports in its target list", None
        return ", ".join(sorted(labels)), (labels if all("-" not in x for x in labels) else None)
    if r.get("remote_port"):   # a rule limited to ports (22 Nov 2026)
        proto = str(r.get("protocol") or "tcp").upper()
        labels = {f"{proto} {p.strip()}" for p in str(r["remote_port"]).split(",") if p.strip()}
        return ", ".join(sorted(labels)), (labels if all("-" not in x for x in labels) else None)
    if r.get("type") == "dns" or (r.get("matching") or {}).get("kind") == "domain":
        return f"{r.get('target') or 'the site'}, any port", None
    return "any port", None


# NARROW IT CHOICES (owner, 23 Nov 2026, D-920): before a Partly Used or
# Unused local rule goes to Review, a popup shows each client the rule covers
# against each port it grants, with when that client last used it, and you
# tick what each keeps. Clients with the same choice become one Review item.
OPEN_UNUSED_GRID_MAX = 40   # more clients than this (a rule on every client): no popup


def open_unused_grid(r, on, used, exact, sides, cut):
    """{ports, clients: [{mac, name, ports: {label: last or 0}}], on_kind,
    on_name, list: {id, name, shared: [rule names]} or None}, or None when
    the clients can't be listed."""
    side = access_target_list_side(r)
    clients = [m for m in dict.fromkeys(on) if m in sides]
    if not clients or len(clients) > OPEN_UNUSED_GRID_MAX or side == "applies_on":
        return None
    ports = sorted(exact)
    cp = used.get("cp") or {}
    lst = None
    if side:
        lid = str((r.get(side) or {}).get("id"))
        others = [x for x in (state.get("policy_rules") or {}).get("rules") or []
                  if str(x.get("pid")) != str(r.get("pid")) and any(str((x.get(s) or {}).get("id")) == lid and (x.get(s) or {}).get("kind") == "target_list"
                                                                     for s in ("matching", "applies_on"))]
        lst = {"id": lid, "name": (msp["lists"].get(lid) or {}).get("name") or "its target list",
               "shared": [access_rule_text(x) for x in others]}
    on_side = r.get("applies_on") or {}
    return {"ports": ports, "on_kind": on_side.get("kind"), "on_name": on_side.get("name") or on_side.get("label"),
            "list": lst, "clients": [{"mac": m, "name": sides[m]["name"],
                                      "ports": {p: ((cp.get(m) or {}).get(p) or 0) if ((cp.get(m) or {}).get(p) or 0) >= cut else 0 for p in ports}}
                                     for m in sorted(clients, key=lambda m: str(sides[m]["name"]).lower())]}


def open_unused_rows(now=None):
    """The two tables, and what couldn't be judged."""
    from policy import local_port_label
    now = now or time.time()
    sides, groups = access_sides()
    rules = [r for r in (state.get("policy_rules") or {}).get("rules") or []
             if r.get("action") == "allow" and r.get("disabled") is not True and r.get("purpose") != "dap"]
    local_used, local_since = open_unused_local(now)
    with open_unused_lock:
        st = open_unused_load()
    inet_since = st.get("since") or now
    cut = now - OPEN_UNUSED_DAYS * 86400
    ports_rows, client_rows, same_net = [], [], 0
    for r in rules:
        pid = str(r.get("pid"))
        local = open_unused_is_local(r)
        kind = "Local" if local else "Internet"
        on = open_unused_members(r.get("applies_on"), sides)
        other = open_unused_members(r.get("matching"), sides) if local else []
        if local and on and other and all(sides[a].get("network") and sides[a].get("network") == sides[b].get("network") for a in on for b in other if a != b):
            same_net += 1   # switched traffic: the router never sees it
            continue
        used = (local_used if local else st["rules"]).get(pid) or {"last": 0, "ports": {}, "clients": {}}
        since = local_since if local else inet_since
        recent = sorted(p for p, t in used["ports"].items() if t >= cut)
        # The router's own count settles it when the records missed the use
        # (owner, 22 Nov 2026: busy rules were shown Unused): a hit in the last
        # 30 days means used, on the port of its last hit. Which clients use it
        # isn't known then, so no client rows for it.
        by_router = False
        if not recent and (r.get("last_hit_ts") or 0) >= cut:
            hit = r.get("last_hit") or {}
            recent = [local_port_label(str(hit.get("protocol") or ""), str(hit.get("port")))[1] if hit.get("port") else "any port"]
            used = {**used, "last": max(used["last"] or 0, r["last_hit_ts"])}
            by_router = True
        grants, exact = open_unused_grants(r)
        sig = str(r.get("updated_at") or r.get("created_at") or "")
        text = access_rule_text(r)
        where = (r.get("applies_on") or {}).get("label") or "--"
        # A target list by its name, not its id (owner, 20 Nov 2026).
        match = r.get("matching") or {}
        target = ((msp["lists"].get(str(match.get("id"))) or {}).get("name") if match.get("kind") == "target_list" else None)             or match.get("name") or r.get("target") or "--"
        allowed = f"{(r.get('applies_on') or {}).get('name') or 'all clients'} {'↔' if r.get('purpose') == 'ap_allow' else '→'} {target}"
        unused = sorted(exact - set(recent)) if exact else None
        if not recent:
            state_ = "Unused"
        elif (exact is None and r.get("purpose") != "ap_allow" and local) or unused:
            # (An Allowed Devices entry is every port: it can be closed, not
            # narrowed. An internet rule is about its site: browsers use the
            # standard ports, so it is never Partly Used (owner, 20 Nov 2026).)
            state_ = "Partly Used"
        else:
            state_ = None   # every port it grants is in use
        if state_:
            ports_rows.append({"id": f"r|{pid}", "pid": pid, "kind": kind, "rule": text, "where": where, "allowed": allowed,
                               "grants": grants, "used": recent, "unused": unused if exact else (["every other port"] if recent else ["all"]), "state": state_, "last": used["last"] or None,
                               "since": since, "sig": sig, "ap_allow": r.get("purpose") == "ap_allow",
                               "grid": open_unused_grid(r, on, used, exact, sides, cut) if local and exact and not by_router and r.get("purpose") != "ap_allow" else None})
        # Clients: devices the rule covers on its own side, and for an
        # Allowed Devices entry both sides (it works both ways).
        covered = on + (other if r.get("purpose") == "ap_allow" else [])
        if by_router or (len(covered) < 2 and not other and local):
            continue
        # A rule for every device has no client to take off (owner, 20 Nov
        # 2026: three such internet rules listed every device).
        if (r.get("applies_on") or {}).get("kind") == "all_devices":
            continue
        users = [m for m in covered if (used["clients"].get(m) or 0) >= cut]
        for mac in dict.fromkeys(covered):
            last = used["clients"].get(mac) or 0
            if last >= cut or mac not in sides:
                continue
            side_obj = r.get("applies_on") if mac in on else r.get("matching")
            via = "the rule names this client" if (side_obj or {}).get("kind") == "device" else f"member of {(side_obj or {}).get('name') or 'its group'}"
            client_rows.append({"id": f"c|{pid}|{mac}", "pid": pid, "mac": mac, "client": sides[mac]["name"], "how": via, "rule": text,
                                "grants": grants, "state": "Not Lately" if last else "Never", "last": last or None, "since": since,
                                "others": f"{len(users)} of {len(set(covered))} use it", "sig": sig, "kind": kind,
                                "group": (side_obj or {}).get("name") if (side_obj or {}).get("kind") == "group" else None,
                                "ap_allow": r.get("purpose") == "ap_allow"})
    for m in (feature_settings.get("box") or {}).get("port_forward_maps") or []:
        if not m.get("enabled"):
            continue
        key = f"{m['proto']}|{m['port']}|{m['to_mac'] or m['to_ip']}"
        f = st["forwards"].get(key) or {"last": 0}
        if f["last"] >= cut:
            continue
        target = (sides.get(m["to_mac"]) or {}).get("name") or m["to_ip"]
        ports_rows.append({"id": f"f|{key}", "pid": None, "kind": "Port Forward", "rule": f"Port forward \"{m['name'] or m['port']}\"",
                           "where": "router port forwards", "allowed": f"Internet → {target}", "grants": f"{m['proto'].upper()} {m['port']}",
                           "used": [], "state": "Unused", "last": f["last"] or None, "since": inet_since, "sig": key, "forward": m})
    # Rows already sent to Policy say so instead of offering the buttons again.
    from policy import policy_state_load
    # (A Narrow It choice can make several items for one row: "rule|<id>#<n>", D-920.)
    open_items = {k[5:].split("#")[0]: (d.get("status")) for k, d in policy_state_load()["decisions"].items() if k.startswith("rule|") and d.get("status") != "decided"}
    for row in ports_rows + client_rows:
        row["in_policy"] = {"review": "Review", "rule_change": "Pending Action", "confirm": "Pending Confirmation"}.get(open_items.get(row["id"]))
    kept = st["kept"]
    shown = lambda row: row["id"] not in kept or kept[row["id"]].get("sig") != row["sig"]
    return {"ports": [x for x in ports_rows if shown(x)], "clients": [x for x in client_rows if shown(x)],
            "kept": [{**x, "kept_at": kept[x["id"]]["at"]} for x in ports_rows + client_rows if not shown(x)],
            "same_network": same_net, "local_since": local_since, "internet_since": inet_since, "days": OPEN_UNUSED_DAYS}


OPEN_UNUSED_KEEP_SECONDS = 60
open_unused_cache = {"at": 0, "rows": None}


def open_unused_page():
    """The rows as the Groups page shows them, worked out at most once a
    minute: the page asks every 30 seconds, and each time read a year of
    local traffic (20 Nov 2026). Keep Open, Undo and Close It have them
    worked out again at once."""
    if not open_unused_cache["rows"] or time.time() - open_unused_cache["at"] > OPEN_UNUSED_KEEP_SECONDS:
        open_unused_cache.update(rows=open_unused_rows(), at=time.time())
    return open_unused_cache["rows"]


@app.get("/api/open-unused")
def api_open_unused():
    return open_unused_page()


@app.post("/api/open-unused/keep")
def api_open_unused_keep(payload: dict = Body(default={})):
    """Keep Open ({id, keep: true}) hides a row until its rule changes; keep
    false (Undo) shows it again."""
    rid = Fields(payload).text("id", 300, strip=False)
    rows = open_unused_page()
    row = next((x for x in rows["ports"] + rows["clients"] + rows["kept"] if x["id"] == rid), None)
    if not row:
        return {"ok": False, "error": "That row is gone."}
    with open_unused_lock:
        st = open_unused_load()
        if payload.get("keep"):
            st["kept"][rid] = {"at": time.time(), "sig": row["sig"]}
        else:
            st["kept"].pop(rid, None)
        open_unused_save(st)
    open_unused_cache["at"] = 0
    return {"ok": True}


def open_unused_steps(row, sides):
    """Show Me How for closing, narrowing or taking off, in words, with what
    else it changes; and its undo."""
    pid = row.get("pid")
    if row["id"].startswith("f|"):
        m = row["forward"]
        return ([f"Firewalla app › Network › Port Forwarding: delete \"{m['name'] or m['port']}\" ({m['proto'].upper()} {m['port']} → {row['allowed'].split('→ ')[-1]})",
                 "Nothing on your network then answers that port from the internet"], [f"Add the port forward \"{m['name'] or m['port']}\" again"])
    if row["id"].startswith("c|"):
        if row.get("ap_allow") and row["how"] == "the rule names this client":
            return ([f"Firewalla app › {row['rule'].split(':')[0].replace('Allowed Devices of ', '')} › Allowed Devices › press and hold {row['client']} › Delete",
                     "Only this client loses this access"], [f"Add {row['client']} back to that Allowed Devices list"])
        if row.get("group"):
            return ([f"Choose one: (1) move {row['client']} out of {row['group']} into a group that doesn't have this rule (it then loses everything else {row['group']} gives it), "
                     f"or (2) change rule #{pid} ({row['rule']}) to name clients instead of the whole group, leaving {row['client']} out",
                     "Check its other access afterwards with the Access Test"], [f"Put {row['client']} back as it was"])
        return ([f"MSP › Rules › #{pid} {row['rule']}: delete it (it names only this client)"], [f"Create rule #{pid} again"])
    if row.get("ap_allow"):
        return ([f"Firewalla app › {row['rule'].split(':')[0].replace('Allowed Devices of ', '')} › Allowed Devices › press and hold the entry › Delete",
                 "Only these clients lose this access: VqLAN and Isolation keep them apart again"], ["Add the entry back to Allowed Devices"])
    if row["state"] == "Partly Used" and row["used"]:
        return ([f"MSP › Rules › #{pid} {row['rule']}: limit it to {', '.join(row['used'])} (a target list with only those ports, or a port on the rule)",
                 "Traffic on its other ports is then decided by your other rules"], [f"Put rule #{pid} back to any port"])
    return ([f"MSP › Rules › #{pid} {row['rule']}: delete it (or pause it first to try)",
             "What it allowed is then decided by your other rules"], [f"Create rule #{pid} again, or unpause it"])


@app.post("/api/open-unused/act")
def api_open_unused_act(payload: dict = Body(default={})):
    """Close It / Narrow It / Take It Off: the row goes to Policy › Review as
    an item (New Action Block), worked like any other (owner, 19 Nov 2026)."""
    rid = Fields(payload).text("id", 300, strip=False)
    rows = open_unused_page()
    row = next((x for x in rows["ports"] + rows["clients"] if x["id"] == rid), None)
    if not row:
        return {"ok": False, "error": "That row is gone."}
    sides, _ = access_sides()
    steps, undo = open_unused_steps(row, sides)
    from policy import policy_data, policy_flow_new, policy_lock, policy_message, policy_state_load, policy_state_save
    verb = "Take It Off" if rid.startswith("c|") else "Narrow It" if row["state"] == "Partly Used" and row.get("used") else "Close It"
    title = f"{verb}: {row.get('client') + ' · ' if row.get('client') else ''}{row['rule']}"
    now = time.time()
    with policy_lock:
        st = policy_state_load()
        key = "rule|" + rid
        if (st["decisions"].get(key) or {}).get("status") not in (None, "decided"):
            return {"ok": False, "error": "It is already in Policy."}
        # Take It Off / Close It on a local rule: the planner's ways too (D-921).
        macs = [row["mac"]] if row.get("mac") else open_unused_members((next((x for x in (state.get("policy_rules") or {}).get("rules") or []
                                                                                if str(x.get("pid")) == str(row.get("pid"))), {}) or {}).get("applies_on"), sides)
        exact = open_unused_grants(next((x for x in (state.get("policy_rules") or {}).get("rules") or [] if str(x.get("pid")) == str(row.get("pid"))), {}) or {})[1]
        howto = open_unused_howto(row.get("pid"), macs, sorted(exact) if exact else None) if row.get("pid") and verb != "Narrow It" else None
        fid = policy_flow_new(st, "rule", [key], [key], title, now, steps=steps, undo=undo, howto=howto,
                              rule={"id": rid, "pid": row.get("pid"), "sig": row["sig"], "mac": row.get("mac"), "verb": verb,
                                    "what": row.get("client") or row["allowed"], "grants": row["grants"], "kind": row["kind"]})
        st["decisions"][key] = {"intent": "block", "at": now, "label": title, "kind": "chose", "status": "review", "status_at": now, "flow": fid,
                                "rule": {"rule": row["rule"], "what": row.get("client") or row["allowed"], "grants": row["grants"],
                                         "act": f"Narrow to {', '.join(row['used'])}" if verb == "Narrow It" else verb.replace(" It", "")}}
        policy_message(st, now, f"{title}: moved to Policy › Review. Show Me How there walks you through it.")
        policy_state_save(st)
        policy_data(fresh=True)
    open_unused_cache["at"] = 0
    return {"ok": True, "message": f"{title}: moved to Policy › Review."}


def open_unused_howto(pid, macs, labels):
    """The Show Me How request for taking access away from these clients
    (owner, 23 Nov 2026, D-921): Block them to the rule's other side on the
    ports dropped (labels; None = every port), so the Review item gets the
    planner's ways, What Else This Changes and the pictures, like any item.
    None when it can't be asked (an internet rule, ports of two protocols)."""
    r = next((x for x in (state.get("policy_rules") or {}).get("rules") or [] if str(x.get("pid")) == str(pid)), None)
    if not r or not open_unused_is_local(r) or not macs or len(macs) > OPEN_UNUSED_GRID_MAX:
        return None
    sides, _ = access_sides()
    on = open_unused_members(r.get("applies_on"), sides)
    other = open_unused_members(r.get("matching"), sides)
    if access_target_list_side(r) == "matching":
        # A target list names addresses: the clients answering on them (and their reservations).
        lines = (msp["lists"].get(str((r.get("matching") or {}).get("id"))) or {}).get("targets") or []
        ips = {str(t).partition(",")[0].partition(":")[0].strip() for t in lines}
        other = [m for m, s in sides.items() if ips & ({ip for ip in (s.get("ips") or [s.get("ip")]) if ip} | set(howto_reserved(m)))]
    # An Allowed Devices entry works both ways: a client on its matching side is blocked to the On side.
    targets = [m for m in (on if r.get("purpose") == "ap_allow" and all(m in other for m in macs) else other) if m not in macs and m in sides]
    if not targets:
        return None
    proto = port = ""
    if labels is not None:
        protos = {str(x).split(" ")[0].lower() for x in labels}
        if len(protos) != 1 or not protos <= {"tcp", "udp"}:
            return None
        proto, port = protos.pop(), ",".join(str(x).split(" ", 1)[1] for x in labels)
    name = lambda ms: ", ".join(sides[m]["name"] for m in ms[:3]) + (f" +{len(ms) - 3}" if len(ms) > 3 else "")
    return {"act": "block", "a": ",".join("d:" + m for m in macs), "b": ",".join("d:" + m for m in targets), "proto": proto, "port": port,
            "words": f"Block {name(macs)} → {name(targets)} · {', '.join(labels) if labels else 'every port'}"}


def open_unused_howto_for(x):
    """The request for an item made before D-921 (its rule facts)."""
    r = next((y for y in (state.get("policy_rules") or {}).get("rules") or [] if str(y.get("pid")) == str(x.get("pid"))), None)
    if not r:
        return None
    exact = open_unused_grants(r)[1]
    macs = x.get("macs") or ([x["mac"]] if x.get("mac") else open_unused_members(r.get("applies_on"), access_sides()[0]))
    drop = sorted(p for p in exact if p not in set(x.get("keep") or [])) if exact else None
    return open_unused_howto(x.get("pid"), macs, drop) if drop is None or drop else None


def open_unused_narrow_steps(row, grid, names, keep, drop, everyone):
    """Show Me How in words for one set of clients with the same choice
    (D-920): which Firewalla change does it, and what else it changes."""
    pid, rule = row["pid"], row["rule"]
    lst, group = grid.get("list"), grid.get("on_name") if grid.get("on_kind") == "group" else None
    who = ", ".join(names)
    shared = (lst or {}).get("shared") or []
    warn = [f"Your target list \"{lst['name']}\" is also used by {', '.join(shared)}: editing the list changes that rule too, so copy the list instead"] if lst and shared else []
    if everyone and not keep:
        return ([f"MSP › Rules › #{pid} {rule}: delete it (or pause it first to try)", "What it allowed is then decided by your other rules"],
                [f"Create rule #{pid} again, or unpause it"])
    if everyone:
        where = (f"MSP › Target Lists › \"{lst['name']}\": take out {', '.join(drop)} (keep {', '.join(keep)})" if lst
                 else f"MSP › Rules › #{pid} {rule}: set its port to {', '.join(keep)}")
        return ([where, *warn, f"Traffic on {', '.join(drop)} is then decided by your other rules"],
                [f"Put {', '.join(drop)} back on {'the list' if lst else 'rule #' + str(pid)}"])
    off = ([f"Take {who} off rule #{pid}: (1) move {who} out of {group} into a group that doesn't have this rule (it then loses everything else {group} gives it), "
            f"or (2) change rule #{pid} to name clients instead of the whole group, leaving {who} out"] if group
           else [f"MSP › Rules › #{pid} {rule}: take {who} off its On"])
    if not keep:
        return ([*off, "Check their other access afterwards with Show Me How"], [f"Put {who} back on rule #{pid}"])
    copy = (f"a copy of the target list \"{lst['name']}\" with only {', '.join(keep)}" if lst else f"port {', '.join(keep)}")
    return ([f"MSP › Rules › New Rule: Allow, On {who}, Matching {copy} (the rest as rule #{pid})", *off,
             f"{who} then {'keeps' if len(names) == 1 else 'keep'} {', '.join(keep)} and {'loses' if len(names) == 1 else 'lose'} {', '.join(drop)}"],
            [f"Delete the new rule and put {who} back on rule #{pid}"])


@app.post("/api/open-unused/narrow")
def api_open_unused_narrow(payload: dict = Body(default={})):
    """Narrow It / Close It with your choices ({id, keep: {mac: [port
    labels]}}, D-920): each set of clients with the same ports kept becomes
    one Review item; clients keeping every port make none."""
    rid = Fields(payload).text("id", 300, strip=False)
    rows = open_unused_page()
    row = next((x for x in rows["ports"] if x["id"] == rid), None)
    grid = (row or {}).get("grid")
    if not row or not grid:
        return {"ok": False, "error": "That row is gone."}
    keep_in = payload.get("keep") if isinstance(payload.get("keep"), dict) else {}
    ports = grid["ports"]
    names = {c["mac"]: c["name"] for c in grid["clients"]}
    sets = {}
    for mac in names:
        kept = keep_in.get(mac)
        kept = tuple(p for p in ports if isinstance(kept, list) and p in kept)
        sets.setdefault(kept, []).append(mac)
    sets = {k: v for k, v in sets.items() if len(k) < len(ports)}
    if not sets:
        return {"ok": False, "error": "Every client keeps every port: nothing to change."}
    from policy import policy_data, policy_flow_new, policy_lock, policy_message, policy_state_load, policy_state_save
    now, made = time.time(), []
    with policy_lock:
        st = policy_state_load()
        if any(k.startswith("rule|" + rid) and (k == "rule|" + rid or k.startswith("rule|" + rid + "#")) and (d.get("status") not in (None, "decided"))
               for k, d in st["decisions"].items()):
            return {"ok": False, "error": "It is already in Policy."}
        everyone = len(sets) == 1 and len(next(iter(sets.values()))) == len(names)
        for n, (kept, macs) in enumerate(sorted(sets.items(), key=lambda x: (len(x[0]), [names[m] for m in x[1]]))):
            drop = [p for p in ports if p not in kept]
            who = [names[m] for m in macs]
            verb = "Close It" if everyone and not kept else "Narrow It"
            label = "every client" if everyone else (who[0] if len(who) == 1 else f"{len(who)} clients")
            act = f"Keep {', '.join(kept)} · Drop {', '.join(drop)}" if kept else f"Drop all ({', '.join(drop)})"
            title = f"{verb}: {label} · {row['rule']} · {act}"
            steps, undo = open_unused_narrow_steps(row, grid, who, list(kept), drop, everyone)
            key = f"rule|{rid}#{n}"
            fid = policy_flow_new(st, "rule", [key], [key], title, now, steps=steps, undo=undo,
                                  howto=open_unused_howto(row["pid"], macs, drop),
                                  rule={"id": rid, "pid": row["pid"], "sig": row["sig"], "macs": macs, "keep": list(kept), "verb": verb,
                                        "what": ", ".join(who), "grants": row["grants"], "kind": row["kind"]})
            st["decisions"][key] = {"intent": "block", "at": now, "label": title, "kind": "chose", "status": "review", "status_at": now, "flow": fid,
                                    "rule": {"rule": row["rule"], "what": ", ".join(who), "grants": row["grants"], "act": act}}
            made.append(title)
        policy_message(st, now, f"{row['rule']}: {len(made)} item{'s' if len(made) != 1 else ''} moved to Policy › Review. Show Me How on each walks you through it.")
        policy_state_save(st)
        policy_data(fresh=True)
    open_unused_cache["at"] = 0
    return {"ok": True, "items": made, "message": f"{row['rule']}: {len(made)} item{'s' if len(made) != 1 else ''} moved to Policy › Review."}


@app.get("/api/access/client")
def api_access_client(mac: str):
    """What one client can reach: the internet, then (14 Nov 2026, user's
    layout) three sections, each row with the verdicts for connections it
    starts and ones started towards it:
      groups   - every group;
      devices  - each device in no group, by name;
      infra    - Your Infrastructure: your switches and APs in no group
                 ("Network Gear", access_is_gear) and the router's own address on
                 each local network. The client's own network's router
                 address is its gateway (always reachable); the others are
                 not checked yet (how Firewalla treats traffic to its own
                 addresses is to be confirmed)."""
    sides, groups = access_sides()
    client = sides.get(str(mac).upper())
    if not client:
        return {"error": "Unknown client"}
    rules = access_local_rules()
    seen = access_seen(client["mac"])
    buckets = {}
    router = router_macs() | {m for m, d in sides.items() if d.get("ip") in router_ips()}
    for other in sides.values():
        if other["mac"] == client["mac"] or other["mac"] in router:
            continue   # the router gets a row per network below
        keys = ([("group", g) for g in other["groups"]]
                or [("gear", other["network"]) if access_is_gear(other) else ("device", other["mac"])])
        for key in keys:
            buckets.setdefault(key, []).append(other)

    def summary(results):
        counts, deciders = {"allowed": 0, "blocked": 0, "uncertain": 0, "conflict": 0}, {}
        for r in results:
            counts[r["verdict"]] += 1
            counts["uncertain"] += 1 if r["uncertain"] else 0
            counts["conflict"] += 1 if r.get("conflict") else 0
            key = (r["verdict"], r["deciding"].get("pid"), r["deciding"]["text"])
            deciders[key] = deciders.get(key, 0) + 1
        return {**counts, "deciding": [
            {"verdict": v, "pid": pid, "text": text, "count": n}
            for (v, pid, text), n in sorted(deciders.items(), key=lambda kv: -kv[1])[:3]]}

    rows = []
    iso = access_isolated()   # once, not per device
    for (kind, bid), members in buckets.items():
        out = [access_with_seen(check_local_access(client, o, groups, rules, access_credited(seen, client, o), isolated=iso), seen)
               for o in members]
        back = [access_with_seen(check_local_access(o, client, groups, rules, access_credited(seen, o, client), isolated=iso), seen)
                for o in members]
        traffic = {"out_flows": 0, "in_flows": 0, "blocked": 0, "bytes": 0}
        for r in out + back:
            if r["seen"]:
                traffic["out_flows" if r["from"] == client["mac"] else "in_flows"] += r["seen"]["flows"]
                traffic["blocked"] += r["seen"]["blocked"]
                traffic["bytes"] += r["seen"]["bytes"]
        # The device the checker opens with: one whose verdict stands out.
        example = next((o["mac"] for o, r in zip(members, out) if r["verdict"] == "blocked"), members[0]["mac"])
        rows.append({
            "kind": kind, "id": bid,
            "section": "groups" if kind == "group" else "infra" if kind == "gear" else "devices",
            "name": (groups.get(bid) or {}).get("name") or f"Group {bid}" if kind == "group"
            else "Network Gear" if kind == "gear" else members[0]["name"],
            "where": members[0]["network_name"] if kind != "group" else "",
            "own": kind == "group" and bid in client["groups"],
            "devices": len(members), "online": sum(1 for o in members if o["online"]),
            "out": summary(out), "in": summary(back), "seen": traffic, "example": example,
            # Each member's own verdict both ways, for the hover (owner, 18 Nov 2026).
            "members": sorted(({"mac": o["mac"], "name": o["name"], "online": bool(o["online"]),
                                "out": {"verdict": a["verdict"], "uncertain": bool(a["uncertain"]), "conflict": bool(a.get("conflict"))},
                                "in": {"verdict": b["verdict"], "uncertain": bool(b["uncertain"]), "conflict": bool(b.get("conflict"))}}
                               for o, a, b in zip(members, out, back)), key=lambda m: str(m["name"]).lower()),
        })
    # The router's own address on each local network (VPN networks left out).
    empty = {"allowed": 0, "blocked": 0, "uncertain": 0, "conflict": 0, "deciding": []}
    for uuid, meta in INTERFACE_METADATA.items():
        if meta.get("network_type") == "wan" or not meta.get("router_ip") or not str(meta.get("interface") or "").startswith("br"):
            continue
        gateway = uuid == client["network"]
        rows.append({
            "kind": "router", "id": uuid, "section": "infra", "name": "Router",
            "where": f"{meta.get('display_name')} · {meta['router_ip']}", "own": False, "devices": 1, "online": 1,
            "status": "gateway" if gateway else "unchecked",
            "note": "Its own network's router: always reachable" if gateway else "Not checked yet: how Firewalla treats its own addresses is to be confirmed",
            "out": empty, "in": empty, "seen": {"out_flows": 0, "in_flows": 0, "blocked": 0, "bytes": 0}, "example": None,
            "order": meta["router_ip"],
        })
    section = {"groups": 0, "devices": 1, "infra": 2}
    rows.sort(key=lambda r: (section[r["section"]], not r["own"], r["kind"] == "router", r.get("status") != "gateway",
                             r["out"]["allowed"] + r["in"]["allowed"] == 0 if r["kind"] != "router" else False,
                             tuple(int(x) for x in r["order"].split(".")) if r.get("order") else (),
                             r["name"].lower()))
    return {"client": access_side_out(client, groups), "internet": access_internet(client),
            "rows": rows, "updated_at": time.time()}


# ============================================================
# SHOW ME HOW (14 Nov 2026; designed with the user, mock-ups in the chat)
#
# You say what should change: Allow or Block, A (who starts it: devices,
# groups, networks), B (what A should reach), protocol and port, one way
# or both. The dashboard works out what decides it today, the ways to get
# there in Firewalla, tries each one out against your rules
# (check_local_access with the change in place) and gives the exact MSP
# and app steps. It never changes Firewalla: "I'm Doing This" adds the
# change to the Changes list (/data/howto_changes.json, 30 days), which
# watches for every step and for the result.
# Firewalla facts it relies on (help.firewalla.com and the MSP, 14 Nov
# 2026): a rule's On is a network, a group or a device in no group; a
# group can't be a rule's target (a target list of its addresses is);
# only Allowed Devices or a target-list Allow rule opens VqLAN and Device
# Isolation; Allowed Devices is every port, both ways; a target list line
# is an address or network, optionally ",tcp:80,443-453"; a device rule
# beats a group rule beats a network rule beats All Devices, and at the
# same level Allow beats Block. Local traffic only for now (internet
# targets come later).
# Refs: "g:<group id>", "n:<network uuid>", "d:<MAC>".
# ============================================================
HOWTO_FILE = os.environ.get("FIREWALLA_HOWTO_FILE", "/data/howto_changes.json")
HOWTO_KEEP = 30 * 86400
HOWTO_MAX_PAIRS = 400
howto_lock = threading.Lock()
howto_plan_cache = {}   # worked-out plans by what they depend on (howto_plan)
howto_plan_lock = threading.Lock()   # its own: plans are worked out under howto_lock


# What else is on (owner, 18 Nov 2026): Firewalla features outside rules,
# VqLAN and Isolation (which the rule check covers) that bear on a device.
# "local": they can change traffic between your own devices, or are worth
# ruling out (DAP with its local part off). "other": internet only. Kept to
# one short phrase each; the page shows the local ones on one line.
ACCESS_OTHER_FEATURES = (("adblock", "Ad Block"), ("family", "Content Filtering"), ("doh", "DNS over HTTPS"),
                         ("vpn_client", "VPN client"), ("bypass_prevention", "Bypass Prevention"))


def access_also_on(side):
    """{"local": [{key, what, effect}], "other": [...]} for one device."""
    out = {"local": [], "other": []}
    if not side:
        return out
    p = access_device_protect.get(side["mac"]) or {}
    phase = str(p.get("state") or "").lower()
    if phase in ("active", "optimizing"):
        if str(p.get("local") or "").lower() == "active":
            out["local"].append({"key": "dap-local", "what": f"DAP {phase}, its local part on", "effect": "can block"})
        else:
            out["local"].append({"key": "dap-internet", "what": f"DAP {phase}, its local part off", "effect": "internet only"})
    dev = (feature_settings.get("devices") or {}).get(side["mac"]) or {}
    if dev.get("isolated") and dev.get("isolated_by_dap"):
        out["local"].append({"key": "iso-dap", "what": "Device Isolation, switched on by DAP", "effect": "can block"})
    paused = access_paused(side)
    if paused:
        out["local"].append({"key": "paused", "what": paused.replace(f" on {side['name']}'s", " on its").replace(f" on {side['name']}", "").replace(f" for {side['name']}", ""), "effect": "lifts blocks"})
    for key, words in ACCESS_OTHER_FEATURES:
        if dev.get(key):
            out["other"].append({"key": key, "what": words, "effect": "internet only"})
    return out


def access_also_on_counts(cards):
    """For a group of Policy cards: each local feature, how many of its
    starters / targets have it ("DAP active, its local part off: 3 of 30
    targets"), without listing devices."""
    lines = []
    for side, word in (("src", "starters"), ("dst", "targets")):
        devices = {}
        for c in cards:
            devices[c[side]["mac"]] = ((c.get("also_on") or {}).get(side) or {}).get("local") or []
        counts = {}
        for items in devices.values():
            for x in items:
                counts.setdefault(x["what"], [0, x["effect"]])[0] += 1
        one = cards[0][side]["name"] if len(devices) == 1 and cards[0][side].get("name") else None
        lines += [f"{one}: {what} ({effect})" if one else f"{what}: {n} of {len(devices)} {word} ({effect})" for what, (n, effect) in counts.items()]
    return lines


def access_isolated():
    """MACs with Device Isolation on the device itself (feature_settings)."""
    return {mac for mac, d in (feature_settings.get("devices") or {}).items() if d.get("isolated") or d.get("vqlan")}


def howto_reserved(mac):
    return [r["ip"] for r in ((feature_settings.get("devices") or {}).get(mac) or {}).get("reserved") or []]


def howto_catalog():
    """Everything you can pick for A and B: groups with their members,
    networks, and devices in no group."""
    sides, groups = access_sides()
    dev = lambda s: {"mac": s["mac"], "name": s["name"], "ip": s["ip"], "ip_text": s.get("ip_text"), "online": s["online"], "reserved": howto_reserved(s["mac"]),
                     "network": s["network"], "group": s["groups"][0] if s["groups"] else None}
    out_groups = sorted(({"id": g["id"], "name": g["name"], "vqlan": bool(g.get("vqlan")), "isolation": bool(g.get("isolation")),
                          "members": sorted((dev(sides[m]) for m in g.get("members") or [] if m in sides), key=lambda d: d["name"].lower())}
                         for g in groups.values()), key=lambda g: g["name"].lower())
    networks = {}
    for s in sides.values():
        if s["network"]:
            networks[s["network"]] = networks.get(s["network"], 0) + 1
    return {"groups": out_groups,
            "networks": sorted(({"id": n, "name": internet_interface_name(n), "count": c} for n, c in networks.items()), key=lambda n: n["name"].lower()),
            "ungrouped": sorted((dev(s) for s in sides.values() if not s["groups"]), key=lambda d: d["name"].lower())}


def howto_expand(refs, sides, groups):
    """Picked refs -> the devices they cover, and the "units" a rule can go
    On (a grouped device brings its whole group: Firewalla won't put a rule
    on one device of a group)."""
    devices, units, picked = {}, {}, []
    for ref in refs:
        kind, _, rid = ref.partition(":")
        if kind == "g" and rid in groups:
            g = groups[rid]
            members = [m for m in g.get("members") or [] if m in sides]
            devices.update({m: sides[m] for m in members})
            units[ref] = {"key": ref, "kind": "group", "id": rid, "name": g["name"], "members": members, "partly": False}
            picked.append({"ref": ref, "kind": "group", "name": g["name"], "count": len(members)})
        elif kind == "n":
            members = [m for m, s in sides.items() if s["network"] == rid]
            devices.update({m: sides[m] for m in members})
            units[ref] = {"key": ref, "kind": "network", "id": rid, "name": internet_interface_name(rid), "members": members, "partly": False}
            picked.append({"ref": ref, "kind": "network", "name": internet_interface_name(rid), "count": len(members)})
        elif kind == "d" and rid.upper() in sides:
            s = sides[rid.upper()]
            devices[s["mac"]] = s
            picked.append({"ref": "d:" + s["mac"], "kind": "device", "name": s["name"], "count": 1,
                           "group": (groups.get(s["groups"][0]) or {}).get("name") if s["groups"] else None})
            if s["groups"]:
                gid = s["groups"][0]
                g = groups.get(gid) or {}
                units.setdefault("g:" + gid, {"key": "g:" + gid, "kind": "group", "id": gid, "name": g.get("name") or gid,
                                              "members": [m for m in g.get("members") or [] if m in sides], "partly": True})
            else:
                units["d:" + s["mac"]] = {"key": "d:" + s["mac"], "kind": "device", "id": s["mac"], "name": s["name"],
                                          "members": [s["mac"]], "partly": False}
    return list(devices.values()), list(units.values()), picked


def howto_port(proto, port):
    """(checker port or None, list-line suffix, words)."""
    proto = str(proto or "any").lower()
    port = re.sub(r"\s+", "", str(port or ""))
    # Any protocol means every port (the page hides the port box then).
    if proto not in ("tcp", "udp"):
        return None, "", "every port"
    # TCP or UDP with no port: every port of that protocol only (18 Nov 2026:
    # it was checked, and listed, as every protocol, so a TCP-only list looked
    # like it opened UDP too).
    if not re.fullmatch(r"\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*", port):
        return (proto, "any"), f",{proto}:1-65535", f"every {proto.upper()} port"
    # A port, a range, or several: "445", "8000-8100", "80,443,8000-8100".
    # The rule checker tries the first one.
    low = int(port.split(",")[0].split("-")[0])
    return (proto, low), f",{proto}:{port}", f"{proto.upper()} {port.replace(',', ', ')}"


HOWTO_PROBES_MAX = 12   # most ports one pair is checked on


def howto_asked_probes(port, suffix):
    """Every port asked for, for the checker (24 Nov 2026, part 1 of the
    safety plan: only the first was checked, so "TCP 80, 443" looked done
    when 443 was still blocked): each port, and both ends of a range.
    -> [(protocol, number)], or [port] for every port (of a protocol)."""
    if not port or port[1] == "any" or ":" not in (suffix or ""):
        return [port]
    proto, _, numbers = suffix.lstrip(",").partition(":")
    out = []
    for part in numbers.split(","):
        low, _, high = part.partition("-")
        for n in (low, high):
            if n.isdigit() and (proto, int(n)) not in out:
                out.append((proto, int(n)))
    return out[:HOWTO_PROBES_MAX] or [port]


def howto_rule_ports(rule):
    """The ports a rule's target list names: [(protocol, number)], both ends
    of each range, TCP and UDP when a line names no protocol."""
    out = []
    for e in (access_list_entries(rule) or []) if access_target_list_side(rule) else []:
        for low, high in e.get("ports") or []:
            for proto in [e["protocol"]] if e.get("protocol") in ("tcp", "udp") else ["tcp", "udp"]:
                for n in dict.fromkeys((low, high)):
                    if (proto, n) not in out:
                        out.append((proto, n))
    return out[:HOWTO_PROBES_MAX]


def howto_addresses(side):
    """The addresses to list for a device: today's and its reservation(s)
    (a NAS can answer on a shared address that isn't its reserved one, as
    NAS 1 did on 14 Nov 2026: .254 today, .236 reserved). Returns
    ([ip], reserved?)."""
    reserved = howto_reserved(side["mac"])
    ips = [ip for ip in [side.get("ip")] + reserved if ip]
    return list(dict.fromkeys(ips)), bool(reserved)


def howto_unit_obj(unit):
    return {"kind": unit["kind"], "id": unit["id"], "name": unit["name"], "label": unit["name"]}


def howto_where(unit):
    """Where a unit's own page is on the MSP."""
    return (["Groups & Users", unit["name"]] if unit["kind"] == "group"
            else ["Devices", unit["name"]] if unit["kind"] == "device" else ["Networks", unit["name"]])


HOWTO_NAME_MAX = 32   # Firewalla: group and target list names, 32 characters at most (owner, 17 Nov 2026)


def howto_fit(parts, joiner=" + ", tail="", prefix=""):
    """A group or target list name Firewalla accepts (32 characters at
    most): the names as they are when they fit; else without their network
    suffix (" .10"), then the last word of the longest name dropped, one
    word at a time; the prefix ("Keep ") and tail ("TCP 631, 443", written
    tight: "TCP 631,443") always kept."""
    tail = re.sub(r",\s+", ",", str(tail or "")).strip()
    make = lambda ps: prefix + " ".join(x for x in (joiner.join(" ".join(w) for w in ps).strip(), tail) if x)
    ps = [str(x).split() for x in parts]
    if len(make(ps)) <= HOWTO_NAME_MAX:
        return make(ps)
    ps = [re.sub(r"\s+\.\d+\b", "", " ".join(w)).split() for w in ps]
    while len(make(ps)) > HOWTO_NAME_MAX:
        longest = max(ps, key=lambda w: (len(w) > 1, len(" ".join(w))))
        if len(longest) <= 1:
            break
        longest.pop()
    return make(ps)[:HOWTO_NAME_MAX].strip()


def howto_list_name(units, dsts, words):
    """The name a group-of-their-own list starts from: what it holds,
    "Printer Office TCP 631,443" (howto_own_group_fix adds whose)."""
    b = dsts[0]["name"] if len(dsts) == 1 else f"{len(dsts)} clients"
    return howto_fit([b], tail=words)


def howto_short_name(name):
    """A group's or client's name as it goes into a list's name: without a
    number in front ("G03 ") and its network at the end (" .6"), the way the
    owner names his own lists ("T08 NAS PC B")."""
    text = str(name or "").strip()
    return re.sub(r"\s+\.\d+(\.\d+)*$", "", re.sub(r"^[A-Za-z]\d{1,3}\s+", "", text)).strip() or text


def howto_list_number(taken=()):
    """"T11 " when most of your lists are numbered that way (T01 ... T10):
    the next number, with the same letters and width. "" otherwise."""
    names = [str(tl.get("name") or "") for tl in msp["lists"].values()]
    marks = [m for m in (re.match(r"^([A-Za-z]{1,2})(\d{2,3})\s", n) for n in names + list(taken)) if m]
    if not marks or sum(1 for n in names if re.match(r"^[A-Za-z]{1,2}\d{2,3}\s", n)) * 2 < len(names):
        return ""
    letters = max({m.group(1) for m in marks}, key=lambda x: sum(1 for m in marks if m.group(1) == x))
    mine = [m.group(2) for m in marks if m.group(1) == letters]
    return f"{letters}{max(int(n) for n in mine) + 1:0{max(len(n) for n in mine)}d} "


def howto_own_list_name(unit, dst_picked, dsts, taken=(), groups=None):
    """The name of a new list of this unit's own: what it reaches, then whose
    it is, numbered like your other lists: "T11 NAS Recovery PC B". What
    it reaches is the group's name when the clients are a whole group (also
    a group of one: names are 32 characters at most, and a client's name cut
    short loses its telling word), else what you picked. No ports in it: the
    list gets more lines as that unit needs more. taken = names this plan
    has already given out."""
    homes = {tuple(d.get("groups") or []) for d in dsts}
    home = (groups or {}).get(next(iter(homes))[0]) if len(homes) == 1 and next(iter(homes)) else None
    whole = home if home and set(home.get("members") or []) == {d["mac"] for d in dsts} else None
    what = (howto_short_name(whole.get("name")) if whole else howto_short_name(dst_picked[0]["name"]) if len(dst_picked) == 1
            else howto_short_name(dsts[0]["name"]) if len(dsts) == 1 else f"{len(dsts)} clients")
    base = name = howto_fit([what, howto_short_name(unit["name"])], joiner=" ", prefix=howto_list_number(taken))
    used = {str(tl.get("name") or "").strip().lower() for tl in msp["lists"].values()} | {str(n).strip().lower() for n in taken}
    n = 2
    while name.strip().lower() in used:
        name, n = f"{base[:HOWTO_NAME_MAX - 1 - len(str(n))]} {n}", n + 1
    return name


def howto_existing_list(unit, action, direction, suffix="", ips=()):
    """One of your lists already used by a rule On this unit with the same
    action and direction, to extend instead of making another: (1) its lines
    all use the same protocol and ports as this change (another device is
    added), or (2, 15 Nov 2026) it holds only the same device(s) (ips) and
    this change is for a port (the new port is added). Never a list for
    other devices AND other ports: that is for something else - e.g. "NAS
    to Cameras" isn't extended for file sharing. And never a list that a
    rule On another group, client or network uses too (owner, 24 Nov 2026,
    D-1061: a list has one owner, so a change for one group can't change
    another's access): this unit then gets a list of its own.
    -> (rule, list, "port" | "devices") or (None, None, None)."""
    same_devices = None
    for r in (state.get("policy_rules") or {}).get("rules") or []:
        if r.get("disabled") is True or r.get("action") != action or access_target_list_side(r) != "matching":
            continue
        on = r.get("applies_on") or {}
        if on.get("kind") == unit["kind"] and str(on.get("id")).upper() == str(unit["id"]).upper() \
                and (r.get("direction") or "bidirection") == direction:
            tl = msp["lists"].get(str((r.get("matching") or {}).get("id")))
            if tl and len(howto_list_owners((r.get("matching") or {}).get("id"))) > 1:
                continue
            lines = [str(t).strip() for t in (tl or {}).get("targets") or [] if str(t).strip() and not str(t).startswith("#")]
            ends = {t[len(t.partition(",")[0].partition(":")[0]):].strip().lower() for t in lines}
            if tl and ends == {suffix.lower()}:
                return r, tl, "port"
            addresses = {t.partition(",")[0].partition(":")[0].strip() for t in lines}
            if tl and suffix and addresses and addresses <= set(ips) and same_devices is None:
                same_devices = (r, tl, "devices")
    return same_devices or (None, None, None)


def howto_list_users(list_id):
    """Every enabled rule that uses this target list. One list often serves
    several groups, so changing its lines changes each of those rules
    (24 Nov 2026: only the rule asked about was modelled, so What Else This
    Changes missed what the other rules' groups gain or lose)."""
    return [r for r in (state.get("policy_rules") or {}).get("rules") or []
            if r.get("disabled") is not True and access_target_list_side(r)
            and str((r.get(access_target_list_side(r)) or {}).get("id")) == str(list_id)]


def howto_list_owners(list_id):
    """The groups, clients and networks whose rules use this target list:
    [{kind, id, name}], each once, in rule order. A list has ONE owner
    (owner, 24 Nov 2026, D-1061): Show Me How never gives one a second, and
    List Check names a list that has several, with the steps to split it."""
    owners = {}
    for r in howto_list_users(list_id):
        on = r.get("applies_on" if access_target_list_side(r) == "matching" else "matching") or {}
        owners.setdefault((str(on.get("kind")), str(on.get("id")).upper()),
                          {"kind": on.get("kind"), "id": on.get("id"), "name": on.get("name") or on.get("label") or str(on.get("id") or "")})
    return list(owners.values())


def howto_list_users_words(users, but):
    """" Rule #5 (On G02 NAS) uses this list too, so it changes with it." for a
    step's note or a way's detail; "" when the list has no other user."""
    others = [r for r in users if str(r.get("pid")) != str(but)]
    if not others:
        return ""
    named = ", ".join(f"#{r.get('pid')} (On {(r.get('applies_on') or {}).get('name') or (r.get('applies_on') or {}).get('label') or 'its scope'})" for r in others[:6])
    more = f" and {len(others) - 6} more" if len(others) > 6 else ""
    return (f" Rule{'s' if len(others) != 1 else ''} {named}{more} use{'s' if len(others) == 1 else ''} this list too, "
            f"so {'it changes' if len(others) == 1 else 'they change'} with it.")


def howto_lines_without(targets, ips, proto, asked):
    """A target list's lines with the asked ports taken away from the lines
    for these addresses: the one place this is worked out (the narrow way
    and a group of their own each had a copy, and they disagreed).
    -> (the lines that stay as they are, [(old line, its new text, or None
    when the whole line goes)]).
    A line stays when it is for another address, for another protocol, or
    names ports without an asked one (24 Nov 2026: a UDP line went with a
    TCP port, and a range line that didn't hold the port). A line naming
    several ports loses only the asked ones (D-921). A line with no ports
    (every port), or with a range that holds an asked port, goes whole; so
    does every line for these addresses when asked is None (every port)."""
    def in_range(entry, number):
        low, dash, high = entry.partition("-")
        return bool(dash) and low.isdigit() and high.isdigit() and str(number).isdigit() and int(low) <= int(number) <= int(high)
    keep, edits = [], []
    for t in targets or []:
        address, _, rest = str(t).partition(",")
        if address.partition(":")[0].strip() not in ips:
            keep.append(t)
            continue
        proto_l, _, plist = rest.partition(":")
        ports_l = [p.strip() for p in plist.split(",") if p.strip()]
        if asked and ports_l:
            if proto_l.strip().lower() != proto:
                keep.append(t)
                continue
            if not any(in_range(p, q) for p in ports_l for q in asked):
                left = [p for p in ports_l if p not in asked]
                if len(left) == len(ports_l):
                    keep.append(t)
                    continue
                if left:
                    edits.append((t, f"{address},{proto_l}:{','.join(left)}"))
                    continue
        edits.append((t, None))
    return keep, edits


def howto_spare_list(ips, suffix):
    """One of your lists that no rule uses, holding exactly the devices this
    change targets (owner, 17 Nov 2026: an unused "Printer Canon Office"
    list sat there while Show Me How said to make a new one): (list id,
    list, "as_is") when its lines already have these ports, (id, list,
    "edit") when they must change to these ports. A list a rule uses has an
    owner already and is left alone (D-1061). -> (None, None, None)."""
    rules = (state.get("policy_rules") or {}).get("rules") or []
    used = {str((r.get(access_target_list_side(r)) or {}).get("id")) for r in rules if r.get("disabled") is not True and access_target_list_side(r)}
    best = (None, None, None)
    for tid, tl in sorted(msp["lists"].items()):
        if tid in used:
            continue
        lines = [str(t).strip() for t in tl.get("targets") or [] if str(t).strip() and not str(t).startswith("#")]
        addresses = {t.partition(",")[0].partition(":")[0].strip() for t in lines}
        if not lines or addresses != set(ips):
            continue
        ends = {t[len(t.partition(",")[0].partition(":")[0]):].strip().lower() for t in lines}
        if ends == {suffix.lower()}:
            return tid, tl, "as_is"
        if best[0] is None:
            best = (tid, tl, "edit")
    return best


def howto_check(pairs, rules, groups, probes, iso, paused, want=None):
    """Each pair checked on every asked port (howto_asked_probes): its
    answer is the first port that isn't as wanted, else the first port's."""
    out = []
    for a, b in pairs:
        first = None
        for p in probes:
            r = check_local_access(a, b, groups, rules, port=p, isolated=iso, paused=paused)
            first = first or r
            if want and r["verdict"] != want:
                first = r
                break
        out.append((a, b, first))
    return out


# A group's own switches, which don't move with a client that leaves it: the
# one table of them (24 Nov 2026: it was written out five times, three of
# them without Bypass Prevention, so a client moved to a group of its own
# lost that one without a word).
HOWTO_GROUP_SWITCHES = {"adblock": "Ad Block", "family": "Content Filtering", "safe_search": "Safe Search",
                        "doh": "DNS over HTTPS", "vpn_client": "VPN Client", "bypass_prevention": "Bypass Prevention"}


def howto_left_behind(gid, groups):
    """What a device leaves behind when it moves out of group gid: the
    rules On or Matching the group (internet ones too), its Allowed Devices
    and its settings, in words."""
    g = groups.get(gid) or {}
    out = []
    for r in (state.get("policy_rules") or {}).get("rules") or []:
        if r.get("disabled") is True:
            continue
        ends = [r.get("applies_on") or {}, r.get("matching") or {}]
        if any(e.get("kind") == "group" and str(e.get("id")) == str(gid) for e in ends):
            out.append(f"#{r.get('pid')} {access_rule_text(r)}")
    settings = (feature_settings.get("groups") or {}).get(str(gid)) or {}
    names = HOWTO_GROUP_SWITCHES
    out += [f"{names[k]} (group setting)" for k in names if settings.get(k)]
    if g.get("vqlan"):
        out.append("VqLAN" + (" + Device Isolation" if g.get("isolation") else "") + " of the group (the new group gets its own)")
    return out


def howto_pair_fix(a, b, suffix, words, groups, sides, iso=frozenset()):
    """Your idea (16 Nov 2026): a group with only A and B, VqLAN on, so
    everyone else is kept out and the two reach each other on every port.
    Ports can't be limited inside it: that would need Isolation plus a
    target-list allow, and a target-list allow never gets through Isolation
    (real tests 4 and 8, 16 Nov 2026). A device's own Isolation would keep
    the two apart, so it goes off."""
    name = howto_fit(sorted((a["name"], b["name"]), key=str.lower))
    gid = "new-pair"
    new = {"id": gid, "name": name, "members": [a["mac"], b["mac"]], "vqlan": True, "isolation": False}
    ref = {"kind": "group", "id": gid, "name": name}
    moving = [a["mac"], b["mac"]]
    olds = list(dict.fromkeys(g for x in (a, b) for g in x["groups"]))
    old_names = [(groups.get(o) or {}).get("name") or str(o) for o in olds]
    who_left = "; ".join(f"{x['name']} leaves {(groups.get(x['groups'][0]) or {}).get('name') or x['groups'][0]}" for x in (a, b) if x["groups"])
    steps = [{"title": f"Make a group \"{name}\" with only {howto_id(a)} and {howto_id(b)}",
              "msp": {"path": ["Groups & Users", "Create Group"], "fields": [["Name", name, name], ["Devices", f"{howto_id(a)}, {howto_id(b)}", None]]},
              "app": howto_app("create_group", name=name, devices=[howto_id(a), howto_id(b)]),
              "note": "A client is in one group at a time" + (f" ({who_left})" if who_left else "")
                      + (". The steps below set up on the new group every rule, Allowed Devices entry and setting they had through "
                         + ("it" if len(olds) == 1 else "them") if olds else "")
                      + ". A client that joins its group through its Wi-Fi network (SSID) can't be moved by hand.",
              "undo": f"Move {a['name']} and {b['name']} back to their old groups and delete the group \"{name}\".",
              "watch": {"kind": "pair_group", "members": moving}}]
    steps.append({"title": f"Turn VqLAN on and Device Isolation off for \"{name}\"",
                  "msp": {"path": ["Groups & Users", name], "fields": [["VqLAN", "On", None], ["Device Isolation", "Off", None]]},
                  "app": howto_app("toggles", unit=name, unit_kind="group", toggles=[["VqLAN", True], ["Device Isolation", False]]),
                  "note": "VqLAN keeps every other client out; inside, the two reach each other on every port.",
                  "undo": "Turn it off again.", "watch": {"kind": "pair_group", "members": moving, "vqlan": True, "isolation": False, "as": "setting"}})
    unisolate = {x["mac"] for x in (a, b) if x["mac"] in iso}
    for x in (a, b):
        if x["mac"] in unisolate:
            steps.append({"title": f"Turn off Device Isolation on {x['name']}'s own page",
                          "msp": {"path": ["Devices", x["name"]], "fields": [["Device Isolation", "Off", None]]},
                          "app": howto_app("toggles", unit=x["name"], unit_kind="device", toggles=[["Device Isolation", False]]),
                          "note": f"Its own Isolation would keep it from {(b if x is a else a)['name']} inside the new group too; the group's VqLAN keeps everyone else out. Check the side effects below: it can then reach whatever else lets it in (other groups' Allowed Devices still apply).",
                          "undo": f"Turn Device Isolation back on for {x['name']}.", "watch": {"kind": "not_isolated", "mac": x["mac"]}})
    # Everything their old group(s) gave them, each written out (D-929, 23 Nov
    # 2026: this way said only "Set those up again on the new group").
    copied, add, on_settings = howto_group_copies(olds, groups, name, ref, moving, skip_far={a["mac"], b["mac"]})
    steps += copied
    rules_n = sum(1 for st in copied if st.get("copy"))
    internet = sum(1 for st in copied if st.get("copy") and st.get("untried"))
    ticks = sum(1 for st in copied if (st.get("watch") or {}).get("as") == "allowed")
    summary = ([who_left] if who_left else []) + ["VqLAN on, Device Isolation off: everyone else kept out"]
    summary += [f"{rules_n} rule{'s' if rules_n != 1 else ''} copied to the new group" + (f" ({internet} of them internet rules, not tried out)" if internet else "")] if rules_n else []
    summary += [f"{ticks} Allowed Devices entr{'ies' if ticks != 1 else 'y'} copied"] if ticks else []
    summary += [f"group settings set again: {', '.join(on_settings)}"] if on_settings else []
    summary += [f"the rules of {' and '.join(old_names)} now apply to both of them"] if len(olds) > 1 else []
    summary += [f"Device Isolation off on {', '.join(sides[m]['name'] for m in unisolate if m in sides)}"] if unisolate else []
    summary += [f"later changes to {' or '.join(old_names)} don't reach them: the new group needs its own"] if olds else []
    return {"id": "pair", "title": f"A group of their own: \"{name}\"",
            "detail": "every port between the two" + (": ports can't be limited inside a group (a target list never gets through Isolation)" if suffix else "")
                      + (" · they leave their group, which is set up again on the new one" if olds else ""),
            "summary": summary,
            "broader": bool(suffix), "steps": steps, "add": add, "replace": {}, "remove": [], "groups": {"move": {a["mac"]: gid, b["mac"]: gid}, "new": {gid: new}},
            "unisolate": unisolate}


def howto_group_copies(olds, groups, new_name, ref, moving, skip_far=frozenset()):
    """Every rule On or Matching the old group(s), their Allowed Devices
    entries and settings, as steps for the new group that stand on their own
    (D-929), once each (two old groups often share rules), and the local
    ones for the model. -> (steps, add, settings turned on)."""
    names = HOWTO_GROUP_SWITCHES
    on_settings = [names[k] for k in names if any(((feature_settings.get("groups") or {}).get(str(o)) or {}).get(k) for o in olds)]
    steps, add, seen = [], [], set()
    if on_settings:
        steps.append({"title": f"Turn on {', '.join(on_settings)} for \"{new_name}\"",
                      "msp": {"path": ["Groups & Users", new_name], "fields": [[n, "On", None] for n in on_settings]},
                      "app": howto_app("toggles", unit=new_name, unit_kind="group", toggles=[[n, True] for n in on_settings]),
                      "note": "Group settings don't move with a client."
                              + (" Allow rules don't get past Content Filtering or Safe Search (Firewalla's Rules Logic): what they block stays blocked."
                                 if {"Content Filtering", "Safe Search"} & set(on_settings) else ""),
                      "undo": "Nothing (the group goes with the first step's undo).", "untried": HOWTO_UNTRIED_INTERNET,
                      "watch": {"kind": "pair_group", "members": moving, "as": "setting", "keys": [k for k in names if names[k] in on_settings]}})
    local = {str(r.get("pid")) for r in access_local_rules()}
    for r in (state.get("policy_rules") or {}).get("rules") or []:
        if r.get("disabled") is True:
            continue
        for gid in olds:
            sides_ = [x for x in ("applies_on", "matching") if (r.get(x) or {}).get("kind") == "group" and str((r.get(x) or {}).get("id")) == str(gid)]
            if not sides_:
                continue
            gname = (groups.get(gid) or {}).get("name") or str(gid)
            if r.get("purpose") == "ap_allow":
                on, other = access_allowed_owner(r)
                far = other if str(on.get("id")) == str(gid) else on
                key = ("ad", far.get("kind"), str(far.get("id")).upper())
                if key in seen or str(far.get("id")).upper() in skip_far:
                    continue
                seen.add(key)
                steps.append({"title": f"Tick {far.get('name') or far.get('id')} in \"{new_name}\"'s Allowed Devices",
                              "msp": {"path": ["Groups & Users", new_name, "Allowed Devices"], "fields": [["Tick", far.get("name") or "", None]]},
                              "app": howto_app("allowed", owner=new_name, owner_kind="group", names=[far.get("name") or ""]),
                              "note": f"Then Save. (They had this through {gname}.)", "picture": "msp-group-allowed-devices.jpg",
                              "undo": "Nothing (the group goes with the first step's undo).",
                              "watch": {"kind": "pair_group", "members": moving, "as": "allowed", "ticked": [far.get("kind"), str(far.get("id"))]}})
            else:
                key = ("rule", r.get("action"), json.dumps(r.get("matching") if "applies_on" in sides_ else r.get("applies_on"), sort_keys=True, default=str),
                       r.get("direction"), "applies_on" in sides_)
                if key in seen:
                    continue
                seen.add(key)
                st = howto_rule_step(r, gname, new_name, "applies_on" in sides_, moving)
                if str(r.get("pid")) not in local:
                    st["untried"] = HOWTO_UNTRIED_INTERNET
                steps.append(st)
            if str(r.get("pid")) in local:
                add.append({**r, "pid": f"pair-{r.get('pid')}-{gid}", **{x: ref for x in sides_}})
    return steps, add, on_settings


def howto_id(x):
    """A client as a step names it when it is to be picked from a list: its
    name and address, "Phone B .10 (192.168.10.25)" (owner, 23 Nov
    2026: Phone A was put in Phone B's group; the names are close)."""
    return f"{x['name']} ({x['ip']})" if x.get("ip") else x["name"]


def howto_lookalike_notes(fix):
    """On a step that picks a list the way makes, a warning when one of your
    lists has a name like it (owner, 23 Nov 2026: rule #1007 got the old
    "T10 NAS Phones" instead of the new "T10 NAS Phones - Phone B",
    which sits next to it in the picker)."""
    made = {f[2] for st in fix.get("steps") or [] if "Create Target List" in ((st.get("msp") or {}).get("path") or [])
            for f in (st.get("msp") or {}).get("fields") or [] if f[0] == "List Name" and f[2]}
    norm = lambda t: re.sub(r"\s+", " ", str(t or "")).strip().lower()
    names = {tl.get("name") for tl in msp["lists"].values() if tl.get("name")}
    for st in fix.get("steps") or []:
        for f in (st.get("msp") or {}).get("fields") or []:
            if f[0] != "Matching" or not str(f[1]).startswith("Target List › "):
                continue
            want = str(f[1])[len("Target List › "):]
            if want not in made:
                continue
            alike = sorted(n for n in names if norm(n) != norm(want) and (norm(want).startswith(norm(n)) or norm(n).startswith(norm(want))
                                                                          or norm(n)[:12] == norm(want)[:12]))
            if alike:
                st["note"] = (st.get("note") or "") + f" In Matching, pick \"{want}\", not " + " or ".join(f"\"{n}\"" for n in alike[:3]) + " (a list with a similar name)."


# Third-party lists by their id: the names the MSP shows (Target Lists page, 14 Nov 2026).
HOWTO_LIST_NAMES = {"hagezi-multipro": "HaGeZi - Multi Pro", "msp-prod-oisd-big-prod": "oisd BIG", "msp-prod-goodbye-ads": "GoodbyeAds"}


def howto_matching(rule):
    """A rule's Matching as the MSP's Set a target menu names it: (menu,
    value), e.g. ("Domain", "gvt2.com"), ("Target List", "GoodbyeAds")."""
    m = rule.get("matching") or {}
    kind, mid = m.get("kind"), str(m.get("id") or "")
    if kind == "target_list":
        return "Target List", (msp["lists"].get(mid) or {}).get("name") or HOWTO_LIST_NAMES.get(mid) or m.get("name") or mid
    if kind == "network":
        return "Local Network", f"Traffic to {internet_interface_name(mid)}"
    menus = {"domain": "Domain", "ip": "IP Address", "net": "IP Address Range", "region": "Region (Beta)", "app": "App",
             "remote_port": "Remote Port", "remotePort": "Remote Port", "internet": "Internet", "local_networks": "Local Network"}
    if kind in menus:
        return menus[kind], m.get("name") or mid
    label = str(m.get("label") or "")
    return (label.partition(":")[0].strip() or "Target"), (m.get("name") or mid or label)


def howto_rule_step(rule, old_name, new_name, on_side, moving):
    """Making a copy of a rule for a new group, as a step that stands on its
    own (owner, 23 Nov 2026: no "like G06" or "the same as #943"; every value
    written out). on_side: the group was the rule's On (else its Matching)."""
    action = str(rule.get("action") or "allow")
    direction = rule.get("direction") or "bidirection"
    menu, value = howto_matching(rule)
    # Rule names aren't held to 32 characters (only group and list names are).
    # A name holding the old group's name gets the new one; any other name
    # (e.g. "G06 Phones to NAS") is replaced, so no step names the old group.
    shown = str(rule.get("display_name") or "")
    name = (shown.replace(old_name, new_name).strip() if old_name in shown else f"{new_name} {value}")[:60]
    dir_words = {"outbound": "Outbound only", "inbound": "Inbound only"}.get(direction, "Bi-directional")
    if on_side:
        title = f"Create the rule \"{name}\": {action.title()} {menu} {value} On \"{new_name}\""
        fields = [["Name", name, name], ["Action", action.title(), None], ["Matching", f"{menu} › {value}", value],
                  ["On", f"FWG Pro (Router) + {new_name}", None], ["Direction", dir_words, None], ["Schedule", "Always", None]]
        app = howto_app("rule", name=name, action=action, matching_path=f"Set a target › {menu} › {value}", matching_label=menu,
                        matching_value=value, target=f"{menu} {value}", list=menu == "Target List",
                        on_kind="group", on=new_name, direction=direction)
    else:
        on = rule.get("applies_on") or {}
        on_name = on.get("name") or on.get("id") or "its scope"
        title = f"Create the rule \"{name}\": {action.title()} On {on_name}, Matching the group \"{new_name}\""
        fields = [["Name", name, name], ["Action", action.title(), None], ["Matching", f"Group › {new_name}", None],
                  ["On", f"FWG Pro (Router) + {on_name}", None], ["Direction", dir_words, None], ["Schedule", "Always", None]]
        app = {"note": f"Only in the Firewalla app: Rules › Add Rule, ACTION {action.title()}, MATCHING Device › the group {new_name}, ON {on_name}."}
    far = rule.get("matching" if on_side else "applies_on") or {}
    return {"title": title, "copy": True, "msp": {"path": ["Rules", "Create Rule"], "fields": fields}, "app": app,
            "note": "Then Create." + (" Direction appears once Matching is set." if on_side else "")
                    + f" ({old_name} keeps its own rule; this one is for \"{new_name}\".)",
            "picture": "msp-rule-create.jpg", "undo": f"Delete the rule \"{name}\".",
            # Seen once the new group has this rule: same action, the group
            # on the same side, the same other end (howto_seen).
            "watch": {"kind": "pair_group", "members": moving, "as": "rule",
                      "rule": {"action": action, "side": "applies_on" if on_side else "matching", "other": [far.get("kind"), str(far.get("id"))]}}}


# A step the checker can't try out (part 1 of the safety plan, 24 Nov 2026):
# it only models traffic between your own clients.
HOWTO_UNTRIED_INTERNET = ("not tried out: it is about internet traffic, and Show Me How only checks traffic between "
                          "your own clients. Check it on the MSP after you do it.")


def howto_own_group_fix(act, srcs, today, groups, sides, suffix, port, lines=(), list_name="", prereq=()):
    """A group of their own (owner, 23 Nov 2026, D-922): Firewalla won't put
    a rule on one client of a group, so when only some of its clients were
    asked for, they move to a new group that gets a copy of everything the
    old one gives them (its rules, its Allowed Devices, VqLAN, Isolation and
    its settings). Block: the asked port is taken out of the rule that
    allows it today. Allow (part 3 of the safety plan, 24 Nov 2026): the new
    group alone gets the allow (lines = the target-list lines for B), so the
    rest of the old group doesn't. "summary" lists all the extra work up
    front. None when it doesn't apply (clients from several groups, or the
    whole group)."""
    if act not in ("block", "allow") or not srcs or (act == "allow" and not lines):
        return None
    olds = {g for x in srcs for g in x["groups"]}
    if len(olds) != 1:
        return None
    gid = olds.pop()
    g = groups.get(gid) or {}
    moving = [x["mac"] for x in srcs]
    members = [m for m in g.get("members") or [] if m in sides]
    if not members or set(members) <= set(moving):
        return None
    # The rules that allow what was asked to take away, each with the clients
    # it allows it to (their lines are the ones that change in its list).
    decided = {}
    for _, b, r in today:
        if act == "block" and r["verdict"] == "allowed" and r["deciding"].get("kind") == "rule":
            decided.setdefault(str(r["deciding"].get("pid")), []).append(b)
    deciding = set(decided)
    gname = g.get("name") or str(gid)
    new_name = howto_fit([gname, srcs[0]["name"] if len(srcs) == 1 else f"{len(srcs)} clients"], joiner=" - ")
    ngid = "new-own"
    ref = {"kind": "group", "id": ngid, "name": new_name}
    asked = set(suffix.split(":", 1)[1].split(",")) if port and port[1] != "any" and ":" in (suffix or "") else None
    who = ", ".join(x["name"] for x in srcs)
    left = howto_left_behind(gid, groups)
    steps = [{"title": f"Make a group \"{new_name}\" with only {', '.join(howto_id(x) for x in srcs)}",
              "msp": {"path": ["Groups & Users", "Create Group"], "fields": [["Name", new_name, new_name], ["Devices", ", ".join(howto_id(x) for x in srcs), None]]},
              "app": howto_app("create_group", name=new_name, devices=[howto_id(x) for x in srcs]),
              "note": f"{who} {'leaves' if len(srcs) == 1 else 'leave'} {gname}, which gives: " + ("; ".join(left[:12]) if left else "nothing else")
                      + (". The steps below set all of that up on the new group, except what you asked to take away." if act == "block"
                         else ". The steps below set all of that up on the new group, then what you asked to allow."),
              "undo": f"Move {who} back to {gname} and delete the group \"{new_name}\".",
              "watch": {"kind": "pair_group", "members": moving}}]
    if g.get("vqlan") or g.get("isolation"):
        steps.append({"title": f"Turn VqLAN {'on' if g.get('vqlan') else 'off'} and Device Isolation {'on' if g.get('isolation') else 'off'} for \"{new_name}\"",
                      "msp": {"path": ["Groups & Users", new_name], "fields": [["VqLAN", "On" if g.get("vqlan") else "Off", None], ["Device Isolation", "On" if g.get("isolation") else "Off", None]]},
                      "app": howto_app("toggles", unit=new_name, unit_kind="group", toggles=[["VqLAN", bool(g.get("vqlan"))], ["Device Isolation", bool(g.get("isolation"))]]),
                      "note": f"So {who} stay{'s' if len(srcs) == 1 else ''} fenced as before.", "undo": "Nothing (the group goes with the first step's undo).",
                      "watch": {"kind": "pair_group", "members": moving, "vqlan": bool(g.get("vqlan")), "isolation": bool(g.get("isolation")), "as": "setting"}})
    settings = (feature_settings.get("groups") or {}).get(str(gid)) or {}
    names = HOWTO_GROUP_SWITCHES
    on_settings = [names[k] for k in names if settings.get(k)]
    if on_settings:
        steps.append({"title": f"Turn on {', '.join(on_settings)} for \"{new_name}\"",
                      "msp": {"path": ["Groups & Users", new_name], "fields": [[n, "On", None] for n in on_settings]},
                      "app": howto_app("toggles", unit=new_name, unit_kind="group", toggles=[[n, True] for n in on_settings]),
                      "note": "Group settings don't move with a client."
                              + (" Allow rules don't get past Content Filtering or Safe Search (Firewalla's Rules Logic): what they block stays blocked."
                                 if {"Content Filtering", "Safe Search"} & set(on_settings) else ""),
                      "undo": "Nothing (the group goes with the first step's undo).",
                      "untried": HOWTO_UNTRIED_INTERNET,
                      "watch": {"kind": "pair_group", "members": moving, "as": "setting", "keys": [k for k in names if settings.get(k)]}})
    add, skipped = [], []
    local = {str(r.get("pid")) for r in access_local_rules()}
    for r in (state.get("policy_rules") or {}).get("rules") or []:
        if r.get("disabled") is True:
            continue
        sides_ = [s for s in ("applies_on", "matching") if (r.get(s) or {}).get("kind") == "group" and str((r.get(s) or {}).get("id")) == str(gid)]
        if not sides_:
            continue
        pid, text = str(r.get("pid")), access_rule_text(r)
        copy = {**r, "pid": f"own-{pid}", **{s: ref for s in sides_}}
        first = len(steps)
        if r.get("purpose") == "ap_allow":
            on, other = access_allowed_owner(r)
            far = other if str(on.get("id")) == str(gid) else on
            steps.append({"title": f"Tick {far.get('name') or far.get('id')} in \"{new_name}\"'s Allowed Devices",
                          "msp": {"path": ["Groups & Users", new_name, "Allowed Devices"], "fields": [["Tick", far.get("name") or "", None]]},
                          "app": howto_app("allowed", owner=new_name, owner_kind="group", names=[far.get("name") or ""]),
                          "note": "Then Save.", "picture": "msp-group-allowed-devices.jpg", "undo": "Nothing (the group goes with the first step's undo).",
                          "watch": {"kind": "pair_group", "members": moving, "as": "allowed", "ticked": [far.get("kind"), str(far.get("id"))]}})
        elif access_target_list_side(r) == "matching" and "applies_on" in sides_ and (asked or pid not in deciding):
            # A rule that uses one of your lists: the new group gets a list of
            # its own with it (a list has one owner, D-1061; before 24 Nov 2026
            # the copied rule used the old group's list).
            tl = msp["lists"].get(str((r.get("matching") or {}).get("id"))) or {}
            if pid in deciding:
                # The list as the new group gets it: the asked ports off the lines
                # of the clients asked about, every other line as it is (24 Nov
                # 2026: the ports went from every client's lines, and a line
                # giving every port stayed).
                ips = {ip for t in decided[pid] for ip in (t.get("ips") or [t.get("ip")]) + howto_reserved(t["mac"]) if ip}
                new_text = dict(howto_lines_without(tl.get("targets"), ips, port[0], asked)[1])
                lines = [str(new_text.get(t, t)) for t in tl.get("targets") or [] if new_text.get(t, t) is not None]
                if not lines:
                    skipped.append(f"#{pid} {text} (it only gave what you asked to take away)")
                    continue
            else:
                lines = [str(t) for t in tl.get("targets") or [] if str(t).strip()]
            lname = howto_fit([tl.get("name") or "List", srcs[0]["name"] if len(srcs) == 1 else f"{len(srcs)} clients"], joiner=" - ")
            steps.append({"title": f"Create the target list \"{lname}\" ({len(lines)} line{'s' if len(lines) != 1 else ''}, below)",
                          "msp": {"path": ["Target Lists", "Create Target List"], "fields": [["List Name", lname, lname], ["Category", "Private", None],
                                  ["Targets", f"{len(lines)} line{'s' if len(lines) != 1 else ''}", "\n".join(lines)], ["Notes", "what it's for", None]], "lines": lines},
                          "app": {"note": "Target lists can only be made on the MSP website."}, "note": "Then Create.", "picture": "msp-targetlist-create.jpg",
                          "undo": f"Delete the list \"{lname}\" (after its rule).", "watch": {"kind": "list", "name": lname, "lines": lines}})
            steps.append({"title": f"Create the rule \"{lname}\": {str(r.get('action') or 'allow').title()} Target List {lname} On \"{new_name}\"",
                          "copy": True, "msp": {"path": ["Rules", "Create Rule"], "fields": [
                              ["Name", lname, lname], ["Action", str(r.get("action") or "allow").title(), None], ["Matching", f"Target List › {lname}", None],
                              ["On", f"FWG Pro (Router) + {new_name}", None], ["Direction", {"outbound": "Outbound only", "inbound": "Inbound only"}.get(r.get("direction"), "Bi-directional"), None],
                              ["Schedule", "Always", None]]},
                          "app": howto_app("rule", name=lname, action=str(r.get("action") or "allow"), matching_path=f"Set a target › Target List › {lname}",
                                           matching_label="Target List", matching_value=lname, target=f"Target List {lname}", list=True,
                                           on_kind="group", on=new_name, direction=r.get("direction") or "bidirection"),
                          "note": "Then Create.", "picture": "msp-rule-create.jpg", "undo": f"Delete the rule \"{lname}\".",
                          "watch": {"kind": "rule", "action": str(r.get("action") or "allow"), "on": ["group", "*"], "list": lname}})
            copy = {**copy, "sim_targets": lines}
        elif pid in deciding:
            skipped.append(f"#{pid} {text} (it is what allows what you asked to take away)")
            continue
        else:
            steps.append(howto_rule_step(r, gname, new_name, "applies_on" in sides_, moving))
        if pid in local:
            add.append(copy)
        else:
            for st in steps[first:]:
                st["untried"] = HOWTO_UNTRIED_INTERNET
    if act == "allow":
        # What was asked, for the new group only: a target list of B + an Allow On it.
        lname = howto_fit([list_name or "List", srcs[0]["name"] if len(srcs) == 1 else f"{len(srcs)} clients"], joiner=" - ")
        steps = list(prereq) + steps
        steps.append({"title": f"Create the target list \"{lname}\"",
                      "msp": {"path": ["Target Lists", "Create Target List"], "fields": [["List Name", lname, lname], ["Category", "Private", None],
                              ["Targets", f"{len(lines)} line{'s' if len(lines) != 1 else ''}", "\n".join(lines)], ["Notes", "what it's for", None]], "lines": list(lines)},
                      "app": {"note": "Target lists can only be made on the MSP website."}, "note": "Then Create.", "picture": "msp-targetlist-create.jpg",
                      "undo": f"Delete the list \"{lname}\" (after its rule).", "watch": {"kind": "list", "name": lname, "lines": list(lines)}})
        steps.append({"title": f"Create the Allow rule On \"{new_name}\"", "msp": {"path": ["Rules", "Create Rule"], "fields": [
                          ["Name", lname, lname], ["Action", "Allow", None], ["Matching", f"Target List › {lname}", None],
                          ["On", f"FWG Pro (Router) + {new_name}", None], ["Direction", "Outbound only", None], ["Schedule", "Always", None]]},
                      "app": howto_app("rule", name=lname, action="allow", matching_path=f"Set a target › Target List › {lname}",
                                       matching_label="Target List", matching_value=lname, target=f"Target List {lname}", list=True,
                                       on_kind="group", on=new_name, direction="outbound"),
                      "note": f"Then Create. Only \"{new_name}\" gets it, not the rest of {gname}.", "picture": "msp-rule-create.jpg",
                      "undo": f"Delete the rule \"{lname}\".", "watch": {"kind": "rule", "action": "allow", "on": ["group", "*"], "list": lname}})
        add.append({"pid": "own-new", "action": "allow", "type": "category", "applies_on": ref,
                    "matching": {"kind": "target_list", "id": "TL-own-new", "name": lname}, "direction": "outbound",
                    "sim_targets": list(lines), "display_name": lname})
    # All the extra work, up front (part 3): what moving them brings with it.
    count = lambda pred: sum(1 for st in steps if pred(st))
    is_copy = lambda st: bool(st.get("copy"))
    copied = count(is_copy)
    internet = count(lambda st: st.get("untried") and is_copy(st))
    ticks = count(lambda st: (st.get("watch") or {}).get("as") == "allowed")
    summary = [f"{who} {'leaves' if len(srcs) == 1 else 'leave'} {gname}"]
    summary += [f"{copied} rule{'s' if copied != 1 else ''} copied to the new group" + (f" ({internet} of them internet rules, not tried out)" if internet else "")] if copied else []
    summary += [f"{ticks} Allowed Devices entr{'ies' if ticks != 1 else 'y'} copied"] if ticks else []
    summary += [f"VqLAN {'on' if g.get('vqlan') else 'off'}, Device Isolation {'on' if g.get('isolation') else 'off'}"] if g.get("vqlan") or g.get("isolation") else []
    summary += [f"group settings set again: {', '.join(on_settings)}"] if on_settings else []
    summary += [f"not copied: {'; '.join(skipped)}"] if skipped else []
    summary += [f"later changes to {gname} don't reach them: the new group needs its own"]
    return {"id": "own-group", "title": f"A group of their own: \"{new_name}\"",
            "detail": f"{who} {'leaves' if len(srcs) == 1 else 'leave'} {gname} for a new group with the same access, "
                      + ("minus what you asked" if act == "block" else "plus what you asked (only them)")
                      + (" · not copied: " + "; ".join(skipped) if skipped else ""),
            "summary": summary,
            "steps": steps, "add": add, "replace": {}, "remove": [], "groups": {"move": {m: ngid for m in moving}, "new": {ngid: {"id": ngid, "name": new_name,
                     "members": moving, "vqlan": bool(g.get("vqlan")), "isolation": bool(g.get("isolation"))}}}}


def howto_app(kind, **k):
    """A step in the Firewalla Android app: path, fields and a "form" the
    page draws like the app's own screen. Paths and words from the user's
    62 screenshots of the app (16 Nov 2026, docs/apps-screens): the app has
    no Direction field (it says it in a line under ON), Local Network
    targets carry it (Traffic from / to / from & to), a target-list Block
    adds Block Mode, an Allowed Devices entry is removed by pressing and
    holding it."""
    where = lambda unit_kind: ["Devices", "Groups"] if unit_kind == "group" else ["Devices", "All"]
    if kind == "rule":
        on_kind = {"group": "Group", "device": "Device", "network": "Network"}.get(k["on_kind"], "Group")
        if k.get("line") is not None:
            line = k["line"]
        elif k.get("direction") == "outbound":
            line = f"{k['action'].title()} all traffic from {on_kind} {k['on']} to {k['target']}."
        else:
            line = f"{k['action'].title()} all bidirectional traffic between {on_kind} {k['on']} and {k['target']}."
        return {"path": ["Home", "Rules", "Add Rule"], "picture": "app-rule-new.jpg",
                "fields": [["Name", k["name"], k["name"]], ["ACTION", k["action"].title(), None], ["MATCHING", k["matching_path"], None],
                           ["ON", f"{on_kind} › {k['on']}", None], ["SCHEDULE", "Active Time › Always", None]],
                "note": ("Then Save. Here the direction is in Matching (Traffic to)." if k.get("line") is not None else
                         "Then Save. The app has no Direction field: check the line under ON reads as below" + (
                             "; if it says bidirectional, set Outbound only on the MSP website instead." if k.get("direction") == "outbound" else ".")),
                "form": {"kind": "rule", "name": k["name"], "action": k["action"], "matching_label": k["matching_label"],
                         "matching": k["matching_value"], "block_mode": k["action"] == "block" and k.get("list"),
                         "on_kind": on_kind, "on": k["on"], "line": line}}
    if kind == "allowed":
        verb = "remove" if k.get("remove") else "add"
        return {"path": where(k["owner_kind"]) + [k["owner"], "Allowed Devices"] + ([] if verb == "remove" else ["Add Device"]),
                "picture": "app-allowed-delete.jpg" if verb == "remove" else "app-group-allowed.jpg" if k["owner_kind"] == "group" else "app-device-allowed.jpg",
                "fields": [["Tick" if verb == "add" else "Press and hold › Delete", n, None] for n in k["names"]],
                "note": ("Tap Add Device, tick them in the list (Search helps), then go back." if verb == "add"
                         else "Press and hold the entry, then Delete."),
                "form": {"kind": "allowed", "owner": k["owner"], "owner_kind": k["owner_kind"], "names": k["names"], "verb": verb}}
    if kind == "toggles":
        return {"path": where(k["unit_kind"]) + [k["unit"]],
                "picture": "app-group-page.jpg" if k["unit_kind"] == "group" else
                           "app-device-bottom.jpg" if any(t in ("Monitoring", "Emergency Access") for t, _ in k["toggles"]) else "app-device-page.jpg",
                "fields": [[t, "On" if on else "Off", None] for t, on in k["toggles"]],
                "note": "Scroll down to the switch" + ("es" if len(k["toggles"]) > 1 else "") + ".",
                "form": {"kind": "toggles", "unit": k["unit"], "unit_kind": k["unit_kind"], "toggles": k["toggles"]}}
    if kind == "create_group":
        return {"path": ["Devices", "Groups", "Create Group"], "picture": "app-create-group.jpg",
                "fields": [["Name", k["name"], k["name"]]] + [["Add Device › tick", n, None] for n in k["devices"]],
                "note": "Then Done, Confirm each \"Change of Group\" (it leaves its old group), then Save.",
                "form": {"kind": "create_group", "name": k["name"], "devices": k["devices"]}}
    if kind == "reserve":
        return {"path": ["Devices", "All", k["device"], "IP Address"], "picture": "app-ip-reserved.jpg",
                "fields": [["IP ALLOCATION", "Reserved", None], ["Reserved IP Address", k["ip"], k["ip"]]],
                "note": "The client gets the reserved address at its next connection.",
                "form": {"kind": "reserve", "device": k["device"], "ip": k["ip"]}}
    if kind == "pause":
        return {"path": ["Home", "Rules", k["scope"], k["rule"], "Pause Rule"], "picture": "app-rule-pause.jpg",
                "fields": [["Pause Rule", "Always Pause (or For 30 Minutes / For 1 Hour / Until…)", None]],
                "note": "Or Delete. Deleting a rule between two networks also deletes its mirror on the other network (the app says so).",
                "form": {"kind": "pause", "rule": k["rule"]}}
    return {}


def howto_reserve_step(x):
    """The step every list change starts with when a client it puts (or keeps)
    in a target list has no reserved address (owner, 23 Nov 2026, D-939):
    only then, short, with how to do it. The steps after it use that address."""
    return {"title": f"A reserved IP address is needed for {x['name']} ({x['ip']})",
            "msp": {"path": ["Devices", x["name"]], "fields": [["IP", f"reserve {x['ip']}", x["ip"]]]},
            "app": howto_app("reserve", device=x["name"], ip=x["ip"]),
            "note": "Target lists go by address: reserve this one so it doesn't change. The steps below already use it.",
            "undo": f"Remove the reservation of {x['name']} (only if nothing else needs it).",
            "watch": {"kind": "reserved", "mac": x["mac"], "ip": x["ip"]}}


def howto_fixes(act, units, srcs, dsts, dst_picked, pairs, today, rules, groups, port, suffix, words, iso, sides, paused, lists_taken=()):
    """The ways to get every pair to the wanted verdict, each with its
    steps, what it changes in the model (to try it out) and what it would
    watch for."""
    fixes = []
    addresses = []
    for d in dsts:
        ips, reserved = howto_addresses(d)
        for ip in ips:
            addresses.append({"mac": d["mac"], "name": d["name"], "ip": ip, "reserved": reserved})
    lines = list(dict.fromkeys(f"{x['ip']}{suffix}" for x in addresses))
    dst_ips = {x["ip"] for x in addresses}
    # An address in use that isn't the device's reservation is a shared one
    # (the DS923+ high-availability cluster's .254 follows the active node).
    shared_notes = [f"#{d['ip']} is {d['name']}'s address today but not its reserved one: a shared address (e.g. a NAS cluster's) that can move"
              for d in dsts if d.get("ip") and howto_reserved(d["mac"]) and d.get("ip") not in howto_reserved(d["mac"])]
    addresses = list({x["mac"]: x for x in addresses}.values())   # one reservation step per device
    prereq = [howto_reserve_step({"mac": x["mac"], "name": x["name"], "ip": x["ip"]}) for x in addresses if not x["reserved"]]

    # 1) A target list + a rule On each unit (the narrowest; works through
    # VqLAN and Device Isolation). Each unit gets a list of its own (owner,
    # 24 Nov 2026, D-1061): a list is never shared between groups, so a later
    # change for one can't change another's access.
    rule_action = "allow" if act == "allow" else "block"
    direction = "outbound" if act == "allow" else "bidirection"
    steps, add, replace = list(prereq), [], {}
    spare = howto_spare_list(dst_ips, suffix) if dst_ips else (None, None, None)
    extended, made, reused, taken = 0, 0, None, list(lists_taken)
    for i, u in enumerate(units):
        old_rule, old_list, why = howto_existing_list(u, rule_action, direction, suffix, dst_ips)
        if old_rule and old_list:
            extended += 1
            have = {str(t).strip().lower() for t in old_list["targets"]}
            missing = [l for l in lines if l.lower() not in have]
            users = howto_list_users((old_rule.get("matching") or {}).get("id"))
            # A list named after its old port only: worth renaming.
            named = re.findall(r"\d{2,5}", old_list.get("name") or "")
            rename = (f" Its name mentions only port {', '.join(named)}: you may want to rename it to include {words}."
                      if why == "devices" and named and not any(n in suffix for n in named) else "")
            if missing:
                steps.append({"title": f"Add {len(missing)} line{'s' if len(missing) != 1 else ''}{' for ' + words if why == 'devices' else ''} to your list \"{old_list['name']}\"",
                              "msp": {"path": ["Target Lists", old_list["name"]], "fields": [["Targets", "add these lines", "\n".join(missing)]], "lines": missing},
                              "app": {"note": "Target lists can only be edited on the MSP website."},
                              "note": f"Rule #{old_rule.get('pid')} already uses it On {u['name']}, so no new rule is needed. Then Save & Apply.{rename}"
                                      + howto_list_users_words(users, old_rule.get("pid")),
                              "picture": "msp-targetlist-edit.jpg", "undo": f"Remove those lines from \"{old_list['name']}\".",
                              "watch": {"kind": "list", "name": old_list["name"], "lines": missing}})
            # Every rule that uses this list gets the new lines (its other users are On the same unit).
            for r in [old_rule] + [x for x in users if str(x.get("pid")) != str(old_rule.get("pid"))]:
                replace[str(r.get("pid"))] = {**r, "sim_targets": list(old_list["targets"]) + missing}
            continue
        list_id = f"TL-new-{i}"
        if spare[0]:
            # One of your lists that no rule uses holds exactly these clients: it becomes this unit's.
            list_id, tl, how = spare
            spare = (None, None, None)
            name = reused = tl.get("name") or howto_own_list_name(u, dst_picked, dsts, taken, groups)
            if how == "edit":
                old = [str(t).strip() for t in tl.get("targets") or [] if str(t).strip()]
                steps.append({"title": f"Change your list \"{name}\" to {words}",
                              "msp": {"path": ["Target Lists", name], "fields": [["Targets", "replace its lines with these", "\n".join(lines)]], "lines": lines},
                              "app": {"note": "Target lists can only be edited on the MSP website."},
                              "note": "It already holds exactly these clients and no rule uses it, so it is reused instead of making a new list. Then Save & Apply.",
                              "picture": "msp-targetlist-edit.jpg", "undo": f"Put back its old lines: {'; '.join(old)}",
                              "watch": {"kind": "list", "name": name, "lines": lines}})
        else:
            made += 1
            name = howto_own_list_name(u, dst_picked, dsts, taken, groups)
            steps.append({"title": f"Create the target list \"{name}\"", "msp": {"path": ["Target Lists", "Create Target List"], "fields": [
                ["List Name", name, name], ["Category", "Private", None],
                ["Targets", f"{len(lines)} line{'s' if len(lines) != 1 else ''}", "\n".join([f"#Made by the dashboard's Show Me How, {datetime.now().strftime('%d %b %Y')}"] + shared_notes + lines)],
                ["Notes", "what it's for", None]], "lines": lines},
                "app": {"note": "Target lists can only be made on the MSP website."},
                "note": f"Then Create. It is {u['name']}'s own list: no other group's rule uses it.", "picture": "msp-targetlist-create.jpg",
                "undo": f"Delete the list \"{name}\" (after its rule).",
                "watch": {"kind": "list", "name": name, "lines": lines}})
        taken.append(name)
        steps.append({"title": f"Create the rule \"{name}\": {rule_action.title()} Target List {name} On {u['name']}", "msp": {"path": ["Rules", "Create Rule"], "fields": [
            ["Name", name, name], ["Action", rule_action.title(), None], ["Matching", f"Target List › {name}", None],
            ["On", f"FWG Pro (Router) + {u['name']}", None],
            ["Direction", "Outbound only" if direction == "outbound" else "Bi-directional", None], ["Schedule", "Always", None]]},
            "app": howto_app("rule", name=name, action=rule_action, matching_path=f"Set a target › Target List › {name}",
                             matching_label="Target List", matching_value=name, target=f"Target List {name}", list=True,
                             on_kind=u["kind"], on=u["name"], direction=direction),
            "note": "Then Create. Direction appears once Matching is set.", "picture": "msp-rule-create.jpg",
            "undo": f"Delete the rule \"{name}\" On {u['name']}.",
            "watch": {"kind": "rule", "action": rule_action, "on": [u["kind"], str(u["id"])], "list": name}})
        add.append({"pid": f"new-{i}", "action": rule_action, "type": "category", "applies_on": howto_unit_obj(u),
                    "matching": {"kind": "target_list", "id": list_id, "name": name}, "direction": direction,
                    "sim_targets": lines, "display_name": name})
    nets = [p for p in dst_picked if p["kind"] == "network"]
    parts = ([("Extend your list" if extended == 1 else f"Extend {extended} of your lists")] if extended and add else []) \
        + ([f"Your list \"{reused}\""] if reused else []) \
        + (["One target list" if made == 1 else f"{made} target lists"] if made else []) \
        + ([f"{len(add)} {rule_action.title()} rule{'s' if len(add) != 1 else ''}"] if add else [])
    fixes.append({"id": "list", "title": " + ".join(parts) if add else "Extend your existing list" if extended == 1 else f"Extend {extended} of your lists",
                  "detail": f"{words} only, to the {len(dsts)} client{'s' if len(dsts) != 1 else ''} you picked"
                            + (" · a list of today's clients: one that joins the network later isn't in it" if nets else ""),
                  "stale": bool(nets), "steps": steps, "add": add, "replace": replace, "remove": [], "groups": {}})

    # 1b) B is a whole network: Firewalla's own target, Local Network ›
    # Traffic to <network>, covers every device on it, now and later.
    if nets and len(nets) == len(dst_picked):
        steps, add = [], []
        for i, u in enumerate(units):
            for j, n in enumerate(nets):
                nid = n["ref"].partition(":")[2]
                steps.append({"title": f"Create the rule On {u['name']}: {rule_action.title()} traffic to {n['name']}", "msp": {"path": ["Rules", "Create Rule"], "fields": [
                    ["Name", f"{u['name']} to {n['name']}"[:60], f"{u['name']} to {n['name']}"[:60]], ["Action", rule_action.title(), None],
                    ["Matching", f"Local Network › Traffic to {n['name']}", None], ["On", f"FWG Pro (Router) + {u['name']}", None],
                    ["Direction", "Outbound only" if direction == "outbound" else "Bi-directional", None], ["Schedule", "Always", None]]},
                    "app": howto_app("rule", name=f"{u['name']} to {n['name']}"[:60], action=rule_action,
                                     matching_path=f"Set a target › Local Network › {n['name']} › Traffic to {n['name']}",
                                     matching_label=f"Traffic to {n['name']}", matching_value="", target=f"Network {n['name']}",
                                     on_kind=u["kind"], on=u["name"], direction=direction, line=""),
                    "note": "Then Create." + (" This rule has no ports: it covers every port." if suffix else ""), "picture": "msp-rule-create.jpg",
                    "undo": f"Delete the rule On {u['name']} for traffic to {n['name']}.",
                    "watch": {"kind": "rule_net", "action": rule_action, "on": [u["kind"], str(u["id"])], "network": nid}})
                add.append({"pid": f"new-net-{i}-{j}", "action": rule_action, "type": "network", "applies_on": howto_unit_obj(u),
                            "matching": {"kind": "network", "id": nid, "name": n["name"]}, "direction": direction,
                            "display_name": f"{u['name']} to {n['name']}"})
        fixes.append({"id": "network", "title": f"{len(add)} {rule_action.title()} rule{'s' if len(add) != 1 else ''} for traffic to the network",
                      "detail": "Firewalla's own Local Network target: every device on it, now and later"
                                + (", but every port" if suffix else "")
                                + (" · doesn't get through VqLAN or Isolation: only a target list or Allowed Devices does" if act == "allow" else ""),
                      "broader": bool(suffix), "steps": steps, "add": add, "replace": {}, "remove": [], "groups": {}})

    if act == "allow":
        # 2) Allowed Devices: one step per unit, but every port both ways.
        if all(u["kind"] in ("group", "device") for u in units):
            steps, add = [], []
            ticks_all = [p for p in dst_picked if p["kind"] in ("group", "device")]
            # Not the group itself in its own list (untested). A member may be
            # ticked: real test 6 (16 Nov 2026) - PC A PowerSpec 2 .5 ticked
            # in PC .5's own list reached and was reached by PC B ASUS .5
            # through B's own Isolation and the group's Isolation (AD6).
            inside = lambda p, u: u["kind"] == "group" and p["ref"] == "g:" + str(u["id"])
            member = lambda p, u: u["kind"] == "group" and p["kind"] == "device" and                 str(u["id"]) in (sides.get(p["ref"].partition(":")[2]) or {}).get("groups", [])
            for u in units:
                ticks = [p for p in ticks_all if not inside(p, u)]
                if not ticks:
                    continue
                steps.append({"title": f"Tick {', '.join(p['name'] for p in ticks)} in {u['name']}'s Allowed Devices",
                              "msp": {"path": howto_where(u) + ["Allowed Devices"], "fields": [["Tick", p["name"], None] for p in ticks]},
                              "app": howto_app("allowed", owner=u["name"], owner_kind=u["kind"], names=[p["name"] for p in ticks]),
                              "note": "Then Save." + "".join(f" {p['name']} is a member of {u['name']}: this opens it to every member, through the group's Isolation too." for p in ticks if member(p, u)),
                              "picture": "msp-group-allowed-devices.jpg",
                              "undo": f"Untick them again in {u['name']}'s Allowed Devices.",
                              "watch": {"kind": "allowed", "on": [u["kind"], str(u["id"])], "others": [[p["kind"], p["ref"].partition(":")[2]] for p in ticks], "present": True}})
                for j, p in enumerate(ticks):
                    add.append({"pid": f"new-ad-{u['key']}-{j}", "action": "allow", "purpose": "ap_allow", "direction": "bidirection",
                                "matching": howto_unit_obj(u), "applies_on": {"kind": p["kind"], "id": p["ref"].partition(":")[2], "name": p["name"]}})
            if steps:
                fixes.append({"id": "allowed", "title": "Allowed Devices", "detail": "simpler, but every port, both ways",
                              "broader": bool(suffix), "steps": steps, "add": add, "replace": {}, "remove": [], "groups": {}})
        # 3) A grouped device's own Allowed Devices (Firewalla's printer
        # example; works both ways, from either device's page: real tests 2, 2b).
        own = [x for x in srcs if x["groups"]][:10]
        ticks = [p for p in dst_picked if p["kind"] in ("group", "device")]
        # Only when A was picked as devices (a grouped device's unit is "partly").
        if own and ticks and all(u["partly"] or u["kind"] == "device" for u in units):
            steps, add = [], []
            for x in own:
                steps.append({"title": f"Tick {', '.join(p['name'] for p in ticks)} in {x['name']}'s own Allowed Devices",
                              "msp": {"path": ["Devices", x["name"], "Allowed Devices"], "fields": [["Tick", p["name"], None] for p in ticks]},
                              "app": howto_app("allowed", owner=x["name"], owner_kind="device", names=[p["name"] for p in ticks]),
                              "note": "Then Save. Only this client gets it, not the rest of its group.", "picture": "msp-group-allowed-devices.jpg",
                              "undo": f"Untick them again in {x['name']}'s Allowed Devices.",
                              "watch": {"kind": "allowed", "on": ["device", x["mac"]], "others": [[p["kind"], p["ref"].partition(":")[2]] for p in ticks], "present": True}})
                for j, p in enumerate(ticks):
                    add.append({"pid": f"new-dad-{x['mac']}-{j}", "action": "allow", "purpose": "ap_allow", "direction": "bidirection",
                                "applies_on": {"kind": "device", "id": x["mac"], "name": x["name"]},
                                "matching": {"kind": p["kind"], "id": p["ref"].partition(":")[2], "name": p["name"]}})
            fixes.append({"id": "allowed-device", "title": "The client's own Allowed Devices",
                          "detail": "only this client, but every port, both ways · tested on your network 16 Nov",
                          "broader": bool(suffix), "steps": steps, "add": add, "replace": {}, "remove": [], "groups": {}})
        # 4) A pair group: A and B move into a new group of their own.
        if len(srcs) == 1 and len(dsts) == 1 and (srcs[0]["groups"] or dsts[0]["groups"]):
            fixes.append(howto_pair_fix(srcs[0], dsts[0], suffix, words, groups, sides, iso))
    else:
        # 2) Take away what allows it today: an Allowed Devices entry, or an
        # allow rule (narrow its list, or pause it).
        deciders = {}
        for a, b, r in today:
            d = r["deciding"]
            if r["verdict"] == "allowed" and d.get("kind") == "rule" and d.get("pid"):
                deciders.setdefault(str(d["pid"]), []).append(b)
        for pid, targets in deciders.items():
            rule = next((x for x in rules if str(x.get("pid")) == pid), None)
            if not rule:
                continue
            if rule.get("purpose") == "ap_allow":
                on, other = access_allowed_owner(rule)
                fixes.append({"id": f"remove-{pid}", "title": f"Untick {other.get('name') or other.get('id')} in {on.get('name') or on.get('id')}'s Allowed Devices",
                              "detail": "closes every port both ways between them, not only these",
                              "steps": [{"title": f"Untick {other.get('name')} in {on.get('name')}'s Allowed Devices",
                                         "msp": {"path": (["Groups & Users"] if on.get("kind") == "group" else ["Devices"]) + [on.get("name") or "", "Allowed Devices"],
                                                 "fields": [["Untick", other.get("name") or "", None]]},
                                         "app": howto_app("allowed", owner=on.get("name") or "", owner_kind=on.get("kind"), names=[other.get("name") or ""], remove=True),
                                         "note": "Then Save.", "picture": "msp-group-allowed-devices.jpg",
                                         "undo": f"Tick {other.get('name')} again.",
                                         "watch": {"kind": "gone", "pid": pid}}],
                              "add": [], "replace": {}, "remove": [pid], "groups": {}})
            elif access_target_list_side(rule):
                tl = msp["lists"].get(str((rule.get(access_target_list_side(rule)) or {}).get("id"))) or {}
                # Every address the device answers on and its reservations (an
                # HA node's own line stays in the list while it is at .254).
                ips = {ip for t in targets for ip in (t.get("ips") or [t.get("ip")]) + howto_reserved(t["mac"]) if ip}
                # Only the ports asked for leave a line that names several (owner,
                # 23 Nov 2026, D-921: "192.168.5.254,tcp:7575,8180" was removed
                # whole to close 8180, taking 7575 away too): howto_lines_without.
                asked = set(suffix.split(":", 1)[1].split(",")) if port and port[1] != "any" and ":" in (suffix or "") else None
                keep_lines, edits = howto_lines_without(tl.get("targets"), ips, port[0] if port else None, asked)
                gone = [o for o, n in edits if n is None]
                changed = [(o, n) for o, n in edits if n]
                new_lines = [n for _, n in changed]
                steps_ = []
                if changed:
                    steps_.append({"title": f"Change {len(changed)} line{'s' if len(changed) != 1 else ''} in \"{tl.get('name')}\" (only {', '.join(sorted(asked))} goes)",
                                   "msp": {"path": ["Target Lists", tl.get("name") or ""],
                                           "fields": [["Change", f"{len(changed)} line{'s' if len(changed) != 1 else ''}", "\n".join(new_lines)]],
                                           "lines": new_lines, "old": [o for o, _ in changed]},
                                   "app": {"note": "Target lists can only be edited on the MSP website."}, "note": "Edit each line to the new text, then Save & Apply.",
                                   "picture": "msp-targetlist-edit.jpg", "undo": "Put the lines back as they were: " + "; ".join(o for o, _ in changed) + ".",
                                   "watch": {"kind": "list", "name": tl.get("name"), "lines": new_lines}})
                # (An edited line needs no step of its own to go: one list, one step each.)
                if gone:
                    steps_.append({"title": f"Remove these lines from \"{tl.get('name')}\"",
                                   "msp": {"path": ["Target Lists", tl.get("name") or ""],
                                           "fields": [["Remove", f"{len(gone)} lines", "\n".join(gone)]], "lines": gone},
                                   "app": {"note": "Target lists can only be edited on the MSP website."}, "note": "Then Save & Apply.",
                                   "picture": "msp-targetlist-edit.jpg", "undo": "Add the lines back.",
                                   "watch": {"kind": "list_without", "name": tl.get("name"), "lines": gone}})
                if not steps_:
                    continue
                title = (f"Take {', '.join(sorted(asked))} off {len(changed)} line{'s' if len(changed) != 1 else ''} in your list \"{tl.get('name')}\"" if changed and not gone
                         else f"Remove {len(edits)} line{'s' if len(edits) != 1 else ''} from your list \"{tl.get('name')}\"")
                # Every rule that uses this list loses the lines, not only #pid.
                users = howto_list_users((rule.get(access_target_list_side(rule)) or {}).get("id"))
                shared = howto_list_users_words(users, pid)
                for st in steps_:
                    st["note"] += shared
                fixes.append({"id": f"narrow-{pid}", "title": title,
                              "detail": f"rule #{pid} then no longer allows them{' on ' + ', '.join(sorted(asked)) if changed else ''}"
                                        + (" ·" + shared.rstrip(".") if shared else ""),
                              "steps": steps_,
                              "add": [], "replace": {str(r.get("pid")): {**r, "sim_targets": keep_lines + new_lines} for r in [rule] + [u for u in users if str(u.get("pid")) != pid]},
                              "remove": [], "groups": {}})
            else:
                fixes.append({"id": f"pause-{pid}", "title": f"Pause or delete rule #{pid}", "detail": access_rule_text(rule),
                              "steps": [{"title": f"Pause rule #{pid}", "msp": {"path": ["Rules", f"#{pid} {access_rule_text(rule)}"], "fields": [["Button", "Pause (or Delete)", None]]},
                                         "app": howto_app("pause", scope=((rule.get("applies_on") or {}).get("name") or (rule.get("applies_on") or {}).get("label") or "its scope"),
                                                          rule=access_rule_text(rule)), "note": "Rule Details › Pause.",
                                         "picture": "msp-rule-details.jpg", "undo": f"Resume rule #{pid}.", "watch": {"kind": "gone", "pid": pid}}],
                              "add": [], "replace": {}, "remove": [pid], "groups": {}})
    if act == "block":
        # 2b) Rules can't block two devices on one network (real tests 7
        # and 9, wired and Wi-Fi): Device Isolation on one of them can. It cuts that device off
        # from every local device but its Allowed Devices: the side-effect
        # check lists them.
        cut = [x for x in (srcs + dsts) if x["mac"] not in iso and not access_is_gear(x)]
        same_pairs = [(a, b) for a, b in pairs if a.get("network") and a.get("network") == b.get("network")
                      and a.get("link") in ("wired", "wifi", "lan") and b.get("link") in ("wired", "wifi", "lan")]
        if same_pairs and len(srcs) + len(dsts) <= 4:
            for x in cut:
                fixes.append({"id": f"isolate-{x['mac']}", "title": f"Turn on Device Isolation for {x['name']}",
                              "detail": "rules can't block two clients on the same network; Isolation cuts it off from every local client except its Allowed Devices",
                              "steps": [{"title": f"Turn on Device Isolation on {x['name']}'s own page",
                                         "msp": {"path": ["Devices", x["name"]], "fields": [["Device Isolation", "On", None]]},
                                         "app": howto_app("toggles", unit=x["name"], unit_kind="device", toggles=[["Device Isolation", True]]),
                                         "note": "Tick in its Allowed Devices anything it must still reach. Check the side effects below.",
                                         "undo": f"Turn Device Isolation off for {x['name']}.", "watch": {"kind": "isolated", "mac": x["mac"]}}],
                              "add": [], "replace": {}, "remove": [], "groups": {}, "isolate": {x["mac"]}})
    # 2c) A group of their own (D-922): some clients of a group leave it.
    own = howto_own_group_fix(act, srcs, today, groups, sides, suffix, port, lines, howto_list_name(units, dsts, words), prereq)
    if own:
        fixes.append(own)
    if act == "block":
        # 3) Firewalla isn't enforcing anything for a device in the way:
        # nothing else works until Monitoring is back on / Emergency Access ends.
        off, blocked_after = {}, False
        for a, b, r in today:
            if r["deciding"].get("kind") == "paused":
                blocked_after = blocked_after or any(st.get("effect") == "block" for st in r["steps"])
                for x in (a, b):
                    if x["mac"] in paused:
                        off[x["mac"]] = (x, paused[x["mac"]])
        if off:
            steps = []
            for x, why in off.values():
                monitoring = why.startswith("Monitoring")
                where = ("the whole box" if why.endswith("whole box") else f"{x['name']}'s network" if why.endswith("network")
                         else f"{x['name']}'s group" if why.endswith("group") else x["name"])
                steps.append({"title": f"{'Turn Monitoring back on' if monitoring else 'End Emergency Access'} for {where}",
                              "msp": {"path": ["Devices", x["name"]] if where == x["name"] else [where],
                                      "fields": [["Setting", "Monitoring: on" if monitoring else "Emergency Access: off", None]]},
                              "app": (howto_app("toggles", unit=x["name"], unit_kind="device",
                                                toggles=[["Monitoring", True]] if monitoring else [["Emergency Access", False]])
                                      if where == x["name"] else {"note": f"On {where}'s page in the app: the same switch."}),
                              "note": f"{why}: until then Firewalla enforces none of your rules, VqLAN or Isolation for it.",
                              "undo": "Set it back the way it was.", "watch": {"kind": "unpaused", "mac": x["mac"]}})
            # Every other way needs it first; on its own it only helps when
            # something already blocks the pair once Firewalla enforces again.
            for f in fixes:
                f["steps"] = steps + f["steps"]
                f["unpause"] = set(off)
            if blocked_after:
                fixes.insert(0, {"id": "unpause", "title": "Turn enforcement back on", "detail": "; ".join(dict.fromkeys(w for _, w in off.values())),
                                 "steps": steps, "add": [], "replace": {}, "remove": [], "groups": {}, "unpause": set(off)})
    return fixes


def howto_alarm_blocks(pairs, hours=24):
    """Asked pairs the router blocked with a rule an alarm made (the rule
    carries the alarm's id, "aid"): Active Protect's alarm rules beat every
    allow rule (Firewalla's Rules Logic), so no way here gets past them.
    -> [(a, b, rule)] from the recorded local traffic."""
    by_pid = {str(r.get("pid")): r for r in (state.get("policy_rules") or {}).get("rules") or [] if r.get("aid")}
    if not by_pid:
        return []
    want = {(a["mac"], b["mac"]): (a, b) for a, b in pairs}
    out, seen = [], set()
    for mac in list(dict.fromkeys(a["mac"] for a, _ in pairs))[:10]:
        for src, dst, outcome, *_, blocked_by in access_local_rows(hours, mac):
            k = (str(src).upper(), str(dst).upper())
            pid = str(blocked_by or "").partition("rule:")[2]
            if outcome == "blocked" and k in want and pid in by_pid and k not in seen:
                seen.add(k)
                out.append((*want[k], by_pid[pid]))
    return out


def howto_conditions(act, today, fixes, pairs, sides):
    """Why no rule can do it, for the pairs that need it (part 2 of the
    safety plan, 24 Nov 2026), each with what does work: {"id", "kind":
    "no_rule" (nothing Firewalla has decides it) | "limit" (rules can't,
    other ways can) | "warn" (the ways may not hold), "text", "works",
    "pairs"}. Only what the rule checker itself found: its deciding step
    for each pair, and the router's own records for alarm blocks."""
    want = "allowed" if act == "allow" else "blocked"
    need = [(a, b, r) for a, b, r in today if r["verdict"] != want]
    works = any(f["result"]["ok"] == f["result"]["of"] for f in fixes)
    out = []
    group = {}
    for a, b, r in need:
        same = a.get("network") and a.get("network") == b.get("network")
        kind = r["deciding"].get("kind")
        key = ("segment" if kind == "segment" else
               "gear" if same and (access_is_gear(a) or access_is_gear(b)) and act == "block" else
               "switched" if same and act == "block" and kind in ("switched", "none") else
               "fence" if same and act == "allow" and kind in ("vqlan", "isolation") else None)
        if key:
            group.setdefault(key, []).append((a, b, r))
    ex = lambda rows: f"{rows[0][0]['name']} → {rows[0][1]['name']}" + (f" and {len(rows) - 1} more pair{'s' if len(rows) > 2 else ''}" if len(rows) > 1 else "")
    if "segment" in group:
        rows = group["segment"]
        out.append({"id": "segment", "kind": "no_rule", "pairs": len(rows),
                    "text": f"{ex(rows)}: both are wired to a switch that isn't Firewalla's ({rows[0][0].get('segment')}). Their traffic "
                            f"never reaches Firewalla, so no rule, VqLAN, Isolation or Allowed Devices can {act} it.",
                    "works": ["Plug one of them into its own port on a Firewalla switch (or an AP7's spare port), then ask again"]})
    if "gear" in group:
        rows = group["gear"]
        out.append({"id": "gear", "kind": "no_rule", "pairs": len(rows),
                    "text": f"{ex(rows)}: Firewalla's own router, switches and access points aren't fenced by VqLAN or Isolation "
                            "(you tested it), and on one network the router's rules never see the traffic.",
                    "works": ["Only a client on another network than the unit can be blocked from it, by a rule"]})
    if "switched" in group:
        rows = group["switched"]
        isolate = any(f["id"].startswith("isolate-") and f["result"]["ok"] == f["result"]["of"] for f in fixes)
        out.append({"id": "switched", "kind": "limit" if isolate else "no_rule", "pairs": len(rows),
                    "text": f"{ex(rows)}: on one network the traffic goes through the switches and access points, and the router's "
                            "rules never see it (tested 16 Nov, wired and Wi-Fi). Only VqLAN, Isolation and Allowed Devices decide it.",
                    "works": ["Device Isolation on one of them: it cuts that client off from every other local client except its Allowed Devices",
                              "A group with VqLAN on that holds one of them and not the other: VqLAN keeps everyone outside the group out",
                              "Moving one of them to another network (for a wired client, its switch-port setting): then a rule can block it"]})
    if "fence" in group and not any(f["id"] == "list" and f["result"]["ok"] == f["result"]["of"] for f in fixes):
        rows = group["fence"]
        out.append({"id": "fence", "kind": "limit", "pairs": len(rows),
                    "text": f"{ex(rows)}: on one network an allow rule never gets through VqLAN or Isolation (tested 16 Nov): "
                            "the switches and access points enforce those, and they only know Allowed Devices.",
                    "works": ["Allowed Devices (every port, both ways)", "A group of their own (every port between them)"]})
    if act == "allow":
        alarms = howto_alarm_blocks(pairs)
        if alarms:
            a, b, rule = alarms[0]
            out.append({"id": "alarm", "kind": "warn", "pairs": len(alarms),
                        "text": f"The router blocked {a['name']} → {b['name']} with rule #{rule.get('pid')}, which an alarm made"
                                + (f" (and {len(alarms) - 1} more pair{'s' if len(alarms) > 2 else ''})" if len(alarms) > 1 else "")
                                + ": alarm rules beat every allow rule, so the ways below won't get past it while it is there.",
                        "works": ["Firewalla app › Alarms: find the alarm for these two clients and choose Allow (or Mute), so its block rule goes",
                                  f"Or Rules: delete rule #{rule.get('pid')}"]})
    if not works and not any(c["kind"] == "no_rule" for c in out):
        missed = {}
        for f in fixes:
            for m in f["result"].get("missed") or []:
                missed[m["text"]] = missed.get(m["text"], 0) + m["pairs"]
        out.append({"id": "none", "kind": "no_rule", "pairs": len(need),
                    "text": "No way found that does it for every pair."
                            + (" What still decides them in the ways tried: " + "; ".join(f"{t} ({n})" for t, n in list(missed.items())[:4]) + "." if missed else ""),
                    "works": ["Pick fewer clients, or one direction, and ask again"]})
    return out


HOWTO_SIDE_PAIRS = 20000  # most device pairs a way's side effects are checked on
HOWTO_SIDE_SHOWN = 40     # most of them listed by name


def howto_rule_ends(rule, sides):
    """The devices on each end of a rule: (MACs it goes On, MACs it
    Matches). A target-list end holds the devices whose address is in the
    list; an Allowed Devices entry is both ways, like any pair."""
    def end(name):
        obj = rule.get(name) or {}
        if obj.get("kind") == "target_list":
            if access_target_list_side(rule) != name:
                return set()
            entries = access_list_entries(rule) or []
            return {m for m, s in sides.items() if any(access_entry_covers(e, s, None) for e in entries)}
        return {m for m, s in sides.items() if access_covers(obj, s)}
    return end("applies_on"), end("matching")


def howto_side_pairs(fix, rules, sides, skip):
    """Every device pair a way can change: a pair's verdict depends only on
    the rules that match it, so only pairs a rule the way adds, removes or
    changes matches (before or after) can change. skip = the pairs asked
    for. -> ([(a, b)], how many there were, {(a, b): what touches it}).
    The first thing to touch a pair is named as its cause. Also -> the
    ports the rules touching each pair name ({(a, b): [(proto, n)]}), so a
    change on a port other than the asked one is seen too (24 Nov 2026)."""
    touched =[(r, "keep" if str(r.get("pid")).startswith("keep-") else "add") for r in fix["add"]] \
        + [(r, "remove") for r in rules if str(r.get("pid")) in fix["remove"]]
    for pid, new in fix["replace"].items():
        touched.append((new, "change"))
        # The rule as it is today too (D-921): a pair the change takes out
        # (an address leaving its target list) is matched only before it, and
        # was never checked, so taking a line away showed "changes nothing else".
        old = next((r for r in rules if str(r.get("pid")) == str(pid)), None)
        if old:
            touched.append((old, "change"))
    cause, ports = {}, {}
    for r, how in touched:
        text = access_rule_text(r)
        label = {"keep": f"a keep step: {text}", "add": f"new: {text}", "remove": f"#{r.get('pid')} {text} goes",
                 "change": f"{text} changes"}[how]
        on, matching = howto_rule_ends(r, sides)
        named = howto_rule_ports(r)
        for x in on:
            for y in matching:
                if x != y:
                    cause.setdefault((x, y), label)
                    cause.setdefault((y, x), label)
                    for k in ((x, y), (y, x)) if named else ():
                        have = ports.setdefault(k, [])
                        have.extend(p for p in named if p not in have)
    moved = (fix.get("groups") or {}).get("move") or {}
    for m, label in [(m, f"{sides[m]['name']} moves to a new group") for m in moved if m in sides] \
            + [(m, f"Isolation off on {sides[m]['name']}") for m in fix.get("unisolate") or () if m in sides] \
            + [(m, f"Isolation on {sides[m]['name']}") for m in fix.get("isolate") or () if m in sides]:
        for x in sides:
            if x != m:
                cause.setdefault((m, x), label)
                cause.setdefault((x, m), label)
    keys = set(cause) - skip
    ordered = sorted(keys, key=lambda k: (sides[k[0]]["name"].lower(), sides[k[1]]["name"].lower()))
    return [(sides[x], sides[y]) for x, y in ordered[:HOWTO_SIDE_PAIRS]], len(keys), cause, ports


def howto_trial(fix, rules, groups, sides, iso, paused):
    """The network as it would be with a way done: (rules, groups, moved(a, b)
    -> the two sides as they would be, Isolation set, paused devices)."""
    trial = [fix["replace"].get(str(r.get("pid")), r) for r in rules if str(r.get("pid")) not in fix["remove"]] + fix["add"]
    trial_paused = {m: w for m, w in paused.items() if m not in fix.get("unpause", ())}
    change = fix.get("groups") or {}
    if change:
        t_groups = {gid: {**g, "members": [m for m in g.get("members") or [] if m not in change["move"]]} for gid, g in groups.items()}
        t_groups.update(change["new"])
        # A move to None takes the client out of every group (Client Onboarding's mirror of an ungrouped client).
        t_sides = {m: ({**sd, "groups": [change["move"][m]] if change["move"][m] else []} if m in change["move"] else sd) for m, sd in sides.items()}
    else:
        t_groups, t_sides = groups, sides
    moved = lambda a, b: (t_sides.get(a["mac"], a), t_sides.get(b["mac"], b))
    t_iso = (set(iso) - set(fix.get("unisolate") or ())) | set(fix.get("isolate") or ())
    return trial, t_groups, moved, t_iso, trial_paused


# The port picture of a pair (owner, 18 Nov 2026: What Else This Changes must
# say exactly which ports are allowed or blocked, today and after a way).
# Ports are only limited by target-list lines here, so the checker is asked
# about: the ports you asked for, each port a target list names for the pair,
# and a port nothing names ("the rest"), TCP and UDP.
HOWTO_REST_PORTS = (("tcp", 9), ("udp", 9))


def howto_port_picture(a, b, groups, rules, iso, paused, asked=()):
    """"Blocked: all ports" / "Allowed: UDP 32768-65535 · Blocked: the rest"
    for a connection a starts to b, from the rule checker. asked = the
    asked ports (howto_asked_probes), each said on its own."""
    probes = []
    for p in asked or ():
        if p and p[1] != "any":   # every port of a protocol: the list ports and "the rest" say it
            probes.append((f"{p[0].upper()} {p[1]}", p))
    for st in check_local_access(a, b, groups, rules, isolated=iso, paused=paused)["steps"]:
        words = st.get("ports")
        if not words:
            continue
        proto, _, numbers = words.partition(" ")
        for part in numbers.split(",")[:6]:
            low = part.strip().split("-")[0]
            if low.isdigit() and proto.lower() in ("tcp", "udp"):
                probes.append((f"{proto.upper()} {part.strip()}", (proto.lower(), int(low))))
    verdict = lambda port: check_local_access(a, b, groups, rules, port=port, isolated=iso, paused=paused)["verdict"]
    rest = {proto: verdict(port) for proto, port in ((p, (p, n)) for p, n in HOWTO_REST_PORTS)}
    seen, named = set(), []
    for label, port in probes:
        if label not in seen:
            seen.add(label)
            named.append((label, verdict(port)))
    word = {"allowed": "Allowed", "blocked": "Blocked"}
    if rest["tcp"] == rest["udp"]:
        other = [(label, v) for label, v in named if v != rest["tcp"]]
        if not other:
            return f"{word[rest['tcp']]}: all ports"
        parts = {}
        for label, v in other:
            parts.setdefault(v, []).append(label)
        return " · ".join(f"{word[v]}: {', '.join(ls)}" for v, ls in parts.items()) + f" · {word[rest['tcp']]}: the rest"
    out = {}
    for label, v in named:
        if v != rest[label.split(" ")[0].lower()]:
            out.setdefault(v, []).append(label)
    out.setdefault(rest["tcp"], []).append("other TCP ports")
    out.setdefault(rest["udp"], []).append("other UDP ports")
    return " · ".join(f"{word[v]}: {', '.join(ls)}" for v, ls in out.items())


def howto_try(fix, rules, groups, pairs, asked_ports, iso, want, sides, paused, both=False, before_cache=None):
    """Run the checker with the fix in place: how many of the pairs asked
    for get the wanted verdict on every asked port, and every other pair
    whose verdict changes on any port (also, also_count; also_checked <
    also_pairs when there were too many to check). Another pair is checked
    on the asked ports, every port the rules touching it name, and a port
    nothing names, TCP and UDP (24 Nov 2026: only the asked port was, so a
    way that closed a pair's other ports showed "changes nothing else").
    both: the way back was asked for too, so it isn't a side effect.
    before_cache: today's verdict per ((a, b), port), shared by every way."""
    before_cache = {} if before_cache is None else before_cache
    trial, t_groups, moved, t_iso, trial_paused = howto_trial(fix, rules, groups, sides, iso, paused)
    after = howto_check([moved(a, b) for a, b in pairs], trial, t_groups, asked_ports, t_iso, trial_paused, want)
    ok = sum(1 for _, _, r in after if r["verdict"] == want)
    missed = {}
    for a, b, r in after:
        if r["verdict"] != want:
            missed[r["deciding"]["text"]] = missed.get(r["deciding"]["text"], 0) + 1
    asked = {(a["mac"], b["mac"]) for a, b in pairs}
    others, total, cause, named = howto_side_pairs(fix, rules, sides, asked | ({(y, x) for x, y in asked} if both else set()))
    rest = list(HOWTO_REST_PORTS)
    side, changes, changed = [], [], {}
    for a, b in others:
        k = (a["mac"], b["mac"])
        ma, mb = moved(a, b)
        diffs = []
        for p in list(dict.fromkeys(list(asked_ports) + named.get(k, [])[:HOWTO_PROBES_MAX] + rest)):
            if (k, p) not in before_cache:
                before_cache[(k, p)] = check_local_access(a, b, groups, rules, port=p, isolated=iso, paused=paused)["verdict"]
            v = check_local_access(ma, mb, t_groups, trial, port=p, isolated=t_iso, paused=trial_paused)["verdict"]
            if v != before_cache[(k, p)]:
                diffs.append((p, before_cache[(k, p)], v))
        if diffs:
            before, now = diffs[0][1], diffs[0][2]
            changed[k] = (before, now)
            side.append(f"{a['name']} → {b['name']}: {before} → {now}")
            changes.append({"a": a["mac"], "b": b["mac"], "an": a["name"], "bn": b["name"],
                            "before": before, "after": now, "cause": cause.get(k, ""),
                            # the ports that open: a keep step blocks just those
                            "opened": [p for p, x, y in diffs if x == "blocked" and y == "allowed"]})
    return {"ok": ok, "of": len(pairs), "missed": [{"text": t, "pairs": n} for t, n in missed.items()],
            "also": side[:HOWTO_SIDE_SHOWN], "also_count": len(side), "also_checked": len(others), "also_pairs": total,
            "changes": changes, "changed": changed}


HOWTO_KEEP_MAX = 300   # most impacted pairs Show Me How works out keep steps for


def howto_keep_ends(opened, suffix):
    """The list-line ends that block just the ports a way would open
    (howto_try's "opened"): ",tcp:445,139", a whole protocol for a port
    nothing names, no end for every port; the asked ports when unknown."""
    if not opened:
        return [suffix]
    if None in opened:
        return [""]
    out = []
    for proto in ("tcp", "udp"):
        ns = [n for p, n in opened if p == proto]
        if not ns:
            continue
        if "any" in ns or (proto, 9) in HOWTO_REST_PORTS and 9 in ns:
            out.append(f",{proto}:1-65535")
        else:
            out.append(f",{proto}:{','.join(str(n) for n in sorted(set(ns)))}")
    return out or [suffix]


def howto_keep_steps(fix, todo, sides, groups, suffix, asked=frozenset(), want="allowed"):
    """Steps that keep the ticked pairs as they are today (todo = impact
    rows). Lost access: the device's own Allowed Devices (on one network and
    between networks; beats group- and network-level blocks: real tests 2,
    3 and 11). Gained access between networks: a Block rule with a target
    list On the starting device's group (or the device). Gained access on
    one network can't be kept: only Isolation would stop it. -> rows that
    can't be kept, by key. A keep step never undoes what was asked: an
    Allowed Devices entry opens both ways, so not between a pair asked to
    be blocked; a Block not on a device asked to be reached."""
    cant = {}
    by_owner, planned = {}, set()
    for r in todo:
        if r["before"] != "allowed":
            continue
        if frozenset((r["a"], r["b"])) in planned:
            continue   # one entry works both ways
        if want == "blocked" and ((r["a"], r["b"]) in asked or (r["b"], r["a"]) in asked):
            cant[(r["a"], r["b"])] = "keeping it would need an Allowed Devices entry, which works both ways and would undo the block you asked for"
            continue
        planned.add(frozenset((r["a"], r["b"])))
        by_owner.setdefault(r["a"], []).append(r["b"])
    for a, bs in by_owner.items():
        x = sides[a]
        names = [howto_id(sides[m]) for m in bs if m in sides]
        fix["steps"].append({"title": f"Keep {x['name']}'s access: tick {', '.join(names[:4])}{f' and {len(names) - 4} more' if len(names) > 4 else ''} in its own Allowed Devices",
                             "keep": True, "keep_for": [(a, m) for m in bs] + [(m, a) for m in bs],
                             "keep_pids": [f"keep-{a}-{m}" for m in bs],
                             "msp": {"path": ["Devices", x["name"], "Allowed Devices"], "fields": [["Tick", n, None] for n in names]},
                             "app": howto_app("allowed", owner=x["name"], owner_kind="device", names=names),
                             "note": "Then Save. Keeps what this way would otherwise cut off (every port, both ways).",
                             "picture": "msp-group-allowed-devices.jpg",
                             "undo": f"Untick them again in {x['name']}'s Allowed Devices.",
                             "watch": {"kind": "allowed", "on": ["device", a], "others": [["device", m] for m in bs], "present": True}})
        for m in bs:
            fix["add"].append({"pid": f"keep-{a}-{m}", "action": "allow", "purpose": "ap_allow", "direction": "bidirection",
                               "applies_on": {"kind": "device", "id": a, "name": x["name"]},
                               "matching": {"kind": "device", "id": m, "name": sides[m]["name"] if m in sides else m}})
    by_unit = {}
    for r in todo:
        if r["before"] != "blocked" and not r.get("opened"):
            continue
        x, y = sides.get(r["a"]), sides.get(r["b"])
        if want == "allowed" and any(b_ == r["b"] for _, b_ in asked):
            cant[(r["a"], r["b"])] = "a Block to keep it would also stop what you asked to allow"
            continue
        if not x or not y or x.get("network") == y.get("network") or access_is_gear(x) or access_is_gear(y):
            cant[(r["a"], r["b"])] = "on one network only Isolation stops it, and that cuts the client off from everything else"
            continue
        if "Allowed Devices" in (r.get("cause") or ""):
            # An entry opens both ways and beats rules (real test 11).
            cant[(r["a"], r["b"])] = "it comes from an Allowed Devices entry, which works both ways: no rule can block one direction of it"
            continue
        unit = ("group", x["groups"][0]) if x["groups"] else ("device", x["mac"])
        by_unit.setdefault(unit, {})[y["mac"]] = y
        by_unit[unit].setdefault("_keys", []).append((r["a"], r["b"]))
        have = by_unit[unit].setdefault("_ports", {}).setdefault(y["mac"], [])
        have.extend(p for p in r.get("opened") or [] if p not in have)
    for (kind, uid), found in by_unit.items():
        keys = found.pop("_keys")
        opened = found.pop("_ports")
        ys = list(found.values())
        uname = (groups.get(uid) or {}).get("name") or uid if kind == "group" else sides[uid]["name"]
        lines = list(dict.fromkeys(f"{ip}{end}" for y in ys for end in howto_keep_ends(opened.get(y["mac"]), suffix)
                                   for ip in howto_addresses(y)[0]))
        lname = howto_fit([uname, ys[0]["name"]], " from ", f"+{len(ys) - 1}" if len(ys) > 1 else "", prefix="Keep ")
        have = {(st.get("watch") or {}).get("mac") for st in fix["steps"] if (st.get("watch") or {}).get("kind") == "reserved"}
        for y in ys:
            if y.get("ip") and not howto_addresses(y)[1] and y["mac"] not in have:
                fix["steps"].append({**howto_reserve_step(y), "keep": True, "keep_for": keys, "keep_pids": []})
        fix["steps"].append({"title": f"Keep {uname} blocked from {', '.join(y['name'] for y in ys[:3])}{' …' if len(ys) > 3 else ''}: a target list", "keep": True,
                             "keep_for": keys, "keep_pids": [],
                             "msp": {"path": ["Target Lists", "Create Target List"], "fields": [["List Name", lname, lname], ["Category", "Private", None],
                                     ["Targets", f"{len(lines)} line{'s' if len(lines) != 1 else ''}", "\n".join(lines)]], "lines": lines},
                             "app": {"note": "Target lists can only be made on the MSP website."}, "note": "Then Create.",
                             "picture": "msp-targetlist-create.jpg", "undo": f"Delete the list \"{lname}\" (after its rule).",
                             "watch": {"kind": "list", "name": lname, "lines": lines}})
        fix["steps"].append({"title": f"Keep {uname} blocked: the Block rule", "keep": True,
                             "keep_for": keys, "keep_pids": [f"keep-blk-{uid}"],
                             "msp": {"path": ["Rules", "Create Rule"], "fields": [["Name", lname, lname], ["Action", "Block", None],
                                     ["Matching", f"Target List › {lname}", None], ["On", f"FWG Pro (Router) + {uname}", None],
                                     ["Direction", "Outbound only", None], ["Schedule", "Always", None]]},
                             "app": howto_app("rule", name=lname, action="block", matching_path=f"Set a target › Target List › {lname}",
                                              matching_label="Target List", matching_value=lname, target=f"Target List {lname}", list=True,
                                              on_kind=kind, on=uname, direction="outbound"),
                             "note": "Then Create.", "picture": "msp-rule-create.jpg", "undo": f"Delete the rule \"{lname}\".",
                             "watch": {"kind": "rule", "action": "block", "on": [kind, str(uid)], "list": lname}})
        fix["add"].append({"pid": f"keep-blk-{uid}", "action": "block", "type": "category",
                           "applies_on": {"kind": kind, "id": uid, "name": uname},
                           "matching": {"kind": "target_list", "id": f"TL-keep-{uid}", "name": lname}, "direction": "outbound",
                           "sim_targets": lines, "display_name": lname})
    return cant


def howto_keep(fix, idx, let, rules, groups, pairs, probes, iso, want, sides, paused, both, before_cache, suffix, words="", today_cache=None):
    """Try a way, then keep every impacted pair you haven't unticked (let =
    "<direction>:<A MAC>><B MAC>" keys you allow to change, the same for
    every way: you decide What Else This Changes once, 18 Nov 2026): add the
    steps that keep them, try again, and so on - pairs the added steps
    disturb join the list, ticked - for up to 3 rounds. Sets fix["result"]
    with impacts: every pair the way (or its keep steps) would change, with
    today's verdict, after the way alone, after everything, the cause,
    whether it is kept and its status: kept / changes (you unticked it) /
    stays (unticked, but a keep step for another pair keeps it) / can't keep."""
    rows, done, cant = {}, set(), {}
    for rnd in range(4):
        res = howto_try(fix, rules, groups, pairs, probes, iso, want, sides, paused, both, before_cache)
        for c in res["changes"]:
            k = (c["a"], c["b"])
            if k not in rows:
                rows[k] = {**c, "round": rnd,
                           "keep": f"{idx}:{c['a']}>{c['b']}" not in let}
        todo = [r for k, r in rows.items() if r["keep"] and k not in done and k not in cant]
        if rnd == 3 or not todo or len(rows) > HOWTO_KEEP_MAX or not res["ok"]:
            break
        done |= {(r["a"], r["b"]) for r in todo}
        asked = {(a["mac"], b["mac"]) for a, b in pairs}
        cant.update(howto_keep_steps(fix, todo, sides, groups, suffix, asked, want))
    # A keep step that keeps none of its pairs goes (with what it adds),
    # and the way is tried once more without it.
    useless = [st for st in fix["steps"] if st.get("keep")
               and not any(k in rows and k not in res["changed"] for k in st.get("keep_for") or [])]
    if useless:
        gone = {pid for st in useless for pid in st.get("keep_pids") or []}
        fix["steps"] = [st for st in fix["steps"] if st not in useless]
        fix["add"] = [r for r in fix["add"] if str(r.get("pid")) not in gone]
        for st in useless:
            for k in st.get("keep_for") or []:
                cant.setdefault(k, "the step that would keep it wouldn't work, so it was left out")
        res = howto_try(fix, rules, groups, pairs, probes, iso, want, sides, paused, both, before_cache)
    for st in fix["steps"]:
        st.pop("keep_for", None)
        st.pop("keep_pids", None)
    # Each pair's ports today and after this way (its keep steps included).
    today_cache = {} if today_cache is None else today_cache
    trial, t_groups, moved, t_iso, trial_paused = howto_trial(fix, rules, groups, sides, iso, paused)
    for k, r in rows.items():
        x, y = sides.get(r["a"]), sides.get(r["b"])
        if not x or not y:
            continue
        if k not in today_cache:
            today_cache[k] = howto_port_picture(x, y, groups, rules, iso, paused, probes)
        r["today_ports"] = today_cache[k]
        r["after_ports"] = howto_port_picture(*moved(x, y), t_groups, trial, t_iso, trial_paused, probes)
    final = res["changed"]
    for k, r in rows.items():
        if k in final:
            r["before"], r["after"] = final[k]
        else:
            r["after"] = r["before"]
        r["status"] = ("kept" if r["after"] == r["before"] else "cant") if r["keep"] else             ("changes" if r["after"] != r["before"] else "stays")
        if r["status"] == "stays":
            r["why"] = "a keep step for another pair keeps this one too (an Allowed Devices entry works both ways)"
        if r["status"] == "cant":
            r["why"] = cant.get(k) or ("too many pairs to work out (over 300): untick some or pick another way"
                                       if len(rows) > HOWTO_KEEP_MAX else
                                       "this way doesn't work for what you asked, so no keep steps were worked out" if not res["ok"] else
                                       "no step found that keeps it without changing more")
    changed = [r for r in rows.values() if r["after"] != r["before"]]
    res.update(impacts=sorted(rows.values(), key=lambda r: (r["an"].lower(), r["bn"].lower())),
               also=[f"{r['an']} → {r['bn']}: {r['before']} → {r['after']}" for r in changed][:HOWTO_SIDE_SHOWN],
               also_count=len(changed), keep_steps=sum(1 for s_ in fix["steps"] if s_.get("keep")))
    for r in rows.values():
        r.pop("opened", None)
    del res["changes"], res["changed"]
    fix["result"] = res


HOWTO_EXPECT_MAX = 1000   # most pairs a change's before-and-after check records


def howto_expect(fix, rules, groups, pairs, probes, iso, sides, paused):
    """Before-and-after check, part 1 (part 4 of the safety plan, 24 Nov
    2026): every pair the way touches (the pairs asked for and every other
    pair a rule, group move or Isolation change of it can reach), each port
    it is checked on, today's verdict and the verdict the way should leave.
    -> [{"a", "b", "an", "bn", "ports", "before", "expect"}]; port = [proto,
    number] or null for every port."""
    trial, t_groups, moved, t_iso, trial_paused = howto_trial(fix, rules, groups, sides, iso, paused)
    others, _, _, named = howto_side_pairs(fix, rules, sides, set())
    rest = list(HOWTO_REST_PORTS)
    out, seen = [], set()
    for a, b in list(pairs) + others:
        k = (a["mac"], b["mac"])
        if k in seen or len(out) >= HOWTO_EXPECT_MAX:
            continue
        seen.add(k)
        ports = list(dict.fromkeys(list(probes) + named.get(k, [])[:HOWTO_PROBES_MAX] + rest))
        ma, mb = moved(a, b)
        out.append({"a": a["mac"], "b": b["mac"], "an": a["name"], "bn": b["name"], "ports": [list(p) if p else None for p in ports],
                    "before": [check_local_access(a, b, groups, rules, port=p, isolated=iso, paused=paused)["verdict"] for p in ports],
                    "expect": [check_local_access(ma, mb, t_groups, trial, port=p, isolated=t_iso, paused=trial_paused)["verdict"] for p in ports]})
    return out


def howto_verify(expect):
    """Before-and-after check, part 2: every recorded pair checked again
    against your rules as they are now. A pair that isn't what the way
    should have left is flagged: it changed when it shouldn't have, or
    didn't change when it should. -> {"at", "pairs", "unexpected": [{"an",
    "bn", "port", "before", "expected", "now"}], "count"}."""
    sides, groups = access_sides()
    rules, iso = access_local_rules(), access_isolated()
    paused = {m: why for m, sd in sides.items() if (why := access_paused(sd))}
    bad, checked = [], 0
    for e in expect or []:
        a, b = sides.get(e["a"]), sides.get(e["b"])
        if not a or not b:
            continue
        checked += 1
        for port, before, want in zip(e["ports"], e["before"], e["expect"]):
            p = tuple(port) if port else None
            now = check_local_access(a, b, groups, rules, port=p, isolated=iso, paused=paused)["verdict"]
            if now != want:
                bad.append({"an": e["an"], "bn": e["bn"], "port": f"{p[0].upper()} {p[1]}" if p else "every port",
                            "before": before, "expected": want, "now": now})
                break
    return {"at": time.time(), "pairs": checked, "unexpected": bad[:40], "count": len(bad)}


def howto_verify_words(v):
    """The check in one line, for the Changes list and the change's history."""
    if not v:
        return ""
    if not v["count"]:
        return f"Before-and-after check: all {v['pairs']} client pairs it touches are as expected."
    first = v["unexpected"][0]
    return (f"Before-and-after check: {v['count']} of {v['pairs']} client pairs aren't as expected, e.g. {first['an']} → {first['bn']} "
            f"({first['port']}): {first['now']} now, should be {first['expected']} (was {first['before']}).")


def howto_work(fix):
    """A way's work in a few words: "Create 1 target list, create 1 rule,
    change 2 Allowed Devices lists" (owner, 18 Nov 2026), from its steps."""
    count = {}
    for st in fix.get("steps") or []:
        w = st.get("watch") or {}
        kind, path = w.get("kind"), (st.get("msp") or {}).get("path") or []
        what = ("create target list" if kind == "list" and "Create Target List" in path else
                "change target list" if kind in ("list", "list_without") else
                "create rule" if kind in ("rule", "rule_net") else
                "remove rule or entry" if kind == "gone" else
                "change Allowed Devices list" if kind == "allowed" or w.get("as") == "allowed" else
                # (A group-of-their-own step watched through its group: counted as what it does, D-922.)
                "create rule" if w.get("as") == "rule" else
                "change group setting" if w.get("as") == "setting" else
                "create group" if kind == "pair_group" else
                "reserve address" if kind == "reserved" else
                "change device" if kind in ("isolated", "not_isolated", "unpaused") else "other step")
        count[what] = count.get(what, 0) + 1
    words = [("create target list", "create", "target list", "target lists"), ("change target list", "change", "target list", "target lists"),
             ("create rule", "create", "rule", "rules"), ("remove rule or entry", "remove", "rule or entry", "rules or entries"),
             ("change Allowed Devices list", "change", "Allowed Devices list", "Allowed Devices lists"),
             ("create group", "create", "group", "groups"), ("change group setting", "set", "group setting", "group settings"),
             ("reserve address", "reserve", "address", "addresses"),
             ("change device", "change", "device", "devices"), ("other step", "do", "other step", "other steps")]
    text = ", ".join(f"{verb} {count[k]} {one if count[k] == 1 else many}" for k, verb, one, many in words if count.get(k))
    return text[:1].upper() + text[1:]


def howto_merged(fixes, words, sides, groups, idx):
    """What Else This Changes for every way at once (owner, 18 Nov 2026): each
    pair a way would change, once, with exactly which ports are allowed or
    blocked today ("today"), and after: the same when you keep it, else one
    line per way that changes it ("ways": its id, title, ports after, offered).
    When every device of a group is in rows that are otherwise alike, they
    show as the group (one row, one tick box for all of them).

    Only the ways that do what you asked for every pair count (D-923; here
    since 24 Nov 2026): a way that doesn't work is never listed under How To
    Make It True, so the pairs only it would change are nothing to decide.
    A Block request between two groups listed 34 rows, 17 of them from ways
    that didn't work."""
    working = [f for f in fixes if (f.get("result") or {}).get("ok") == (f.get("result") or {}).get("of")]
    rows = {}
    for f in working:
        for m in (f.get("result") or {}).get("impacts") or []:
            k = (m["a"], m["b"])
            r = rows.setdefault(k, {"a": [m["a"]], "b": [m["b"]], "an": m["an"], "bn": m["bn"], "before": m["before"],
                                    "today": m.get("today_ports") or m["before"].capitalize(), "keep": m["keep"],
                                    "ways": [], "kept_by": 0, "cant": None})
            after = m.get("after_ports") or m["after"].capitalize()
            if after != r["today"]:
                r["ways"].append({"id": f["id"], "title": f.get("title"), "after": after, "offer": bool(f.get("offer"))})
            # A ticked pair no way can keep says so (and why), so After = Today
            # never promises what no way does. A way that doesn't touch the
            # pair keeps it too.
            if m["keep"] and m.get("status") == "cant":
                r["cant"] = r["cant"] or m.get("why")
                r["kept_by"] -= 1
    for r in rows.values():
        r["kept_by"] += len(working)   # = the working ways that keep it (touching it or not)
        if r["keep"] and r["kept_by"] <= 0 and not r["cant"]:
            r["cant"] = "no way that does what you asked keeps it"
    out = list(rows.values())
    for side, name in (("a", "an"), ("b", "bn")):
        other, oname = ("b", "bn") if side == "a" else ("a", "an")
        merged, used = [], set()
        for gid, g in groups.items():
            members = set(g.get("members") or [])
            if len(members) < 2:
                continue
            buckets = {}
            for i, r in enumerate(out):
                if i in used or len(r[side]) != 1 or r[side][0] not in members:
                    continue
                buckets.setdefault((tuple(r[other]), r["today"], json.dumps(r["ways"]), r["keep"], bool(r["cant"] and not r["kept_by"])), []).append(i)
            for key, ids in buckets.items():
                if {out[i][side][0] for i in ids} == members:
                    first = out[ids[0]]
                    merged.append({**first, side: sorted(members), name: f"{g.get('name') or gid} ({len(members)})"})
                    used.update(ids)
        out = merged + [r for i, r in enumerate(out) if i not in used]
    for r in out:
        r["keys"] = [f"{idx}:{a}>{b}" for a in r["a"] for b in r["b"]]
        kept = r.pop("kept_by", 0)
        r["cant"] = r["cant"] if r["keep"] and not kept else None
        r["after"] = r["today"] if r["keep"] else None   # unticked: one line per way (ways)
    return sorted(out, key=lambda r: (r["an"].lower(), r["bn"].lower()))


def howto_direction(act, a_refs, b_refs, port, suffix, words, sides, groups, rules, iso, paused, label, both=False, idx=0, let=frozenset(), model=False,
                    lists_taken=()):
    # lists_taken: names of the lists a plan of several parts has already given out
    # (Client Onboarding, From Scratch: one list per target, each with its own number).
    want = "allowed" if act == "allow" else "blocked"
    srcs, units, a_picked = howto_expand(a_refs, sides, groups)
    dsts, _, b_picked = howto_expand(b_refs, sides, groups)
    pairs = [(a, b) for a in srcs for b in dsts if a["mac"] != b["mac"]]
    cut = len(pairs) > HOWTO_MAX_PAIRS
    pairs = pairs[:HOWTO_MAX_PAIRS]
    probes = howto_asked_probes(port, suffix)
    today = howto_check(pairs, rules, groups, probes, iso, paused, want)
    deciders = {}
    for a, b, r in today:
        key = (r["verdict"], r["deciding"]["text"])
        deciders.setdefault(key, {"verdict": r["verdict"], "text": r["deciding"]["text"], "pid": r["deciding"].get("pid"), "pairs": 0,
                                  "example": f"{a['name']} → {b['name']}", "_pairs": []})
        deciders[key]["pairs"] += 1
        deciders[key]["_pairs"].append((a["mac"], b["mac"]))   # for Traffic Seen (howto_traffic); not sent
    need = [t for t in today if t[2]["verdict"] != want]
    picked_srcs = {s["mac"] for s in srcs}
    # Devices A doesn't name but that share a unit (they'd get the rule too).
    # B's own devices aren't among them: a rule to reach yourself does nothing.
    extra = sorted({m for u in units for m in u["members"]} - picked_srcs - {d["mac"] for d in dsts})
    fixes = []
    if need and units and dsts:
        fixes = howto_fixes(act, units, srcs, dsts, b_picked, pairs, today, rules, groups, port, suffix, words, iso, sides, paused, lists_taken)
        before_cache, today_cache = {}, {}
        for f in fixes:
            howto_keep(f, idx, let, rules, groups, pairs, probes, iso, want, sides, paused, both, before_cache, suffix, words, today_cache)
            howto_lookalike_notes(f)
            if model:   # I'm Doing This: what every pair it touches should be afterwards (part 4)
                f["expect"] = howto_expect(f, rules, groups, pairs, probes, iso, sides, paused)
                # What the way changes, for a caller that adds ways together (Client Onboarding).
                f["model"] = {k: f.get(k) for k in ("add", "replace", "remove", "groups", "isolate", "unisolate", "unpause")}
            del f["add"], f["replace"], f["remove"], f["groups"]
            f.pop("unpause", None)
            f.pop("unisolate", None)
            f.pop("isolate", None)
        # Ways that work first, then those that change nothing else, then
        # the fewest other pairs changed; the list way first among equals.
        # Ways that work first, then those that change nothing you kept, the
        # fewest other pairs changed, the fewest keep steps, then the ports.
        # A way whose other pairs weren't all checked comes after one whose were.
        fixes.sort(key=lambda f: (f["result"]["ok"] < f["result"]["of"], f["result"]["also_count"] > 0,
                                  f["result"]["also_checked"] < f["result"]["also_pairs"],
                                  f["result"]["also_count"], f["result"]["keep_steps"], bool(f.get("broader")),
                                  bool(f.get("stale")), f["id"] != "list"))
        # Offered: a way that changes no pair you keep (every ticked pair it
        # touches stays as today, by its own keep steps if need be).
        for f in fixes:
            f["work"] = howto_work(f)
            f["untried"] = sum(1 for st in f["steps"] if st.get("untried"))
            f["offer"] = not any(m["status"] == "cant" for m in f["result"].get("impacts") or [])
    return {
        "label": label, "a": a_picked, "b": b_picked, "pairs": len(pairs), "cut": cut,
        "today": sorted(deciders.values(), key=lambda d: -d["pairs"]),
        "need": len(need), "done": not need,
        "units": [{"kind": u["kind"], "name": u["name"], "members": len(u["members"]), "partly": u["partly"]} for u in units],
        "extra": [sides[m]["name"] for m in extra if m in sides][:30], "extra_count": len(extra),
        "fixes": fixes,
        # Why no rule can do it, and what does (part 2 of the safety plan).
        "conditions": howto_conditions(act, today, fixes, pairs, sides) if need else [],
        "impacts": howto_merged(fixes, words, sides, groups, idx),
        # clean: a way gets every pair there without changing any other pair;
        # exact: one also keeps to the ports asked for.
        "clean": any(f["result"]["ok"] == f["result"]["of"] and not f["result"]["also_count"] for f in fixes),
        "exact": any(f["result"]["ok"] == f["result"]["of"] and not f["result"]["also_count"] and not f.get("broader") for f in fixes),
    }


def howto_plan(act, a, b, proto, port, both, let="", model=False):
    """let: the impacted pairs you unticked ("Keep As Today"), comma-separated
    "<direction>:<A MAC>><B MAC>"; every other impacted pair is kept.
    model: for I'm Doing This, each way also carries "expect" (howto_expect);
    worked out fresh, never kept."""
    act = "block" if act == "block" else "allow"
    let = frozenset(x[:80] for x in str(let or "").split(",") if x)
    # A ref is "g:<id>", "n:<uuid>" or "d:<MAC>"; a pick has at most 300.
    a_refs = [r[:80] for r in str(a or "").split(",") if r][:300]
    b_refs = [r[:80] for r in str(b or "").split(",") if r][:300]
    if not a_refs or not b_refs:
        return None
    check, suffix, words = howto_port(proto, port)
    sides, groups = access_sides()
    rules = access_local_rules()
    iso = access_isolated()
    paused = {m: why for m, sd in sides.items() if (why := access_paused(sd))}
    # The page asks again every 20 s and a big pick (every group to every
    # group) takes ~18 s to work out (measured 14 Nov 2026), so an answer is
    # kept while the pick and everything it was worked out from stay the same.
    # Rule hit counts (in the rules and in each group's Allowed Devices),
    # times and online flags change all the time without changing the answer.
    def steady(v):
        if isinstance(v, dict):
            return {k: steady(x) for k, x in v.items()
                    if k not in ("online", "hit_count", "last_hit") and not k.endswith(("_at", "_ts"))}
        return [steady(x) for x in v] if isinstance(v, (list, tuple)) else v
    key = hashlib.sha1(json.dumps(steady(
        [act, a_refs, b_refs, check, suffix, bool(both), sorted(let), rules, groups, sorted(iso), sides,
         {k: v for k, v in feature_settings.items() if k != "updated_at"}, msp["lists"]]),
        sort_keys=True, default=str).encode()).hexdigest()
    with howto_plan_lock:
        if key in howto_plan_cache and not model:
            return howto_plan_cache[key]
    out = {"act": act, "words": words, "both": bool(both), "directions": [
        howto_direction(act, a_refs, b_refs, check, suffix, words, sides, groups, rules, iso, paused, "A → B", both, 0, let, model)]}
    if both:
        out["directions"].append(howto_direction(act, b_refs, a_refs, check, suffix, words, sides, groups, rules, iso, paused, "B → A", both, 1, let, model))
    if model:
        return out
    with howto_plan_lock:
        howto_plan_cache[key] = out
        # The latest picks plus every change still in progress (up to 100),
        # so the Changes list never pushes its own plans out.
        while len(howto_plan_cache) > 120:
            howto_plan_cache.pop(next(iter(howto_plan_cache)))
    return out


# ---- the Changes list ----
HOWTO_STEP_KEYS = ("msp", "app", "note", "picture", "untried", "keep", "undo")   # what a saved step keeps besides its title and watch


def howto_load():
    st = policy_read_json(HOWTO_FILE) or {}
    st["changes"] = [c for c in st.get("changes") or [] if c.get("status") != "done" or (c.get("done_at") or 0) >= time.time() - HOWTO_KEEP]
    return st


def howto_save(st):
    temporary = HOWTO_FILE + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(st, handle)
    os.replace(temporary, HOWTO_FILE)


def howto_rule_pid(watch):
    """The number of the rule a "rule" step made, once it is there."""
    norm = lambda t: str(t).strip().lower()
    names = {i for i, tl in msp["lists"].items() if norm(tl.get("name")) == norm(watch["list"])}
    on = howto_watch_on(watch)
    if on[1] is None:
        return None
    return next((str(r.get("pid")) for r in (state.get("policy_rules") or {}).get("rules") or []
                 if r.get("disabled") is not True and r.get("action") == watch["action"]
                 and (r.get("applies_on") or {}).get("kind") == on[0]
                 and on[1] in ("*", str((r.get("applies_on") or {}).get("id")).upper(), str((r.get("applies_on") or {}).get("id")))
                 and str((r.get("matching") or {}).get("id")) in names), None)


def howto_watch_on(watch):
    """A step's On as [kind, id]. A group that had no number when the step
    was written (a From Scratch client's new group) carries its members
    instead (on_members): it is the group that has exactly those members
    now, [kind, None] until it exists."""
    on = watch["on"]
    if not watch.get("on_members"):
        return on
    want = {str(m).upper() for m in watch["on_members"]}
    g = next((g for g in (state.get("groups") or {}).get("groups") or [] if {str(m).upper() for m in g.get("members") or []} == want), None)
    return [on[0], str(g.get("id")) if g else None]


def howto_done_facts(change):
    """What a change did, for "Done in Firewalla" and the history: each step
    in words (with the list lines and the rule number), and its Undo steps."""
    lines, pids = [], []
    for step in change.get("steps") or []:
        watch, text = step.get("watch") or {}, step.get("title") or ""
        if watch.get("kind") in ("list", "list_without"):
            text += ": " + ", ".join(watch.get("lines") or [])
        if watch.get("kind") == "rule" and (pid := howto_rule_pid(watch)):
            text += f" (rule #{pid})"
            pids.append(pid)
        lines.append(text)
    if change.get("verify"):
        lines.append(howto_verify_words(change["verify"]))
    return {"change": change.get("id"), "title": change.get("title"), "lines": lines, "pids": pids, "undo": change.get("undo") or [],
            "verify": change.get("verify")}


def howto_seen(watch):
    """Has the dashboard seen this step done? Never before the router's
    devices, groups and rules are read (router_ready): until then every step
    looks done (no rule = removed, no device = deleted, nothing blocks), and
    a change whose steps are all seen is marked done for good (25 Nov 2026)."""
    if not router_ready():
        return False
    kind = watch.get("kind")
    rules = (state.get("policy_rules") or {}).get("rules") or []
    lists = msp["lists"].values()
    norm = lambda t: str(t).strip().lower()
    if kind == "list":
        return any(norm(tl.get("name")) == norm(watch["name"]) and {norm(l) for l in watch["lines"]} <= {norm(t) for t in tl.get("targets") or []} for tl in lists)
    if kind == "list_without":
        return any(norm(tl.get("name")) == norm(watch["name"]) and not ({norm(l) for l in watch["lines"]} & {norm(t) for t in tl.get("targets") or []}) for tl in lists)
    if kind == "rule":
        return howto_rule_pid(watch) is not None
    if kind == "allowed":
        # (owner, ticked) per entry: a device's own page stores them the other way round.
        on = howto_watch_on(watch)
        if on[1] is None:
            return not watch.get("present", True)
        ends = [access_allowed_owner(r) for r in rules if r.get("purpose") == "ap_allow" and r.get("disabled") is not True]
        have = {(t.get("kind"), str(t.get("id")).upper()) for o, t in ends
                if [o.get("kind"), str(o.get("id")).upper()] == [on[0], str(on[1]).upper()]}
        found = all((k, str(i).upper()) in have for k, i in watch["others"])
        return found if watch.get("present", True) else not found
    if kind == "gone":
        return not any(str(r.get("pid")) == str(watch["pid"]) and r.get("disabled") is not True for r in rules)
    if kind == "reserved":
        return watch["ip"] in howto_reserved(watch["mac"])
    if kind == "rule_net":
        on = howto_watch_on(watch)
        return on[1] is not None and any(r.get("disabled") is not True and r.get("action") == watch["action"]
                   and (r.get("applies_on") or {}).get("kind") == on[0]
                   and str((r.get("applies_on") or {}).get("id")).upper() == str(on[1]).upper()
                   and (r.get("matching") or {}).get("kind") == "network" and str((r.get("matching") or {}).get("id")) == watch["network"]
                   for r in rules)
    if kind == "pair_group":
        want = {m.upper() for m in watch["members"]}
        g = next((g for g in (state.get("groups") or {}).get("groups") or [] if {str(m).upper() for m in g.get("members") or []} == want), None)
        if not g or not all(bool(g.get(k)) == watch[k] for k in ("vqlan", "isolation") if k in watch):
            return False
        # The steps that set the new group up are seen when the thing itself
        # is there (24 Nov 2026: each counted as seen as soon as the group
        # existed, so a change was "done" with none of the old group's rules,
        # ticks or switches made again). A step saved before then has none
        # of these and is seen with the group, as before.
        gid = str(g.get("id"))
        end = lambda r, side: ((r.get(side) or {}).get("kind"), str((r.get(side) or {}).get("id")).upper())
        live = [r for r in rules if r.get("disabled") is not True]
        if watch.get("keys"):      # the group's switches (Ad Block, Content Filtering…)
            got = (feature_settings.get("groups") or {}).get(gid) or {}
            return all(got.get(k) for k in watch["keys"])
        if watch.get("ticked"):    # an Allowed Devices entry between the group and what is ticked, either way round
            ticked = (watch["ticked"][0], str(watch["ticked"][1]).upper())
            return any(r.get("purpose") == "ap_allow" and {end(r, "applies_on"), end(r, "matching")} == {("group", gid.upper()), ticked} for r in live)
        if watch.get("rule"):      # the copied rule: same action, the group on the same side, the same other end
            w = watch["rule"]
            far = "matching" if w["side"] == "applies_on" else "applies_on"
            other = (w["other"][0], str(w["other"][1]).upper())
            return any(r.get("purpose") != "ap_allow" and r.get("action") == w["action"]
                       and end(r, w["side"]) == ("group", gid.upper()) and end(r, far) == other for r in live)
        return True
    if kind == "own_group_setting":   # Client Onboarding: a switch on for the group it is alone in
        mac = str(watch["mac"]).upper()
        own = next((g for g in (state.get("groups") or {}).get("groups") or [] if [str(m).upper() for m in g.get("members") or []] == [mac]), None)
        got = (feature_settings.get("groups") or {}).get(str((own or {}).get("id"))) or {}
        return bool(own) and all(got.get(k) for k in watch.get("keys") or [])
    if kind == "own_group_no_internet":   # Client Onboarding, From Scratch: a Block Internet rule on the group it is alone in
        mac = str(watch["mac"]).upper()
        own = next((g for g in (state.get("groups") or {}).get("groups") or [] if [str(m).upper() for m in g.get("members") or []] == [mac]), None)
        return bool(own) and any(
            r.get("disabled") is not True and r.get("action") == "block" and (r.get("applies_on") or {}).get("kind") == "group"
            and str((r.get("applies_on") or {}).get("id")) == str(own.get("id"))
            and (r.get("type") in ("mac", "internet") or (r.get("matching") or {}).get("kind") in ("device_control", "internet")) for r in rules)
    if kind == "dap_on":   # Client Onboarding: Device Active Protect turned back on for it (Learning onwards)
        return str((access_device_protect.get(str(watch["mac"]).upper()) or {}).get("state") or "").lower() in ("learning", "optimizing", "active", "ready")
    if kind == "device_setting":   # Client Onboarding: a switch turned on for the client itself
        d = (feature_settings.get("devices") or {}).get(str(watch["mac"]).upper()) or {}
        return bool(d.get(watch["key"])) or watch["key"] in (d.get("on") or [])
    if kind == "unreserved":   # Client Offboarding: its reservation deleted
        return watch["ip"] not in howto_reserved(watch["mac"])
    if kind == "device_gone":   # Client Offboarding: deleted in Firewalla
        return not any(str(d.get("mac") or "").upper() == str(watch["mac"]).upper() for d in state.get("devices") or [])
    if kind == "no_forward":   # Client Offboarding: no port forward to it
        return not any(m.get("to_mac") == str(watch["mac"]).upper() or (watch.get("ip") and m.get("to_ip") == watch["ip"])
                       for m in (feature_settings.get("box") or {}).get("port_forward_maps") or [])
    if kind == "not_in_group":   # Client Onboarding: out of Quarantine (mirroring an ungrouped client)
        return not any(str(g.get("id")) == str(watch["group"]) and str(watch["mac"]).upper() in {str(m).upper() for m in g.get("members") or []}
                       for g in (state.get("groups") or {}).get("groups") or [])
    if kind == "rule_device":   # Client Onboarding: a client's own rule, copied from the client it mirrors
        other = watch.get("other") or [None, None]
        far = "matching" if watch["side"] == "applies_on" else "applies_on"
        return any(r.get("disabled") is not True and r.get("action") == watch["action"]
                   and (r.get(watch["side"]) or {}).get("kind") == "device" and str((r.get(watch["side"]) or {}).get("id") or "").upper() == str(watch["mac"]).upper()
                   and (r.get(far) or {}).get("kind") == other[0] and str((r.get(far) or {}).get("id")) == str(other[1]) for r in rules)
    if kind == "named":   # Client Onboarding: renamed in Firewalla
        d = next((d for d in state.get("devices") or [] if str(d.get("mac") or "").upper() == str(watch["mac"]).upper()), None)
        return bool(d) and str(d.get("name") or "").strip().lower() == str(watch["name"]).strip().lower()
    if kind == "in_group":   # Client Onboarding: in its group (and so out of Quarantine)
        return any(str(g.get("id")) == str(watch["group"]) and str(watch["mac"]).upper() in {str(m).upper() for m in g.get("members") or []}
                   for g in (state.get("groups") or {}).get("groups") or [])
    if kind == "isolated":
        return str(watch["mac"]).upper() in access_isolated()
    if kind == "not_isolated":
        return str(watch["mac"]).upper() not in access_isolated()
    if kind == "unpaused":
        side = access_sides()[0].get(watch["mac"])
        return bool(side) and access_paused(side) is None
    return False


def howto_mark_done():
    """Every change with each step's seen state and the result re-checked;
    a change whose steps are all seen and whose result holds is done, kept
    with what it did (howto_done_facts). Run every minute by the Policy
    worker and whenever Show Me How is open. The plans are worked out
    outside the lock (a big one takes seconds), so I'm Doing This and other
    tabs never wait for them; only marking a change done takes the lock, on
    the file as it is then. Returns the changes as shown."""
    with howto_lock:
        st = howto_load()
    out, done_now, verified = [], {}, {}
    for c in st["changes"]:
        steps = [{**{k: s.get(k) for k in HOWTO_STEP_KEYS if s.get(k) is not None}, "title": s["title"], "seen": howto_seen(s["watch"])}
                 for s in c.get("steps") or []]
        # Before-and-after check (part 4): once every step is seen, every
        # recorded pair again, then every 10 minutes while it is in progress.
        if c.get("status") != "done" and c.get("expect") and steps and all(s["seen"] for s in steps) \
                and time.time() - ((c.get("verify") or {}).get("at") or 0) > 600:
            c["verify"] = verified[c.get("id")] = howto_verify(c["expect"])
        result = None
        if c.get("status") != "done" and (c.get("request") or {}).get("kind") in ("onboard", "offboard"):
            # Client Onboarding / Offboarding: done when every step is seen.
            result = bool(steps) and all(s_["seen"] for s_ in steps)
        elif c.get("status") != "done":
            plan = howto_plan(c["request"]["act"], c["request"]["a"], c["request"]["b"], c["request"].get("proto"), c["request"].get("port"),
                              c["request"].get("both"), c["request"].get("let"))
            result = all(d["done"] for d in plan["directions"]) if plan else False
            if steps and all(s["seen"] for s in steps) and result:
                c.update(status="done", done_at=time.time(), done=howto_done_facts(c))
                done_now[c.get("id")] = c
        out.append({**{k: c.get(k) for k in ("id", "title", "source", "started", "status", "done_at", "request", "undo", "item", "verify", "fixes", "back")},
                    "steps": steps, "result": result if c.get("status") != "done" else True,
                    "verify_words": howto_verify_words(c.get("verify"))})
    if done_now or verified:
        with howto_lock:
            st = howto_load()
            for c in st["changes"]:
                if c.get("id") in verified:
                    c["verify"] = verified[c["id"]]
                if c.get("id") in done_now and c.get("status") != "done":
                    c.update({k: done_now[c["id"]][k] for k in ("status", "done_at", "done")})
                    c.pop("expect", None)   # its check is kept in "done"; the pairs list isn't needed again
            howto_save(st)
    return out


def howto_traffic(plan, check):
    """Traffic Seen for each Today row (owner, 22 Nov 2026: the Access Test
    folded into Show Me How): of its pairs, how many the router's recorded
    traffic in 24 hours (on the ports asked for) agrees with, how many had
    none, and how many disagree (connections got through that the rules
    block, or only blocks where the rules allow). Worked out on each ask:
    the plan itself is kept, the traffic changes. A copy without the pair
    lists is returned."""
    if not plan or plan.get("error"):
        return plan
    pairs = {p for d in plan["directions"] for t in d["today"] for p in t.get("_pairs") or []}
    seen = access_test_seen(list(pairs), check) if pairs else {}
    directions = []
    for d in plan["directions"]:
        today = []
        for t in d["today"]:
            agree = none = disagree = allowed = blocked = 0
            for p in t.get("_pairs") or []:
                n = seen.get(p) or {"allowed": 0, "blocked": 0}
                # Traffic in 24 h (owner, 22 Nov 2026): connections allowed and
                # blocked; the router's summary record counts as blocked.
                allowed += 0 if n.get("summary") else n["allowed"]
                blocked += n["blocked"] + (n["allowed"] if n.get("summary") else 0)
                if not n["allowed"] and not n["blocked"]:
                    none += 1
                elif (n["allowed"] and not n.get("summary") if t["verdict"] == "blocked" else not n["allowed"]):
                    disagree += 1
                else:
                    agree += 1
            today.append({**{k: v for k, v in t.items() if k != "_pairs"},
                          "seen": {"agree": agree, "none": none, "disagree": disagree, "allowed": allowed, "blocked": blocked}})
        directions.append({**d, "today": today})
    return {**plan, "directions": directions}


@app.get("/api/howto-page")
def api_howto_page(act: str = None, a: str = None, b: str = None, proto: str = None, port: str = None, both: str = None, let: str = None):
    """The pickers' lists, your changes in progress, and (with a and b) the plan."""
    try:
        plan = howto_plan(act, a, b, proto, port, both in ("1", "true", "on"), (let or "")[:60000]) if a and b else None
        plan = howto_traffic(plan, howto_port(proto, port)[0])
    except Exception as exc:
        plan = {"error": public_error("Show Me How", exc)}
    # Finished changes leave the list (15 Nov 2026): one from a Policy card
    # is on that card's Details (Settings › Change History was removed, D-1021).
    changes = [c for c in howto_mark_done() if c["status"] != "done"]
    # Keep Needs made from What Else This Changes (pair, the change they're
    # kept from), so a kept pair shows its Need instead of a button.
    from connections import details_load, details_lock
    with details_lock:
        keep = [{"id": n["id"], "a": n["src"][2:].upper(), "b": n["dst"][2:].upper(), "for": n.get("for_request")}
                for n in details_load()["needs"] if n.get("kind") == "keep"]
    return {"catalog": howto_catalog(), "plan": plan, "changes": changes, "keep_needs": keep, "updated_at": time.time()}


@app.post("/api/howto/start")
def api_howto_start(payload: dict = Body(default={})):
    """I'm Doing This: {act, a, b, proto, port, both, fixes: [fix id per
    direction], title, source}. The plan is worked out again here; its
    steps are what the Changes list watches."""
    # Kept as plain text of bounded size (the plan reads them the same way).
    fields = Fields(payload)
    text = lambda k, n: fields.text(k, n, strip=False)
    req = {"act": "block" if payload.get("act") == "block" else "allow", "a": text("a", 30000), "b": text("b", 30000),
           "proto": text("proto", 10), "port": text("port", 40), "both": bool(payload.get("both")), "let": text("let", 60000)}
    plan = howto_plan(req["act"], req["a"], req["b"], req["proto"], req["port"], req["both"], req["let"], model=True)
    if not plan:
        return {"ok": False, "error": "Pick A and B first."}
    chosen = payload.get("fixes") if isinstance(payload.get("fixes"), list) else []
    steps, undo, picked, expect = [], [], [], []
    for i, d in enumerate(plan["directions"]):
        # The way you ticked, as the plan has it now: one that does what you
        # asked for every pair and keeps what you ticked (the ways the page
        # offers, D-923). Before 24 Nov 2026 a way no longer in the plan was
        # quietly swapped for the plan's first way, working or not.
        want = chosen[i] if i < len(chosen) else None
        fix = None if d["done"] else next((f for f in d["fixes"] if f["id"] == want and f.get("offer") and f["result"]["ok"] == f["result"]["of"]), None)
        if not d["done"] and not fix:
            return {"ok": False, "error": "The way you ticked isn't offered any more: your rules, or what you ticked to keep, have changed since. "
                                          "Look at the ways again and tick one." if want else "Tick one of the ways under How To Make It True first."}
        picked.append((fix or {}).get("id"))
        expect += (fix or {}).get("expect") or []
        for s in (fix or {}).get("steps") or []:
            # The whole step, saved (owner, 23 Nov 2026): the plan is worked out
            # again from the network as it is, so once the first steps are done
            # the way picked can drop out of it; Changes shows these instead.
            steps.append({**{k: s.get(k) for k in HOWTO_STEP_KEYS if s.get(k) is not None},
                          "title": f"{d['label']}: {s['title']}" if plan["both"] else s["title"], "watch": s["watch"]})
            undo.insert(0, s.get("undo"))
    if not steps:
        return {"ok": False, "error": "Nothing to change for that pick."}
    change = {"id": os.urandom(6).hex(), "title": fields.text("title", 160, strip=False) or "A change", "source": fields.text("source", 80, strip=False),
              "started": time.time(), "status": "in_progress", "request": req, "steps": steps, "undo": [u for u in undo if u],
              # The Policy card it was started from ("c|<key>" or "v|<key>|<kind>").
              "item": fields.text("item", 200, strip=False) or None,
              # The way picked per direction and where Show Me How was opened
              # from: its link in Changes reopens it as you left it (18 Nov 2026).
              "fixes": picked, "back": fields.text("back", 300, strip=False) or None,
              # Every pair the way touches and what it should be afterwards (part 4).
              "expect": expect}
    with howto_lock:
        st = howto_load()
        st["changes"] = [change] + st["changes"][:99]
        howto_save(st)
    return {"ok": True, "id": change["id"]}


@app.post("/api/howto/remove")
def api_howto_remove(payload: dict = Body(default={})):
    with howto_lock:
        st = howto_load()
        st["changes"] = [c for c in st["changes"] if c.get("id") != payload.get("id")]
        howto_save(st)
    return {"ok": True}


# ============================================================
# CHANGE HISTORY (15 Nov 2026): the owner forgets what was changed and
# when, so the dashboard keeps it: Policy decisions (yours and settled by
# default), Show Me How changes, and rules and lists changed directly in
# Firewalla (seen by comparing MSP reads). Shown in device popups ("Recent
# Changes"), on the Access Test ("made <date> from your Policy decision"),
# (Settings › Change History, which listed Show Me How changes without a Policy card, was removed: D-1021)
# and given to Claude with every question.
# ============================================================
CHANGE_DAYS = 30
FIREWALLA_CHANGES_FILE = os.environ.get("FIREWALLA_CHANGES_FILE", "/data/firewalla_changes.json")
firewalla_changes_lock = threading.Lock()


def msp_changes_load():
    """Rules and target lists changed in Firewalla: [{at, text, macs, groups}]."""
    return (policy_read_json(FIREWALLA_CHANGES_FILE) or {}).get("events") or []


def msp_snapshot():
    """What the change log compares: each rule's meaning (not its hit counts
    or times) and each target list's lines."""
    rules = {str(r["pid"]): {"text": access_rule_text(r), **{k: r.get(k) for k in (
                "action", "type", "target", "applies_on", "matching", "direction", "disabled", "purpose")}}
             for r in (state.get("policy_rules") or {}).get("rules") or [] if r.get("pid") is not None}
    lists = {str(i): {"name": tl.get("name"), "targets": sorted({str(t).strip() for t in tl.get("targets") or []
                                                                  if str(t).strip() and not str(t).startswith("#")})}
             for i, tl in msp["lists"].items()}
    return rules, lists


def msp_changes_check(now=None):
    """Rules and target lists changed directly in Firewalla (or by anyone),
    found by comparing what is read now with the last read: rules added,
    removed, paused, resumed or changed; lists made, deleted, lines added or
    removed. Each event names the devices and groups it touches. A read that
    came back empty is skipped (a failed read, not everything deleted). Kept
    30 days. Run every minute by the Policy worker."""
    now = now or time.time()
    rules, lists = msp_snapshot()
    with firewalla_changes_lock:
        st = policy_read_json(FIREWALLA_CHANGES_FILE) or {}
        old_rules, old_lists = st.get("rules"), st.get("lists")
        events = [e for e in st.get("events") or [] if now - e["at"] < CHANGE_DAYS * 86400]
        if not rules:
            return
        sides, _ = access_sides()
        by_ip = {ip: s_["mac"] for s_ in sides.values() for ip in s_.get("ips") or []}
        new = []

        def touched(*parts):
            macs, gids = set(), set()
            for part in parts:
                if (part or {}).get("kind") == "device":
                    macs.add(str(part.get("id")).upper())
                elif (part or {}).get("kind") == "group":
                    gids.add("g" + str(part.get("id")))
            return sorted(macs), sorted(gids)

        if old_rules is not None:
            for pid, r in rules.items():
                was = old_rules.get(pid)
                if was == r:
                    continue
                if not was:
                    text = f"rule #{pid} added: {r['text']}"
                elif bool(was.get("disabled")) != bool(r.get("disabled")):
                    text = f"rule #{pid} {'paused' if r.get('disabled') else 'resumed'}: {r['text']}"
                else:
                    text = f"rule #{pid} changed: {was['text']} → {r['text']}" if was["text"] != r["text"] else f"rule #{pid} changed: {r['text']}"
                macs, gids = touched(r.get("applies_on"), r.get("matching"), (was or {}).get("applies_on"), (was or {}).get("matching"))
                new.append({"at": now, "text": text, "macs": macs, "groups": gids})
            for pid, was in old_rules.items():
                if pid not in rules:
                    macs, gids = touched(was.get("applies_on"), was.get("matching"))
                    new.append({"at": now, "text": f"rule #{pid} removed: {was['text']}", "macs": macs, "groups": gids})
        # Before the first MSP read the lists are unknown (not empty): they are
        # neither compared nor saved, else every list would later show as made.
        lists_known = bool(msp["at"])
        if lists_known and old_lists is not None and (lists or not old_lists):
            used_by = {}
            for r in rules.values():
                for side in ("matching", "target"):
                    ref = r.get(side) if isinstance(r.get(side), dict) else None
                    if ref and ref.get("kind") == "target_list":
                        used_by.setdefault(str(ref.get("id")), []).append(r.get("applies_on"))
            for lid in set(lists) | set(old_lists):
                now_l, was_l = lists.get(lid), old_lists.get(lid)
                if now_l == was_l:
                    continue
                name = (now_l or was_l)["name"]
                added = sorted(set((now_l or {}).get("targets") or []) - set((was_l or {}).get("targets") or []))
                gone = sorted(set((was_l or {}).get("targets") or []) - set((now_l or {}).get("targets") or []))
                show = lambda lines: ", ".join(lines[:5]) + (f" and {len(lines) - 5} more" if len(lines) > 5 else "")
                text = (f'target list "{name}" made' + (f": {show(added)}" if added else "") if not was_l
                        else f'target list "{name}" deleted' if not now_l
                        else "; ".join(x for x in (f'target list "{name}": added {show(added)}' if added else "",
                                                     f'target list "{name}": removed {show(gone)}' if gone else "",
                                                     f'target list renamed "{was_l["name"]}" → "{name}"' if was_l["name"] != name else "") if x))
                macs, gids = touched(*used_by.get(lid, []))
                macs = sorted(set(macs) | {by_ip[t.partition(",")[0].partition(":")[0]] for t in added + gone
                                           if t.partition(",")[0].partition(":")[0] in by_ip})
                new.append({"at": now, "text": text, "macs": macs, "groups": gids})
        keep_lists = (lists if (lists or not old_lists) else old_lists) if lists_known else old_lists
        if new or old_rules is None or rules != old_rules or keep_lists != old_lists:
            temporary = FIREWALLA_CHANGES_FILE + ".tmp"
            with open(temporary, "w", encoding="utf-8") as handle:
                json.dump({"rules": rules, "lists": keep_lists, "events": events + new}, handle)
            os.replace(temporary, FIREWALLA_CHANGES_FILE)


def change_made_by(pid):
    """A rule a finished Show Me How change made: {at, item, title}."""
    with howto_lock:
        changes = howto_load()["changes"]
    c = next((c for c in sorted(changes, key=lambda c: -(c.get("done_at") or 0))
              if c.get("status") == "done" and str(pid) in ((c.get("done") or {}).get("pids") or [])), None)
    return {"at": c.get("done_at"), "item": c.get("item"), "title": c.get("title")} if c else None


def recent_changes(macs=(), group_ids=(), days=CHANGE_DAYS, now=None):
    """Changes in the last <days> touching these devices (MACs) or groups
    ("g<id>"), newest first: [{at, kind, text}]. A device also counts its
    groups; a decision or change on a group counts for its members."""
    from policy import policy_lock, policy_state_load
    now = now or time.time()
    since = now - days * 86400
    sides, groups = access_sides()
    macs = {str(m).upper() for m in macs}
    gids = {str(g) for g in group_ids} | {"g" + str(g) for m in macs for g in (sides.get(m) or {}).get("groups") or []}
    touches = lambda ms, gs: bool(macs & set(ms)) or bool(gids & set(gs))
    when = lambda t: datetime.fromtimestamp(t).strftime("%d %b %H:%M")
    out = []
    with policy_lock:
        st = policy_state_load()
    for key, d in st["decisions"].items():
        if (d.get("at") or 0) < since or key.count("|") != 2:
            continue
        src, dst, _ = key.split("|")
        if not touches([src, dst], []):
            continue
        how = {"default": "settled by default as", "changed": "you chose", "false_alarm": "False Alarm by you, as"}.get(d.get("kind"), "you chose")
        state_ = {"review": " · in Review", "rule_change": " · waiting for a rule change"}.get(d.get("status"), "")
        done = f" · done in Firewalla {when(d['done']['at'])}" if (d.get("done") or {}).get("at") else ""
        out.append({"at": d["at"], "kind": "policy",
                    "text": f"Policy: {how} {'Allow' if d.get('intent') == 'allow' else 'Block'} {d.get('label') or key}{state_}{done}"})
    with howto_lock:
        changes = howto_load()["changes"]
    for c in changes:
        at = c.get("done_at") or c.get("started") or 0
        if at < since:
            continue
        refs = [r for side in ("a", "b") for r in str((c.get("request") or {}).get(side) or "").split(",") if r]
        ms = [r[2:].upper() for r in refs if r.startswith("d:")]
        gs = ["g" + r[2:] for r in refs if r.startswith("g:")]
        if not touches(ms, gs):
            continue
        out.append({"at": at, "kind": "howto", "text": f"Show Me How: {c.get('title')}"
                    + (f" · done in Firewalla {when(c['done_at'])}" if c.get("status") == "done" else f" · started {when(c.get('started') or at)}, in progress")})
    for e in msp_changes_load():
        if e["at"] >= since and touches(e.get("macs") or [], e.get("groups") or []):
            out.append({"at": e["at"], "kind": "firewalla", "text": f"In Firewalla: {e['text']}"})
    return sorted(out, key=lambda e: -e["at"])
