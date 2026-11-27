# CLIENT ONBOARDING (owner, 23 Nov 2026, D-932, D-933, D-934). Every new
# client starts in Firewalla's Quarantine group (New Device Quarantine: fenced
# off from the internet and your other clients). This page sets one up step by
# step, the way Show Me How does (steps that stand on their own, I'm Doing
# This with saved steps, Print Steps, the before-and-after check). It makes no
# assumptions about what the client should reach (owner, 23 Nov 2026): you
# pick the client, press Onboard, and say how it gets its access:
#   mirror  the same access as another client: it joins that client's group
#           (or, for an ungrouped one, just leaves Quarantine), goes into the
#           same target lists and gets the same Allowed Devices entries and
#           client rules;
#   scratch you say which groups and ungrouped clients it should reach, and
#           which should reach it. It goes into a new group of its own with
#           VqLAN on (so nothing else reaches it or is reached), and Show Me
#           How's engine works out the steps for each choice, tried against
#           your rules.
# Then What It Will Reach shows the result from your rules, and flags
# anything it would reach (or be reached by) that you didn't ask for.
# Client Offboarding (removing a client) is in this file too, further down.

import ipaddress
import json
import os
import re
import threading
import time

from fastapi import Body

from core import Fields, INTERFACE_METADATA, app, msp, policy_read_json, state
from router import access_device_protect, feature_settings, internet_interface_name
from access import (
    HOWTO_GROUP_SWITCHES, HOWTO_STEP_KEYS, HOWTO_UNTRIED_INTERNET, access_allowed_owner, access_is_gear, access_isolated, access_local_rules, access_paused, access_rule_text,
    access_list_entries, access_local_rows, access_sides, access_target_list_side, check_local_access, howto_addresses, howto_app, howto_direction, howto_expect, howto_fit,
    howto_group_number, howto_short_name,
    howto_port,
    howto_id, howto_left_behind, howto_load, howto_lock, howto_mark_done, howto_matching, howto_reserve_step, howto_reserved, howto_save, howto_trial,
)
from listcheck import api_quarantine_settings, list_check_lines

QUARANTINE = "1"   # Firewalla's Quarantine group id
# Rule purposes Firewalla makes and keeps itself: never copied by hand.
OB_FIREWALLA_PURPOSES = {"dap", "region_blocking", "advanced_threat_filtering", "family", "firewall"}
OB_NEW = "new-ob"  # the new group a from-scratch client goes into, until Firewalla gives it an id
# Start From Scratch asks, and assumes nothing (owner, D-1060 / D-1064 / D-1069):
# the internet Yes or No, then for each target ticked what the access is for
# and its ports: typed, or Learning Mode (every port to that one target, to be
# narrowed once the traffic has been watched).
OB_PURPOSES = [["print", "Printing"], ["files", "File Sharing"], ["stream", "Streaming / Casting"], ["remote", "Remote Desktop"],
               ["smart", "Smart Home Control"], ["cameras", "Cameras"], ["backup", "Backup"], ["media", "Media Server"], ["gaming", "Gaming"],
               ["other", "Other"]]
OB_PORTS = r"\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*"   # "445", "80,443", "8000-8100"
OB_LEARNING_FILE = os.environ.get("FIREWALLA_OB_LEARNING_FILE", "/data/onboarding_learning.json")
ob_learning_lock = threading.Lock()


def ob_how(text):
    """The page's answers about each ticked target:
    "<to|frm>~<ref>~<purpose>~<ports|learn>~<tcp|udp>~<ports>~<other purpose>",
    ";" between targets -> {(side, ref): {...}}."""
    out = {}
    for part in str(text or "").split(";")[:80]:
        f = (part.split("~") + [""] * 7)[:7]
        if f[0] in ("to", "frm") and f[1]:
            out[(f[0], f[1])] = {"purpose": f[2] if f[2] in dict(OB_PURPOSES) else "", "mode": f[3] if f[3] in ("ports", "learn", "copy") else "",
                                 "proto": f[4] if f[4] in ("tcp", "udp") else "tcp", "ports": re.sub(r"\s+", "", f[5])[:120],
                                 "other": f[6].strip()[:40]}
    return out


def ob_pick(side, ref, label, d):
    """One ticked target with its answers; missing = what is still to say."""
    why = (d.get("other") if d.get("purpose") == "other" else dict(OB_PURPOSES).get(d.get("purpose") or "")) or ""
    ports = d.get("ports") or ""
    ports_ok = bool(re.fullmatch(OB_PORTS, ports)) and all(1 <= int(n) <= 65535 for n in re.findall(r"\d+", ports))
    missing = ("what the access is for" if not why else "its ports, or Learning Mode" if not d.get("mode")
               else "which ports to copy (press Use These on one line), or type them, or Learning Mode" if d["mode"] == "copy"
               else "the port numbers (like 445, or 80,443, or 8000-8100)" if d["mode"] == "ports" and not ports_ok else "")
    return {"side": side, "ref": ref, "name": label, "purpose": d.get("purpose") or "", "other": d.get("other") or "", "why": why,
            "mode": d.get("mode") or "", "proto": d.get("proto") or "tcp", "ports": ports, "missing": missing, "ok": not missing}


OB_OTHERS_DAYS = 7     # how far back Use What Others Use looks at recorded traffic
OB_OTHERS_PORTS = 6    # most ports named from one source's traffic


def ob_others(ref, mine, sides, groups):
    """Use What Others Use (D-1069): who already reaches this target, on which
    ports: from your rules (target lists that hold one of its addresses,
    Allowed Devices entries naming it) and from the last 7 days of recorded
    traffic to it. -> [{who, source "rule" | "allowed" | "traffic", protocol,
    ports, words, note, usable}]; usable = it names ports of one protocol,
    which Use These can copy."""
    members = [m for m in ((groups.get(ref[2:]) or {}).get("members") or [] if ref.startswith("g:") else [ref[2:]]) if m in sides]
    own = lambda mac: (groups.get(sides[mac]["groups"][0]) or {}).get("name") if sides[mac]["groups"] else sides[mac]["name"]
    span = lambda ports: ",".join(str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in ports)
    out, have = [], set()

    def add(who, source, protocol, ports, note):
        key = (who, protocol, ports)
        if who and key not in have:
            have.add(key)
            out.append({"who": who, "source": source, "protocol": protocol or "", "ports": ports,
                        "words": f"{protocol.upper() if protocol else 'TCP and UDP'} {ports.replace(',', ', ')}" if ports else "every port",
                        "note": note, "usable": bool(ports) and protocol in ("tcp", "udp")})

    for r in access_local_rules():
        if r.get("action") != "allow":
            continue
        listed = access_target_list_side(r)
        if listed:
            far = r.get("applies_on" if listed == "matching" else "matching") or {}
            for e in access_list_entries(r) or []:
                if e["net"] is not None and any(ob_in_net(ip, e["net"]) for m in members for ip in sides[m].get("ips") or []):
                    add(far.get("name"), "rule", e["protocol"], span(e["ports"]) if e["ports"] else "", f"its rule \"{access_rule_text(r)}\"")
        elif r.get("purpose") == "ap_allow":
            owner, ticked = access_allowed_owner(r)
            ends = {(o.get("kind"), str(o.get("id"))): o for o in (owner, ticked)}
            mine_end = next((k for k in ends if (k[0] == "group" and ref == f"g:{k[1]}") or (k[0] == "device" and k[1].upper() in members)), None)
            if mine_end:
                other = next(o for k, o in ends.items() if k != mine_end) if len(ends) == 2 else None
                if other:
                    add(other.get("name"), "allowed", None, "", "an Allowed Devices entry")
    seen = {}
    for m in members:
        for src, dst, outcome, protocol, port, n, *_ in access_local_rows(OB_OTHERS_DAYS * 24, m):
            if outcome == "allowed" and protocol and dst == m and src in sides and src != mine:
                ports = seen.setdefault((own(src), str(protocol).lower()), {})
                ports[int(port)] = ports.get(int(port), 0) + (n or 0)
    for (who, protocol), ports in sorted(seen.items(), key=lambda t: -sum(t[1].values())):
        top = sorted(sorted(ports, key=lambda p: -ports[p])[:OB_OTHERS_PORTS])
        add(who, "traffic", protocol, ",".join(str(p) for p in top),
            f"seen in the last {OB_OTHERS_DAYS} days ({sum(ports.values()):,} connections" + (f", its {OB_OTHERS_PORTS} busiest ports of {len(ports)}" if len(ports) > OB_OTHERS_PORTS else "") + ")")
    return out[:30]


def ob_in_net(ip, net):
    try:
        return ipaddress.ip_address(ip) in net
    except ValueError:
        return False


def ob_learning_load():
    return (policy_read_json(OB_LEARNING_FILE) or {}).get("items") or []


def ob_learning_save(items):
    temporary = OB_LEARNING_FILE + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump({"items": items}, handle)
    os.replace(temporary, OB_LEARNING_FILE)


OB_LEARNING_DAYS = 7      # after this long the ports seen are offered to narrow to
OB_LEARNING_PORTS = 20    # most ports of one protocol put on one list line


def ob_learning_view(sides, groups):
    """The Learning Mode section (D-1069): each target opened on every port,
    with the ports the recorder has really seen since (allowed connections,
    in the direction asked), and from day 7 the steps to narrow its list to
    them: the list's lines again, each with its ports. A line nothing used
    is left out. It never closes by itself: Done Learning takes it off."""
    now, out = time.time(), []
    norm = lambda t: str(t or "").strip().lower()
    by_ip = {ip: m for m, s in sides.items() for ip in s.get("ips") or []}
    for i in ob_learning_load():
        mine, to = i["mac"], i["side"] == "to"
        members = set((groups.get(i["ref"][2:]) or {}).get("members") or []) if i["ref"].startswith("g:") else {i["ref"][2:]}
        hours = min(int((now - i["started"]) // 3600) + 1, 60 * 24)
        seen = {}   # the client the traffic went to -> protocol -> port -> connections
        for src, dst, outcome, protocol, port, n, _records, _size, last, *_ in access_local_rows(hours, mine):
            if outcome == "allowed" and protocol and (last or 0) >= i["started"] and (src == mine and dst in members if to else dst == mine and src in members):
                ports = seen.setdefault(dst, {}).setdefault(str(protocol).lower(), {})
                ports[int(port)] = ports.get(int(port), 0) + (n or 0)
        total = {}
        for per in seen.values():
            for proto, ports in per.items():
                for port, n in ports.items():
                    total[(proto, port)] = total.get((proto, port), 0) + n
        tl = next((t for t in msp["lists"].values() if norm(t.get("name")) == norm(i.get("list"))), None) if i.get("list") else None
        lines, dropped = [], []
        for line in (tl or {}).get("targets") or []:
            address, _, ports = str(line).partition(",")
            if ports:
                lines.append(str(line))   # already narrowed: kept as it is
                continue
            per = seen.get(by_ip.get(address.strip())) or {}
            new = [f"{address.strip()},{proto}:{','.join(str(p) for p in sorted(sorted(ports, key=lambda p: -ports[p])[:OB_LEARNING_PORTS]))}"
                   for proto, ports in sorted(per.items())]
            lines += new
            if not new:
                dropped.append(sides[by_ip[address.strip()]]["name"] if address.strip() in by_ip else address.strip())
        days = int((now - i["started"]) // 86400)
        narrowed = bool(tl) and all("," in str(line) for line in tl.get("targets") or [])
        ready = days >= OB_LEARNING_DAYS and not narrowed
        steps = ([f"On the MSP website open Target Lists, then \"{tl['name']}\", then Edit",
                  "Replace its lines with the lines below (each address now carries the ports that were used)",
                  "Press Save & Apply. The rule stays as it is: from then on only these ports are open",
                  "Come back here and press Done Learning"] if ready and tl and lines else [])
        out.append({**i, "days": days, "needed": OB_LEARNING_DAYS, "ready": ready, "narrowed": narrowed, "list_found": bool(tl),
                    "seen": [{"protocol": proto.upper(), "port": port, "connections": n}
                             for (proto, port), n in sorted(total.items(), key=lambda t: -t[1])[:30]],
                    "steps": steps, "lines": lines if steps else [], "dropped": dropped if steps else []})
    return out


@app.post("/api/onboarding/learning-done")
def api_onboarding_learning_done(payload: dict = Body(default={})):
    """Done Learning: the target leaves the Learning Mode section (nothing in
    Firewalla changes)."""
    lid = Fields(payload).text("id", 20)
    with ob_learning_lock:
        items = ob_learning_load()
        if not any(i["id"] == lid for i in items):
            return {"ok": False, "error": "It is no longer listed."}
        ob_learning_save([i for i in items if i["id"] != lid])
    return {"ok": True}


def ob_private(mac):
    """A made-up ("private", "randomised") Wi-Fi address: its first byte has
    the locally-administered bit (x2, x6, xA, xE)."""
    try:
        return bool(int(str(mac)[:2], 16) & 2)
    except ValueError:
        return False


def ob_quarantine_check():
    """Is Quarantine the safe starting point it should be (D-932)? ->
    {"ok", "notes": [problems]}."""
    q = api_quarantine_settings()
    notes = []
    box = (q.get("box") or {}).get("newDeviceTag") or {}
    if not box.get("state"):
        notes.append("New Device Quarantine is off for the box: new clients don't start in Quarantine. Turn it on in the Firewalla app (main page › + › New Device Quarantine).")
    for name, setting in (q.get("networks") or {}).items():
        tag = (setting or {}).get("newDeviceTag")
        if isinstance(tag, dict) and tag.get("state") is False:
            notes.append(f"New Device Quarantine is off on {name}: new clients there skip Quarantine.")
    g = q.get("group") or {}
    texts = " ".join(str(r.get("matching") or "") for r in g.get("rules") or [] if r.get("action") == "block" and not r.get("disabled"))
    if "Local Networks" not in texts:
        notes.append("The Quarantine group has no rule blocking Local Networks: quarantined clients may reach your other clients.")
    if "All traffic" not in texts and "Internet" not in texts:
        notes.append("The Quarantine group has no rule blocking the internet.")
    if not g.get("vqlan") or not g.get("isolation"):
        notes.append("Turn on VqLAN and Device Isolation for the Quarantine group, so quarantined clients can't reach each other on one network.")
    return {"ok": not notes, "notes": notes, "members": g.get("members") or []}


def ob_group_gives(gid, groups, sides):
    """What a group gives its clients, in words: its switches, settings,
    Allowed Devices and rules (local and internet)."""
    g = groups.get(gid) or {}
    local = {str(r.get("pid")) for r in access_local_rules()}
    rules = [r for r in (state.get("policy_rules") or {}).get("rules") or [] if r.get("disabled") is not True and r.get("purpose") != "ap_allow"
             and any((r.get(s) or {}).get("kind") == "group" and str((r.get(s) or {}).get("id")) == str(gid) for s in ("applies_on", "matching"))]
    names = HOWTO_GROUP_SWITCHES
    settings = (feature_settings.get("groups") or {}).get(str(gid)) or {}
    word = lambda r: f"{'Allows' if r.get('action') == 'allow' else 'Blocks'} {access_rule_text(r)}"
    return {
        "members": [sides[m]["name"] for m in g.get("members") or [] if m in sides],
        "fence": ("VqLAN on (kept apart from other groups)" if g.get("vqlan") else "VqLAN off")
                 + (", Device Isolation on (kept apart from each other)" if g.get("isolation") else ", Device Isolation off (the group's clients reach each other)"),
        "settings": [names[k] for k in names if settings.get(k)],
        "allowed": [a.get("name") or a.get("id") for a in g.get("allowed") or []],
        "local": [word(r) for r in rules if str(r.get("pid")) in local],
        "internet": [word(r) for r in rules if str(r.get("pid")) not in local],
    }


def ob_choices(x, sides, groups):
    """What a from-scratch client can be given access to and from: your
    groups (not Quarantine, not empty) and clients in no group (not Firewalla
    equipment, not itself). [{ref, name, kind, count}]"""
    out = [{"ref": f"g:{gid}", "name": g.get("name") or gid, "kind": "group", "count": len([m for m in g.get("members") or [] if m in sides])}
           for gid, g in groups.items() if gid != QUARANTINE and any(m in sides for m in g.get("members") or [])]
    out += [{"ref": f"d:{m}", "name": s["name"], "kind": "client", "count": 1}
            for m, s in sides.items() if not s["groups"] and m != x["mac"] and not access_is_gear(s)]
    return sorted(out, key=lambda c: (c["kind"] != "group", str(c["name"]).lower()))


def ob_refs(text, choices):
    allowed = {c["ref"] for c in choices}
    return list(dict.fromkeys(r for r in str(text or "").split(",") if r in allowed))[:40]


def ob_merge(fixes):
    """Ways added together (each worked out on its own) into one model."""
    out = {"add": [], "replace": {}, "remove": [], "groups": {"move": {}, "new": {}}, "isolate": set(), "unisolate": set(), "unpause": set()}
    for f in fixes:
        out["add"] += f.get("add") or []
        for pid, r in (f.get("replace") or {}).items():
            if pid in out["replace"] and out["replace"][pid].get("sim_targets") is not None and r.get("sim_targets") is not None:
                r = {**r, "sim_targets": list(dict.fromkeys(list(out["replace"][pid]["sim_targets"]) + list(r["sim_targets"])))}
            out["replace"][pid] = r
        out["remove"] += [p for p in f.get("remove") or [] if p not in out["remove"]]
        g = f.get("groups") or {}
        out["groups"]["move"].update(g.get("move") or {})
        out["groups"]["new"].update(g.get("new") or {})
        for k in ("isolate", "unisolate", "unpause"):
            out[k] |= set(f.get(k) or ())
    return out


# Step 1 of onboarding (owner, 23 Nov 2026, D-935): where the client
# connects. The page shows what it knows (its Wi-Fi network, or its switch,
# port and VLAN); you confirm it, or say where it will connect instead and get
# a short instruction, then come back once it's there. Only on Firewalla's
# own equipment: VqLAN, Isolation and Allowed Devices hold only on the router,
# AP7s and Firewalla switches, so anywhere else the page stops.

def ob_networks():
    """Your switched networks (bridges: not WAN, not VPN): [{uuid, name, vlan}]."""
    out = []
    for uuid, meta in INTERFACE_METADATA.items():
        if meta.get("network_type") == "wan" or not meta.get("subnet") or not str(meta.get("interface") or "").startswith("br"):
            continue
        out.append({"uuid": str(uuid), "name": internet_interface_name(uuid) or meta.get("display_name") or str(uuid), "vlan": meta.get("vlan_id")})
    return sorted(out, key=lambda n: str(n["name"]).lower())


def ob_ssids(sides):
    """Each Wi-Fi network (SSID) and the network its clients land on (the
    most common one among them; the APs' own mesh links left out)."""
    seen = {}
    for mac, st in (state.get("wifi_stations") or {}).items():
        ssid = str((st or {}).get("ssid") or "")
        s = sides.get(str(mac).upper())
        if ssid and not ssid.startswith("FWAP") and s:
            seen.setdefault(ssid, []).append(s.get("network_name"))
    return sorted(({"ssid": k, "network": max(set(v), key=v.count)} for k, v in seen.items()), key=lambda x: x["ssid"].lower())


def ob_port_network(port, networks):
    vlan = port.get("pvid") if port.get("pvid") is not None else (port.get("untagged_vlans") or [None])[0]
    return next((n for n in networks if vlan is not None and str(n.get("vlan")) == str(vlan)), None), vlan


def ob_where(x):
    """Where the client connects now, and whether that is all Firewalla."""
    st = (state.get("wifi_stations") or {}).get(x["mac"])
    if st:
        ap_ok = str(st.get("ap_id") or "").upper() in {str(k).upper() for k in (state.get("access_points") or {})}
        return {"kind": "wifi", "ssid": st.get("ssid"), "ap": st.get("ap_name"), "band": st.get("band"), "network": x.get("network_name"),
                "firewalla": ap_ok, "why_not": None if ap_ok else "its access point isn't a Firewalla AP7"}
    w = (state.get("wired_clients") or {}).get(x["mac"])
    if w:
        sw = (state.get("switches") or {}).get(w.get("switch_id")) or {}
        port = (sw.get("ports") or {}).get(str(w.get("port"))) or {}
        # Other wired clients on the port (not the Wi-Fi clients of an AP further down it).
        wifi = {str(m).upper() for m in state.get("wifi_stations") or {}}
        names = dict(zip([str(m).upper() for m in port.get("connected_macs") or []], port.get("connected_names") or []))
        others = [n for m, n in names.items() if m != x["mac"] and m not in wifi]
        ok = bool(sw) and not x.get("segment")
        return {"kind": "wired", "switch": w.get("switch_name") or sw.get("name"), "switch_id": w.get("switch_id"), "port": str(w.get("port")),
                "vlan": w.get("vlan_id"), "network": x.get("network_name"), "firewalla": ok, "shares": others[:6],
                "why_not": None if ok else "it shares its switch port with other clients through a switch that isn't Firewalla's"}
    return {"kind": "unknown", "network": x.get("network_name"), "firewalla": None,
            "why_not": "neither an AP7 nor a Firewalla switch reports it: it may be plugged into the router itself, or be offline"}


def ob_ports():
    """Every Firewalla switch port, for a wired client's new place."""
    networks = ob_networks()
    out = []
    for sid, sw in sorted((state.get("switches") or {}).items(), key=lambda t: str(t[1].get("name") or "")):
        for key, p in sorted((sw.get("ports") or {}).items(), key=lambda t: int(t[0]) if str(t[0]).isdigit() else 999):
            net, vlan = ob_port_network(p, networks)
            use = "uplink" if p.get("connection_type") == "infrastructure" else (", ".join(p.get("connected_names") or [])[:60] or ("in use" if p.get("link_up") else "free"))
            out.append({"id": f"{sid}|{key}", "switch": sw.get("name") or sid, "port": str(key), "use": use, "free": not p.get("link_up"),
                        "uplink": p.get("connection_type") == "infrastructure", "network": (net or {}).get("name"), "network_uuid": (net or {}).get("uuid"), "vlan": vlan})
    return out


def ob_connect(x, where, want, wport):
    """The instruction to connect it somewhere else, and whether it's there
    now. want = "wifi:<SSID>" or "net:<network uuid>"; wport = "<switch
    id>|<port>" for a wired client moving to another port."""
    kind, _, value = str(want or "").partition(":")
    lines, arrived = [], None
    networks = {n["uuid"]: n for n in ob_networks()}
    if kind == "wifi" and value:
        lines.append(f"On the client: forget {where.get('ssid') or 'its Wi-Fi network'} and join {value}.")
        arrived = where.get("kind") == "wifi" and where.get("ssid") == value
    elif kind == "net" and value in networks:
        net = networks[value]
        target = None
        if wport:
            sid, _, key = wport.partition("|")
            port = next((p for p in ob_ports() if p["id"] == wport), None)
            if port:
                target = port
                lines.append(f"Plug its cable into {port['switch']}, port {port['port']}" + (" (free now)." if port["free"] else f" (in use now: {port['use']})."))
        elif where.get("kind") == "wired":
            target = next((p for p in ob_ports() if p["id"] == f"{where.get('switch_id')}|{where.get('port')}"), None)
        if target and target.get("network_uuid") != value:
            lines.append(f"In the Firewalla app: Network › Topology › {target['switch']} › Port {target['port']}: set its network (VLAN) to {net['name']}"
                         + (f" (VLAN {net['vlan']})" if net.get("vlan") is not None else "") + ", then Save. (On the MSP: the switch's page › Ports › "
                         + f"Port {target['port']}.) Anything else on that port moves to {net['name']} too.")
        lines.append("Then unplug the client's cable for about 10 seconds and plug it back in, so it gets an address on the new network.")
        arrived = x.get("network") == value and (not wport or (where.get("kind") == "wired" and f"{where.get('switch_id')}|{where.get('port')}" == wport))
    if lines:
        lines.append("Once it's connected there, come back to this page and press Yes, That's Right.")
    return {"lines": lines, "arrived": arrived}


# Private Wi-Fi addresses (owner, 23 Nov 2026, D-936) are not supported: a
# made-up address can change by itself, leaving every step behind. A client
# with one gets only a warning and NEXT (turn private addressing off); it then
# rejoins under its real address as a new Quarantine entry, which is the one
# onboarded, and the old entry goes to Client Offboarding. Every onboarded
# client is watched: if its entry goes quiet while a new private-address entry
# with its name appears (private addressing turned back on), that is listed
# under Changed Address on Client Onboarding and in Needs You.
ROTATION_FILE = os.environ.get("FIREWALLA_ROTATION_FILE", "/data/mac_rotation.json")
ROTATION_EVERY = 60   # seconds between checks (26 Nov 2026: was 300; a resolved one now clears within a minute)
rotation_lock = threading.Lock()


def rotation_load():
    st = policy_read_json(ROTATION_FILE) or {}
    st.setdefault("watch", {})
    st.setdefault("events", [])
    return st


def rotation_save(st):
    temporary = ROTATION_FILE + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(st, handle)
    os.replace(temporary, ROTATION_FILE)


def rotation_watch(mac, names):
    """Onboarding a client with a private address: watch it from now on."""
    with rotation_lock:
        st = rotation_load()
        st["watch"][mac] = {"names": sorted({str(n).strip().lower() for n in names if n}), "since": time.time()}
        rotation_save(st)


def rotation_check():
    """One pass: a watched client whose entry is offline while a newer entry
    with one of its names (and a private address) has appeared = a rotation."""
    devices = {str(d.get("mac") or "").upper(): d for d in state.get("devices") or []}
    now = time.time()
    with rotation_lock:
        st = rotation_load()
        known = {(e["old"], e["new"]) for e in st["events"]}
        for old, w in list(st["watch"].items()):
            od = devices.get(old)
            if od and od.get("online"):
                continue
            for new, nd in devices.items():
                if new == old or not ob_private(new) or (old, new) in known:
                    continue
                if str(nd.get("name") or "").strip().lower() in w["names"] and (nd.get("first_found") or 0) >= w["since"] - 3600:
                    st["events"].append({"id": os.urandom(5).hex(), "old": old, "new": new, "name": nd.get("name"), "at": nd.get("first_found") or now, "acked": None})
                    st["watch"][new] = {"names": w["names"], "since": now}
                    known.add((old, new))
        st["events"] = st["events"][-200:]
        rotation_save(st)
        events = list(st["events"])
    open_ = [e for e in events if not e.get("acked")]
    state["mac_rotation"] = {"events": events[-50:], "open": len(open_), "newest_at": max((e["at"] for e in open_), default=0), "at": now}


def rotation_worker():
    time.sleep(120)
    while True:
        rotation_check()
        time.sleep(ROTATION_EVERY)


@app.post("/api/onboarding/rotation-ack")
def api_rotation_ack(payload: dict = Body(default={})):
    """Acknowledge a change of address (or undo: true)."""
    fields = Fields(payload)
    eid = fields.text("id", 40, strip=False)
    with rotation_lock:
        st = rotation_load()
        for e in st["events"]:
            if e["id"] == eid:
                e["acked"] = None if payload.get("undo") else time.time()
        rotation_save(st)
    rotation_check()
    return {"ok": True}


# Firewalla features (owner, 23 Nov 2026, D-937): a feature you turned on for
# some groups (or that Firewalla runs per client) doesn't reach a new group of
# its own by itself. From scratch asks which of them the new client should
# have, and gives the step for each; box-wide ones already apply.
OB_GROUP_FEATURES = [(key, HOWTO_GROUP_SWITCHES[key]) for key in ("doh", "adblock", "family", "safe_search", "vpn_client", "bypass_prevention")]


def ob_watch(watch, mac):
    """A From Scratch step's watch. One On the new group can't name it (it
    has no number until Firewalla makes it): it carries the group's members
    instead, and howto_seen finds the group by them (24 Nov 2026: it named
    the placeholder, which no group has, so these steps were never seen and
    the change stayed In Progress for ever)."""
    on = (watch or {}).get("on")
    if on and on[0] == "group" and str(on[1]) == OB_NEW:
        return {**watch, "on_members": [mac]}
    return watch


def ob_leaving_words(x, groups):
    """What the group a client leaves (Quarantine) gave it, said in the step
    that takes it out (24 Nov 2026: nothing said that Quarantine's internet
    block doesn't follow it, so a From Scratch client with nothing ticked
    got the whole internet without a word)."""
    left = [w for gid in x.get("groups") or [] for w in howto_left_behind(gid, groups)]
    if not left:
        return ""
    return (" Leaving it also ends what that group did for it: " + "; ".join(left[:8]) + (f" and {len(left) - 8} more" if len(left) > 8 else "")
            + ". None of the steps here block the internet for the new group: it gets the internet as any client does, less what your box-wide rules "
              "and the features ticked below block. If it should have less, add a rule for the new group afterwards.")


def ob_features(groups):
    """[{key, name, kind, on, of, box}]: per-group switches (how many of your
    groups have it, and whether it is on box-wide). Device Active Protect is
    not one: it goes by network (ob_dap)."""
    box = feature_settings.get("box") or {}
    running = box.get("running") or {}
    gset = feature_settings.get("groups") or {}
    mine = [gid for gid in groups if gid != QUARANTINE]
    out = []
    for key, name in OB_GROUP_FEATURES:
        on = sum(1 for gid in mine if (gset.get(str(gid)) or {}).get(key))
        engine = {"doh": "doh", "adblock": "adblock", "family": "family_protect", "safe_search": "safe_search"}.get(key)
        box_on = bool(box.get(key)) and (engine is None or running.get(engine, True))
        if on or box_on:
            out.append({"key": key, "name": name, "kind": "group", "on": on, "of": len(mine), "box": box_on})
    return out


# Device Active Protect (owner, 23 Nov 2026, D-942): it is switched on for
# networks (Protect › Device Active Protect › Apply To: all or chosen ones),
# and Firewalla decides which clients there it covers (simple IoT only, never
# phones, computers or tablets). A single client can only be turned off, or
# back on ("Turn On DAP on This Device"). The router reports each client's
# state; the networks it covers are the ones with a client it protects.
OB_DAP_PROTECTED = ("learning", "optimizing", "active", "ready")


def ob_dap(x, name, sides, wanted):
    """(info, step or None): what Device Active Protect does for x, in words,
    and the one step there can be (turning it back on for x, when it was
    turned off on a network it covers and wanted, the reason, says it should
    be on)."""
    networks = sorted({s.get("network_name") for s in sides.values() if s.get("network_name")
                       and str((access_device_protect.get(s["mac"]) or {}).get("state") or "").lower() in OB_DAP_PROTECTED})
    st = access_device_protect.get(x["mac"]) or {}
    state_ = str(st.get("state") or "").lower()
    net = x.get("network_name")
    info = {"networks": networks, "network": net, "covered": net in networks, "state": state_ or None, "reason": st.get("reason")}
    if state_ in OB_DAP_PROTECTED:
        text = f"Firewalla already protects {name} ({state_.title()}). Nothing to do."
    elif state_ == "not_applicable":
        text = f"Firewalla doesn't use it for {name}: {st.get('reason') or 'not a client it can protect'}. Nothing to do."
    elif state_ == "disabled":
        text = f"It is turned off on {name}."
    elif net in networks:
        text = (f"{net} is a network it covers: Firewalla decides by itself whether {name} qualifies (only simple IoT clients do), "
                "then learns for up to 7 days. Nothing to do.")
    else:
        text = ""
    if net and net not in networks:
        text += (" " if text else "") + (
            f"{net}, where {name} connects, isn't a network it covers ({', '.join(networks) or 'none'}). It is set for whole networks "
            f"(Protect › Device Active Protect › Apply To), so adding {net} would cover every client there: the dashboard gives no step for that.")
    info["text"] = text
    step = None
    if wanted and state_ == "disabled" and net in networks:
        step = {"title": f"Turn Device Active Protect back on for {name}",
                "msp": {"path": ["Protect", "Device Active Protect", "Protected Devices", name], "fields": [["Press", "Turn On DAP on This Device", None]]},
                "app": {"path": ["Home", "Protect", "Device Active Protect", "Protected Devices", name],
                        "note": "Scroll down and tap Turn On DAP on This Device."},
                "note": f"{wanted} It is switched on for {net}, but turned off on {name}. It starts again at Learning (up to 7 days) and keeps what it learned before.",
                "picture": "msp-dap-device.jpg",
                "undo": f"Turn it off again: Protected Devices › {name} › Turn Off DAP on This Device.",
                "watch": {"kind": "dap_on", "mac": x["mac"]}}
    return info, step


# A client's own switches the dashboard gives steps for when you mirror a
# client that has them (owner, 23 Nov 2026, D-944): Firewalla's names and where
# each is set for one client (its page in the app; the feature's Apply To on
# the MSP). Ones it has through its group or network come with joining them.
OB_DEVICE_SWITCHES = [
    ("adblock", "Ad Block", ["Ad Block", "Apply To", "Edit"], "the Ad Block button on its page"),
    ("family", "Content Filtering", ["Controls", "Content Filtering", "Apply To", "Edit"], None),
    ("safe_search", "Safe Search", ["Controls", "Safe Search", "Apply To", "Edit"], "the Safe Search button on its page"),
    ("bypass_prevention", "Bypass Prevention", ["Controls", "Bypass Prevention", "Apply To", "Edit"], "the Prevent Bypass button on its page"),
    ("doh", "DNS over HTTPS", ["Services", "DNS over HTTPS", "Apply To", "Edit"], "DNS Service › DNS over HTTPS on its page"),
    ("unbound", "Unbound", ["Services", "Unbound", "Apply To", "Edit"], "DNS Service › Unbound on its page"),
]
OB_DEVICE_SWITCH_KEYS = {"adblock", "family", "safeSearch", "safe_search", "bypass_prevention", "bypassPrevention", "doh", "unbound"}


def ob_switch_on(d, key):
    on = d.get("on") or []
    return bool(d.get(key)) or key in on or (key == "bypass_prevention" and "bypassPrevention" in on) or (key == "safe_search" and "safeSearch" in on)


def ob_device_switches(x, name, m_side):
    """Steps that turn on, for x, the switches m_side has on for itself."""
    dset = feature_settings.get("devices") or {}
    mine, theirs = dset.get(x["mac"]) or {}, dset.get(m_side["mac"]) or {}
    steps = []
    for key, label, msp_path, app_where in OB_DEVICE_SWITCHES:
        if not ob_switch_on(theirs, key) or ob_switch_on(mine, key):
            continue
        steps.append({"title": f"Turn on {label} for {name}",
                      "msp": {"path": msp_path, "fields": [["Apply To", "Specified Devices", None], ["Tick", name, None]]},
                      "app": ({"path": ["Devices", name], "note": f"Turn on {app_where}."} if app_where else
                              {"path": ["Home", "Controls", label, "Apply To"], "note": f"Specified Devices: tick {name}, then Save."}),
                      "note": f"Then Confirm. {m_side['name']} has {label} on for itself (not through its group or network)."
                              + (" A client uses one DNS service at a time: DNS over HTTPS or Unbound." if key in ("doh", "unbound") else ""),
                      "undo": f"Untick {name} again.", "untried": HOWTO_UNTRIED_INTERNET,
                      "watch": {"kind": "device_setting", "mac": x["mac"], "key": key}})
    return steps


def ob_smart_queue_step(x, name, r, m_side):
    """A Smart Queue rule of m_side's own, made again for x (read loosely:
    the router keeps priority, rateLimit and trafficDirection on it)."""
    menu, value = howto_matching(r)
    qos = r.get("qos") if isinstance(r.get("qos"), dict) else {}
    prio = str(r.get("priority") or qos.get("priority") or "default").title()
    rate = r.get("rateLimit") or qos.get("rateLimit")
    limit = "Upload Limit" if str(r.get("trafficDirection") or qos.get("trafficDirection") or "").lower().startswith("up") else "Download Limit"
    fields = [["Matching", f"{menu} › {value}", value], ["On", name, None], ["Priority", prio, None]]
    if rate:
        fields.append([limit, str(rate), str(rate)])
    fields.append(["Schedule", "Always", None])
    return {"title": f"Create the Smart Queue rule: {prio} priority for {value} On {name}",
            "msp": {"path": ["Smart Queue", "Add Smart Queue Rule"], "fields": fields},
            "app": {"path": ["Home", "Smart Queue", "Smart Queue Rules", "Add Smart Queue Rule"],
                    "note": f"MATCHING {menu} {value}, ON {name}, Priority {prio}" + (f", {limit} {rate}" if rate else "") + ", then Save."},
            "note": f"Then Create. {m_side['name']} has this Smart Queue rule of its own (#{r.get('pid')}).", "picture": "msp-smartqb.jpg",
            "undo": "Delete the rule again.", "untried": HOWTO_UNTRIED_INTERNET,
            "watch": {"kind": "rule_device", "mac": x["mac"], "action": "qos", "side": "applies_on",
                      "other": [(r.get("matching") or {}).get("kind"), str((r.get("matching") or {}).get("id"))]}}


# What else changes when it leaves Quarantine (owner, 23 Nov 2026, D-943):
# switches the Quarantine group has that the group it joins doesn't, and, when
# it uses another network than the client it mirrors, the switches set for
# those networks. Box-wide ones apply everywhere and are left out.


def ob_changes(x, name, dest_gid, m_side):
    box = feature_settings.get("box") or {}
    running = box.get("running") or {}
    engine = {"doh": "doh", "adblock": "adblock", "family": "family_protect", "safe_search": "safe_search"}
    box_on = lambda k: bool(box.get(k)) and running.get(engine.get(k, k), True)
    gset = feature_settings.get("groups") or {}
    q = gset.get(QUARANTINE) or {}
    dest = (gset.get(str(dest_gid)) or {}) if dest_gid else {}
    out = []
    lost = [n for k, n in HOWTO_GROUP_SWITCHES.items() if q.get(k) and not dest.get(k) and not box_on(k)]
    if lost:
        out.append(f"Leaving Quarantine, {name} loses {', '.join(lost)}: the Quarantine group has "
                   + ("it" if len(lost) == 1 else "them") + ", the group it joins doesn't"
                   + (f" ({m_side['name']} doesn't have " + ("it" if len(lost) == 1 else "them") + " either)." if m_side else "."))
    if m_side:
        dset, nets = feature_settings.get("devices") or {}, feature_settings.get("networks") or {}
        xn, mn = (dset.get(x["mac"]) or {}).get("network"), (dset.get(m_side["mac"]) or {}).get("network")
        if xn and mn and xn != mn:
            xs, ms = nets.get(str(xn)) or {}, nets.get(str(mn)) or {}
            xname = x.get("network_name") or internet_interface_name(xn) or xn
            mname = m_side.get("network_name") or internet_interface_name(mn) or mn
            only_m = [n for k, n in HOWTO_GROUP_SWITCHES.items() if ms.get(k) and not xs.get(k) and not box_on(k)]
            only_x = [n for k, n in HOWTO_GROUP_SWITCHES.items() if xs.get(k) and not ms.get(k) and not box_on(k)]
            if only_m:
                out.append(f"{m_side['name']} uses {mname}, which has {', '.join(only_m)} on; {name} uses {xname}, which doesn't. "
                           "These are set for whole networks: the dashboard gives no step for them.")
            if only_x:
                out.append(f"{name} uses {xname}, which has {', '.join(only_x)} on; {mname}, which {m_side['name']} uses, doesn't.")
    return out


# Not Covered (owner, 23 Nov 2026, D-938): the router's settings and rules the
# dashboard has no steps for. Onboarding names every one that is on where the
# new client's access comes from, so you set those up yourself in the app.
# The keys the dashboard does handle (or that aren't features): never listed.
OB_HANDLED_KEYS = {"adblock", "family", "safeSearch", "doh", "vpnClient", "isolation", "tags", "deviceTags", "ipAllocation",
                   "monitor", "acl", "dap", "newDeviceTag", "userTags", "dapAdmin", "bypass_prevention", "bypassPrevention",
                   # NTP Intercept goes by network (all networks here), never by client (D-943).
                   "ntp_redirect"}
# Firewalla's own names for the router's keys the dashboard knows but has no steps for.
OB_KEY_NAMES = {"qos": "Smart Queue (QoS)", "bypass_prevention": "Bypass Prevention", "bypassPrevention": "Bypass Prevention",
                "blockin": "Block Inbound Traffic", "ntp_redirect": "NTP Intercept", "dnsmasq": "Custom DNS", "unbound": "Unbound DNS",
                "upnp": "UPnP", "enhancedSpoof": "Enhanced Spoofing", "shield": "Shield Mode", "doh_fallback": "DNS over HTTPS fallback",
                "adblock_ext": "Ad Block (Strict mode)", "safeSearchConfig": "Safe Search engines", "vpnProfiles": "VPN Client profiles",
                "routing": "Policy-based Routing", "tor": "Tor blocking", "sni": "SNI filtering", "familyConfig": "Content Filtering (3rd-party)"}
OB_RULE_ACTIONS = {"qos": "a Smart Queue / QoS rule", "address": "a custom DNS (address) rule", "route": "a routing rule",
                   "timelimit": "a Time Limit rule", "resolve": "a custom DNS rule", "intranet": "a local-network rule"}


def ob_key_name(k):
    return OB_KEY_NAMES.get(k) or k


def ob_not_covered(scope, groups, sides):
    """[{what, where}]: settings switched on and rules with actions the
    dashboard can't write steps for. scope: ("mirror", client side) - its
    own and its group's; ("scratch", None) - anything in use on the network
    beyond the box (box-wide settings already apply)."""
    out = {}
    gset, dset = feature_settings.get("groups") or {}, feature_settings.get("devices") or {}
    def add(key, where):
        if key in OB_HANDLED_KEYS:
            return
        out.setdefault(ob_key_name(key), set()).add(where)
    rules = [r for r in (state.get("policy_rules") or {}).get("rules") or [] if r.get("disabled") is not True]
    def rule_where(r):
        on = r.get("applies_on") or {}
        return on.get("label") or on.get("name") or "a rule"
    kind, x = scope
    if kind == "mirror":
        gid = x["groups"][0] if x["groups"] else None
        for k in (dset.get(x["mac"]) or {}).get("on") or []:
            if k not in OB_DEVICE_SWITCH_KEYS:   # these get steps (ob_device_switches)
                add(k, f"{x['name']} itself")
        if gid:
            gname = (groups.get(gid) or {}).get("name") or gid
            for k in (gset.get(str(gid)) or {}).get("on") or []:
                add(k, f"its group {gname}")
        for r in rules:
            ends = [r.get("applies_on") or {}, r.get("matching") or {}]
            mine = any((e.get("kind") == "device" and str(e.get("id") or "").upper() == x["mac"])
                       or (gid and e.get("kind") == "group" and str(e.get("id")) == str(gid)) for e in ends)
            stepped = r.get("action") == "qos" and any(e.get("kind") == "device" for e in ends)   # ob_smart_queue_step
            if mine and not stepped and r.get("action") in OB_RULE_ACTIONS and r.get("purpose") not in OB_FIREWALLA_PURPOSES:
                out.setdefault(f"{OB_RULE_ACTIONS[r['action']]}: #{r.get('pid')} {access_rule_text(r)}", set()).add(rule_where(r))
    else:
        for gid, g in gset.items():
            if gid == QUARANTINE or gid not in groups:
                continue
            for k in g.get("on") or []:
                add(k, f"group {(groups.get(gid) or {}).get('name') or gid}")
        for mac, d in dset.items():
            if mac in sides and not access_is_gear(sides[mac]):
                for k in d.get("on") or []:
                    add(k, sides[mac]["name"])
        for r in rules:
            on = r.get("applies_on") or {}
            if r.get("action") in OB_RULE_ACTIONS and r.get("purpose") not in OB_FIREWALLA_PURPOSES and on.get("kind") in ("group", "device"):
                out.setdefault(OB_RULE_ACTIONS[r["action"]].capitalize() + "s", set()).add(rule_where(r))
    def where_words(ws):
        ws = sorted(ws)
        return ", ".join(ws[:4]) + (f" and {len(ws) - 4} more" if len(ws) > 4 else "")
    return sorted(({"what": k, "where": where_words(v)} for k, v in out.items()), key=lambda i: i["what"].lower())


def ob_plan(mac, mode=None, like=None, to=None, frm=None, name=None, conn=None, want=None, wport=None, pmac=None, feat=None, net=None, how=None):
    """Everything the page shows for one client once you say how it gets its
    access (mode "mirror" with like = a client, or "scratch" with to / frm =
    refs, net = "yes" / "no" for the internet and how = each target's purpose
    and ports, ob_how), with "_fix" for I'm Doing This. From scratch there
    are no steps until every question is answered ("waiting" lists what is
    still to say)."""
    sides, groups = access_sides()
    x = sides.get(str(mac or "").upper())
    if not x:
        return None
    name = (name or "").strip()[:60] or x["name"]
    choices = ob_choices(x, sides, groups)
    out = {"mac": x["mac"], "name": name, "mode": mode if mode in ("mirror", "scratch") else None,
           "client": {"name": x["name"], "ip": x.get("ip"), "online": x.get("online"), "network": x.get("network_name"), "private": ob_private(x["mac"])},
           "choices": choices,
           "clients": sorted(({"mac": m, "name": s["name"], "group": (groups.get(s["groups"][0]) or {}).get("name") if s["groups"] else None}
                              for m, s in sides.items() if m != x["mac"] and not access_is_gear(s) and QUARANTINE not in s["groups"]),
                             key=lambda c: (str(c["name"]).lower(), str(c["group"] or "~")))}   # A to Z by name (owner, 27 Nov 2026, D-1085)
    # A private Wi-Fi address isn't supported (owner, 23 Nov 2026, D-936): the
    # phone must have private addressing turned off, and then it rejoins under
    # its real address as a new entry in Quarantine, which is the one to onboard.
    if ob_private(x["mac"]):
        # Its new entry: one with the same name, or (a phone names itself, e.g.
        # "Kellys-iPhone-2", while you renamed the old one) any entry with a
        # real address that came into Quarantine in the last two days.
        key = str(x["name"]).strip().lower()
        devices = {str(d.get("mac") or "").upper(): d for d in state.get("devices") or []}
        recent = time.time() - 2 * 86400
        twins = [{"mac": m, "name": s_["name"], "online": s_.get("online"), "ip": s_.get("ip"),
                  "ssid": ((state.get("wifi_stations") or {}).get(m) or {}).get("ssid"), "same_name": str(s_["name"]).strip().lower() == key}
                 for m, s_ in sides.items() if m != x["mac"] and not ob_private(m)
                 and (str(s_["name"]).strip().lower() == key or (QUARANTINE in s_["groups"] and ((devices.get(m) or {}).get("first_found") or 0) >= recent))]
        twins.sort(key=lambda t: (not t["same_name"], str(t["name"]).lower()))
        out["gate"] = {"confirmed": pmac == "1", "twins": twins[:6], "ssid": ((state.get("wifi_stations") or {}).get(x["mac"]) or {}).get("ssid")}
        out["mode"] = None
        return out
    # Step 1: where it connects, confirmed by you before anything else (D-935).
    where = ob_where(x)
    out["where"] = where
    out["ssids"] = ob_ssids(sides)
    out["networks"] = ob_networks()
    out["ports"] = ob_ports()
    out["connect"] = ob_connect(x, where, want, wport)
    out["conn"] = "ok" if conn == "ok" else ("else" if conn == "else" else None)
    if where.get("firewalla") is False:
        out["blocked"] = (f"{x['name']} connects where Firewalla can't fence it: {where['why_not']}. VqLAN, Isolation and Allowed Devices only hold on "
                          "Firewalla's own router, AP7s and switches, so onboarding stops here. Connect it to an AP7 or its own port on a Firewalla switch, then come back.")
        out["mode"] = None
        return out
    if out["conn"] != "ok" or not out["mode"]:
        out["mode"] = out["mode"] if out["conn"] == "ok" else None
        return out
    shown = {**x, "name": name}
    steps = []
    if name != x["name"]:
        steps.append({"title": f"Name it \"{name}\"", "msp": {"path": ["Devices", x["name"]], "fields": [["Name", name, name]]},
                      "app": {"path": ["Devices", "All", x["name"]], "fields": [["Name (tap the name at the top)", name]], "note": "Tap its name at the top of its page, type the new name, then Save."},
                      "note": f"It is {howto_id(x)} today. A name in your style makes it easy to find in every list.",
                      "undo": f"Rename it back to \"{x['name']}\".", "watch": {"kind": "named", "mac": x["mac"], "name": name}})
    rules, iso = access_local_rules(), access_isolated()
    paused = {m: why for m, sd in sides.items() if (why := access_paused(sd))}
    fixes, problems = [], []
    if out["mode"] == "mirror":
        m_side = sides.get(str(like or "").upper())
        if not m_side or m_side["mac"] == x["mac"]:
            out["mode_ready"] = False
            return out
        out["like"] = {"mac": m_side["mac"], "name": m_side["name"]}
        base = ob_mirror(x, shown, m_side, sides, groups, steps)
        fixes.append(base)
        if m_side["groups"]:
            out["gives"] = ob_group_gives(m_side["groups"][0], groups, sides)
            out["group_name"] = (groups.get(m_side["groups"][0]) or {}).get("name")
        m_state = str((access_device_protect.get(m_side["mac"]) or {}).get("state") or "").lower()
        out["dap"], dap_step = ob_dap(x, name, sides, f"{m_side['name']} has it ({m_state.title()})." if m_state in OB_DAP_PROTECTED else None)
        if dap_step:
            steps.append(dap_step)
        out["changes"] = ob_changes(x, name, m_side["groups"][0] if m_side["groups"] else None, m_side)
    else:
        want_to, want_from = ob_refs(to, choices), ob_refs(frm, choices)
        out["to"], out["frm"] = want_to, want_from
        # Named like your other groups (owner, 27 Nov 2026, D-1091): the next
        # number in front and its network at the end, "G30 Printer .7".
        octets = str(x.get("ip") or "").split(".")
        net_end = f" .{octets[2]}" if len(octets) == 4 and octets[2].isdigit() else ""
        base = howto_short_name(name) + net_end
        gname = howto_fit([base], prefix=howto_group_number(groups))
        if any(str(g.get("name") or "").lower() == gname.lower() for g in groups.values()):
            gname = howto_fit([base], tail="2", prefix=howto_group_number(groups))
        out["group_name"] = gname
        new = {"id": OB_NEW, "name": gname, "members": [x["mac"]], "vqlan": True, "isolation": False}
        steps.append({"title": f"Make a group \"{gname}\" with only {howto_id(shown)}",
                      "msp": {"path": ["Groups & Users", "Create Group"], "fields": [["Name", gname, gname], ["Devices", howto_id(shown), None]]},
                      "app": howto_app("create_group", name=gname, devices=[howto_id(shown)]),
                      "note": "It leaves Quarantine (a client is in one group at a time) for a group of its own, so what it reaches on your network is only what you choose below."
                              + ob_leaving_words(x, groups),
                      "undo": f"Move {name} back into Quarantine and delete the group \"{gname}\".", "watch": {"kind": "pair_group", "members": [x["mac"]]}})
        steps.append({"title": f"Turn VqLAN on and Device Isolation off for \"{gname}\"",
                      "msp": {"path": ["Groups & Users", gname], "fields": [["VqLAN", "On", None], ["Device Isolation", "Off", None]]},
                      "app": howto_app("toggles", unit=gname, unit_kind="group", toggles=[["VqLAN", True], ["Device Isolation", False]]),
                      "note": "VqLAN keeps every other client out, and it from them, except what the steps below open.",
                      "undo": "Nothing (the group goes with the step above's undo).",
                      "watch": {"kind": "pair_group", "members": [x["mac"]], "vqlan": True, "isolation": False, "as": "setting"}})
        # The internet: asked, never assumed (D-1064). No = a Block Internet rule on its group.
        net = net if net in ("yes", "no") else None
        out["net"] = net
        if net == "no":
            rname = howto_fit([gname], tail="No Internet")
            steps.append({"title": f"Block the internet for \"{gname}\"", "copy": True,
                          "msp": {"path": ["Rules", "Create Rule"], "fields": [
                              ["Name", rname, rname], ["Action", "Block", None], ["Matching", "Internet › Traffic from & to Internet", None],
                              ["On", f"FWG Pro (Router) + {gname}", None], ["Schedule", "Always", None]]},
                          "app": howto_app("rule", name=rname, action="block", matching_path="Set a target › Internet", matching_label="Internet",
                                           matching_value="Traffic from & to Internet", target="the Internet", on_kind="group", on=gname),
                          "note": f"You said {name} doesn't need the internet. Then Create. What it reaches on your network is in the steps below.",
                          "picture": "msp-rule-create.jpg", "undo": f"Delete the rule \"{rname}\".", "untried": HOWTO_UNTRIED_INTERNET,
                          "watch": {"kind": "own_group_no_internet", "mac": x["mac"]}})
        # Firewalla features for it (D-937): box-wide ones already apply; the rest only if you tick them.
        feats = ob_features(groups)
        out["features"] = feats
        picked = [f for f in feats if f["key"] in set(str(feat or "").split(",")) and not f["box"]]
        out["feat"] = [f["key"] for f in picked]
        switches = [f for f in picked if f["kind"] == "group"]
        if switches:
            words = ", ".join(f["name"] for f in switches)
            steps.append({"title": f"Turn on {words} for \"{gname}\"",
                          "msp": {"path": ["Groups & Users", gname], "fields": [[f["name"], "On", None] for f in switches]},
                          "app": howto_app("toggles", unit=gname, unit_kind="group", toggles=[[f["name"], True] for f in switches]),
                          "note": "On the group's own page. " + "; ".join(f"{f['name']} is on for {f['on']} of your {f['of']} groups" for f in switches) + ".",
                          "undo": "Turn them off again.", "untried": HOWTO_UNTRIED_INTERNET,
                          "watch": {"kind": "own_group_setting", "mac": x["mac"], "keys": [f["key"] for f in switches]}})
        out["dap"] = ob_dap(x, name, sides, None)[0]
        out["changes"] = ob_changes(x, name, None, None)
        # Each ticked target: what for, and its ports or Learning Mode. Nothing is worked out before all is said.
        label = {c["ref"]: c["name"] for c in choices}
        details = ob_how(how)
        picks = [ob_pick(side, r, label[r], details.get((side, r)) or {}) for side, refs in (("to", want_to), ("frm", want_from)) for r in refs]
        out["picks"], out["purposes"] = picks, OB_PURPOSES
        for p in picks:
            if p["mode"] == "copy" and p["side"] == "to":
                p["others"] = ob_others(p["ref"], x["mac"], sides, groups)
        waiting = (["Whether it needs the internet"] if not net else []) + [
            f"{'It reaches' if p['side'] == 'to' else 'Reaching it:'} {p['name']}: {p['missing']}" for p in picks if not p["ok"]]
        if waiting:
            out["waiting"], out["steps"], out["problems"] = waiting, [], []
            return out
        base = {"add": [], "replace": {}, "remove": [], "groups": {"move": {x["mac"]: OB_NEW}, "new": {OB_NEW: new}}}
        fixes.append(base)
        t_groups = {gid: {**g, "members": [m for m in g.get("members") or [] if m != x["mac"]]} for gid, g in groups.items()}
        t_groups[OB_NEW] = new
        t_sides = {m: ({**sd, "groups": [OB_NEW], "name": name} if m == x["mac"] else sd) for m, sd in sides.items()}
        for p in picks:
            a_refs, b_refs = (["d:" + x["mac"]], [p["ref"]]) if p["side"] == "to" else ([p["ref"]], ["d:" + x["mac"]])
            check, suffix, words = howto_port(p["proto"], p["ports"]) if p["mode"] == "ports" else (None, "", "every port")
            what = ((f"{name} → {p['name']}" if p["side"] == "to" else f"{p['name']} → {name}")
                    + f" · {p['why']} · {'Learning Mode: every port, to narrow later' if p['mode'] == 'learn' else words}")
            # The lists the targets before this one are getting: this one's list takes the next number.
            made = [st["watch"]["name"] for st in steps if (st.get("watch") or {}).get("kind") == "list"]
            d = howto_direction("allow", a_refs, b_refs, check, suffix, words, t_sides, t_groups, rules, iso, paused, what, model=True, lists_taken=made)
            if d["done"]:
                continue
            ways = [f for f in d["fixes"] if f["id"] not in ("pair", "own-group") and f["result"]["ok"] == f["result"]["of"]]
            pick = next((f for f in ways if f.get("offer")), ways[0] if ways else None)
            if not pick:
                problems.append(f"{what}: no way found" + (" (" + "; ".join(c["text"] for c in d.get("conditions") or [])[:300] + ")" if d.get("conditions") else ""))
                continue
            steps += [{**st, "for": what, "watch": ob_watch(st.get("watch"), x["mac"])} for st in pick["steps"] if st["title"] not in {s["title"] for s in steps}]
            fixes.append(pick["model"])
    # A reserved IP address only when a step puts its address in a target list
    # (owner, 23 Nov 2026, D-939), just before the first such step.
    ips = set(howto_addresses(x)[0]) | {x.get("ip")}
    listing = [i for i, st in enumerate(steps) if (st.get("watch") or {}).get("kind") == "list"
               and any(str(l).partition(",")[0] in ips for l in (st.get("watch") or {}).get("lines") or [])]
    reserved_step = any((st.get("watch") or {}).get("kind") == "reserved" and (st.get("watch") or {}).get("mac") == x["mac"] for st in steps)
    if listing and x.get("ip") and not howto_addresses(x)[1] and not reserved_step:
        steps.insert(listing[0], howto_reserve_step({"mac": x["mac"], "name": name, "ip": x["ip"]}))
    out["problems"] = problems
    out["steps"] = steps
    out["not_covered"] = ob_not_covered(("mirror", m_side) if out["mode"] == "mirror" else ("scratch", None), groups, sides)
    fix = ob_merge(fixes)
    out["_fix"] = fix
    # What it will reach, from your rules, once every step is done.
    trial, t_groups, moved, t_iso, t_paused = howto_trial(fix, rules, groups, sides, iso, paused)
    others = [s for m, s in sides.items() if m != x["mac"] and not access_is_gear(s)]
    def reach(a, rs, gs, isolated, pz, mover):
        to_ = [y for y in others if y["mac"] != a["mac"] and check_local_access(*mover(a, y), gs, rs, isolated=isolated, paused=pz)["verdict"] == "allowed"]
        back = [y for y in others if y["mac"] != a["mac"] and check_local_access(*mover(y, a), gs, rs, isolated=isolated, paused=pz)["verdict"] == "allowed"]
        return to_, back
    same = lambda a, b: (a, b)
    now_to, now_back = reach(x, rules, groups, iso, paused, same)
    after_to, after_back = reach(x, trial, t_groups, t_iso, t_paused, moved)
    names = lambda ys: sorted(y["name"] for y in ys)
    out["reach"] = {"now": {"to": names(now_to), "back": names(now_back)}, "after": {"to": names(after_to), "back": names(after_back)}}
    if out["mode"] == "mirror":
        m_to, m_back = reach(m_side, rules, groups, iso, paused, same)
        drop = lambda ys: {y["name"] for y in ys if y["mac"] not in (x["mac"], m_side["mac"])}
        out["reach"]["mate"] = {"name": m_side["name"],
                                "only_mate": sorted(drop(m_to) - drop(after_to)), "only_new": sorted(drop(after_to) - drop(m_to)),
                                "only_mate_back": sorted(drop(m_back) - drop(after_back)), "only_new_back": sorted(drop(after_back) - drop(m_back))}
    else:
        covered = lambda refs: {m for r in refs for m in ((groups.get(r[2:]) or {}).get("members") or [] if r.startswith("g:") else [r[2:]])}
        asked_to, asked_from = covered(out["to"]), covered(out["frm"])
        out["reach"]["extra_to"] = names(y for y in after_to if y["mac"] not in asked_to)
        out["reach"]["extra_back"] = names(y for y in after_back if y["mac"] not in asked_from)
        out["reach"]["missing_to"] = sorted(sides[m]["name"] for m in asked_to if m in sides and m != x["mac"] and m not in {y["mac"] for y in after_to})
        out["reach"]["missing_back"] = sorted(sides[m]["name"] for m in asked_from if m in sides and m != x["mac"] and m not in {y["mac"] for y in after_back})
    return out


def ob_mirror(x, shown, m_side, sides, groups, steps):
    """The steps (added to steps) and model that give x the same access as
    the client m_side: its group (or none), its lines in every target list,
    its Allowed Devices entries and its own rules."""
    name = shown["name"]
    fix = {"add": [], "replace": {}, "remove": [], "groups": {}}
    if m_side["groups"]:
        gid = m_side["groups"][0]
        gname = (groups.get(gid) or {}).get("name") or gid
        steps.append({"title": f"Move {howto_id(shown)} from Quarantine into \"{gname}\"",
                      "msp": {"path": ["Groups & Users", gname, "Devices"], "fields": [["Tick", howto_id(shown), None]]},
                      "app": {"path": ["Devices", "Groups", gname, "Add Device"], "fields": [["Tick", howto_id(shown), None]],
                              "note": "Tick it, Done, confirm the \"Change of Group\", then Save."},
                      "note": f"Then Save. It leaves Quarantine and gets everything {gname} gives, as {m_side['name']} does.",
                      "undo": f"Move {name} back into Quarantine.", "watch": {"kind": "in_group", "mac": x["mac"], "group": gid}})
        fix["groups"] = {"move": {x["mac"]: gid}, "new": {}}
    else:
        steps.append({"title": f"Take {howto_id(shown)} out of Quarantine",
                      "msp": {"path": ["Groups & Users", "Quarantine", "Devices"], "fields": [["Untick", howto_id(shown), None]]},
                      "app": {"path": ["Devices", "Groups", "Quarantine"], "note": "Swipe left on it in the list, then tap Leave Group (Firewalla's New Device Quarantine help)."},
                      "note": f"Then Save. {m_side['name']} is in no group, so neither is {name}: it then has only what the steps below give it.",
                      "undo": f"Move {name} back into Quarantine.", "watch": {"kind": "not_in_group", "mac": x["mac"], "group": QUARANTINE}})
        fix["groups"] = {"move": {x["mac"]: None}, "new": {}}
    rules = [r for r in (state.get("policy_rules") or {}).get("rules") or [] if r.get("disabled") is not True]
    m_ips = set(howto_addresses(m_side)[0]) | set(m_side.get("ips") or [])
    x_ips = howto_addresses(x)[0]
    for tid, tl in sorted(msp["lists"].items(), key=lambda t: str(t[1].get("name") or "").lower()):
        endings = list(dict.fromkeys(e for _, ip, e in list_check_lines(tl) if ip in m_ips))
        if not endings or not x_ips:
            continue
        add = list(dict.fromkeys(f"{ip}{e}" for ip in x_ips for e in endings))
        have = {str(t).strip().lower() for t in tl.get("targets") or []}
        add = [a for a in add if a.lower() not in have]
        if not add:
            continue
        lname = tl.get("name") or tid
        users = [r for r in rules if access_target_list_side(r) and str((r.get(access_target_list_side(r)) or {}).get("id")) == str(tid)]
        steps.append({"title": f"Add {howto_id(shown)} to your list \"{lname}\"",
                      "msp": {"path": ["Target Lists", lname], "fields": [["Targets", "add this line" if len(add) == 1 else "add these lines", "\n".join(add)]], "lines": add},
                      "app": {"note": "Target lists can only be edited on the MSP website."},
                      "note": f"Then Save & Apply. {m_side['name']} is in this list" + (f" ({', '.join('#' + str(r.get('pid')) for r in users)} use{'s' if len(users) == 1 else ''} it)." if users else " (no rule uses it today)."),
                      "picture": "msp-targetlist-edit.jpg", "undo": f"Remove the line{'s' if len(add) != 1 else ''} again: " + "; ".join(add),
                      "watch": {"kind": "list", "name": lname, "lines": add}})
        for r in users:
            fix["replace"][str(r.get("pid"))] = {**r, "sim_targets": list(tl.get("targets") or []) + add}
    for r in rules:
        ends = {s: r.get(s) or {} for s in ("applies_on", "matching")}
        mine = [s for s, e in ends.items() if e.get("kind") == "device" and str(e.get("id") or "").upper() == m_side["mac"]]
        if not mine:
            continue
        # Rules Firewalla makes and keeps itself are never copied by hand (owner,
        # 23 Nov 2026): Device Active Protect's two rules per client (its own
        # learned list), Region Blocking, Threat Filtering, Content Filtering,
        # Firewall Defaults, App QoS.
        if r.get("purpose") in OB_FIREWALLA_PURPOSES or str(r.get("app_name") or "").startswith("qos_"):
            continue
        if r.get("action") == "qos" and "applies_on" in mine:
            steps.append(ob_smart_queue_step(x, name, r, m_side))
            continue
        if r.get("action") not in ("allow", "block"):
            continue   # QoS, routing, custom DNS, time limits: listed under Not Covered instead
        me = {"kind": "device", "id": x["mac"], "name": name}
        copy = {**r, "pid": f"ob-{r.get('pid')}", **{s: me for s in mine}}
        if r.get("purpose") == "ap_allow":
            owner, ticked = access_allowed_owner(r)
            if str(owner.get("id") or "").upper() == m_side["mac"]:
                title, where, tick = f"Tick {ticked.get('name')} in {name}'s own Allowed Devices", ["Devices", name, "Allowed Devices"], ticked.get("name") or ""
                app = howto_app("allowed", owner=name, owner_kind="device", names=[tick])
                watch = {"kind": "allowed", "on": ["device", x["mac"]], "others": [[ticked.get("kind"), str(ticked.get("id"))]], "present": True}
            else:
                title = f"Tick {howto_id(shown)} in {owner.get('name')}'s Allowed Devices"
                where = (["Groups & Users"] if owner.get("kind") == "group" else ["Devices"]) + [owner.get("name") or "", "Allowed Devices"]
                tick = howto_id(shown)
                app = howto_app("allowed", owner=owner.get("name") or "", owner_kind=owner.get("kind"), names=[tick])
                watch = {"kind": "allowed", "on": [owner.get("kind"), str(owner.get("id"))], "others": [["device", x["mac"]]], "present": True}
            steps.append({"title": title, "msp": {"path": where, "fields": [["Tick", tick, None]]}, "app": app,
                          "note": f"Then Save. {m_side['name']} has this Allowed Devices entry (every port, both ways).", "picture": "msp-group-allowed-devices.jpg",
                          "undo": "Untick it again.", "watch": watch})
        else:
            menu, value = howto_matching(r) if "applies_on" in mine else ("Device", name)
            on_name = name if "applies_on" in mine else ((r.get("applies_on") or {}).get("name") or "its scope")
            text = access_rule_text(r)
            steps.append({"title": f"Create the rule: {str(r.get('action') or 'allow').title()} {menu} {value} On {on_name}",
                          "msp": {"path": ["Rules", "Create Rule"], "fields": [["Action", str(r.get("action") or "allow").title(), None], ["Matching", f"{menu} › {value}", value],
                                  ["On", f"FWG Pro (Router) + {on_name}", None],
                                  ["Direction", {"outbound": "Outbound only", "inbound": "Inbound only"}.get(r.get("direction"), "Bi-directional"), None], ["Schedule", "Always", None]]},
                          "app": {"note": f"In the app: Rules › Add Rule: ACTION {str(r.get('action') or 'allow').title()}, MATCHING {menu} {value}, ON {on_name}."},
                          "note": f"Then Create. {m_side['name']} has this rule of its own ({text}).", "picture": "msp-rule-create.jpg",
                          "undo": "Delete the rule again.",
                          "watch": {"kind": "rule_device", "mac": x["mac"], "action": r.get("action"), "side": mine[0],
                                    "other": [(r.get("matching" if mine[0] == "applies_on" else "applies_on") or {}).get("kind"),
                                              str((r.get("matching" if mine[0] == "applies_on" else "applies_on") or {}).get("id"))]}})
        fix.setdefault("add", []).append(copy)
    steps += ob_device_switches(x, name, m_side)
    return fix


@app.get("/api/onboarding-page")
def api_onboarding_page(mac: str = None, mode: str = None, like: str = None, to: str = None, frm: str = None, name: str = None,
                        conn: str = None, want: str = None, wport: str = None, pmac: str = None, feat: str = None, net: str = None, how: str = None):
    """The Client Onboarding page: Quarantine's check, the clients in it (and
    clients in no group at all), the plan for one, and onboarding changes."""
    sides, groups = access_sides()
    check = ob_quarantine_check()
    devices = {str(d.get("mac") or "").upper(): d for d in state.get("devices") or []}
    wifi = state.get("wifi_stations") or {}
    # A twin: another entry with the same name, as a phone with a private Wi-Fi
    # address leaves behind when it joins another Wi-Fi network (a new address).
    by_name = {}
    for s in sides.values():
        by_name.setdefault(str(s["name"]).strip().lower(), []).append(s)
    twin = lambda s: next(({"mac": o["mac"], "name": o["name"], "online": o.get("online")} for o in by_name.get(str(s["name"]).strip().lower(), []) if o["mac"] != s["mac"]), None)
    row = lambda s: {"mac": s["mac"], "name": s["name"], "ip": s.get("ip"), "online": s.get("online"), "network": s.get("network_name"),
                     "private": ob_private(s["mac"]), "ssid": (wifi.get(s["mac"]) or {}).get("ssid"), "first_found": (devices.get(s["mac"]) or {}).get("first_found"),
                     "twin": twin(s)}
    quarantined = [row(sides[m]) for m in (groups.get(QUARANTINE) or {}).get("members") or [] if m in sides]
    loose = [row(s) for s in sides.values() if not s["groups"] and not access_is_gear(s) and s.get("online")]
    plan = ob_plan(mac, mode, like, to, frm, name, conn, want, wport, pmac, feat, net, how) if mac else None
    if plan:
        plan.pop("_fix", None)
    # Onboarding and offboarding changes in progress, as the Changes list shows them (steps seen, saved steps).
    changes = [c for c in howto_mark_done() if (c.get("request") or {}).get("kind") in ("onboard", "offboard") and c.get("status") != "done"]
    return {"check": check, "rotations": (state.get("mac_rotation") or {}).get("events") or [], "quarantined": sorted(quarantined, key=lambda r: str(r["name"]).lower()),
            "loose": sorted(loose, key=lambda r: str(r["name"]).lower()), "plan": plan,
            "changes": changes, "learning": ob_learning_view(sides, groups), "updated_at": time.time()}


@app.post("/api/onboarding/start")
def api_onboarding_start(payload: dict = Body(default={})):
    """I'm Doing This for onboarding: {mac, mode, like, to, frm, name}. Saved
    like a Show Me How change (kind "onboard"): its steps in full and every
    pair it touches for the before-and-after check; watched by howto_mark_done."""
    fields = Fields(payload)
    text = lambda k, n: fields.text(k, n, strip=False)
    req = {"mac": text("mac", 40).upper(), "mode": text("mode", 10), "like": text("like", 40).upper(), "to": text("to", 4000), "frm": text("frm", 4000), "name": text("name", 60),
           "pmac": "1" if payload.get("pmac") in ("1", 1, True) else "", "feat": text("feat", 200),
           "net": text("net", 3), "how": text("how", 8000)}
    plan = ob_plan(req["mac"], req["mode"], req["like"], req["to"], req["frm"], req["name"], "ok", None, None, req["pmac"], req["feat"], req["net"], req["how"])
    if plan and ob_private(plan["mac"]):
        return {"ok": False, "error": "Private Wi-Fi addresses are not supported: turn private addressing off on the device, then onboard the new entry it makes in Quarantine."}
    if plan and plan.get("waiting"):
        return {"ok": False, "error": "Still to answer: " + "; ".join(plan["waiting"][:4]) + "."}
    if not plan or not plan.get("steps"):
        return {"ok": False, "error": "Say how it gets its access first."}
    sides, groups = access_sides()
    rules, iso = access_local_rules(), access_isolated()
    paused = {m: why for m, sd in sides.items() if (why := access_paused(sd))}
    expect = howto_expect(plan["_fix"], rules, groups, [], [None], iso, sides, paused)
    steps = [{**{k: s.get(k) for k in HOWTO_STEP_KEYS if s.get(k) is not None}, "title": s["title"], "watch": s["watch"]} for s in plan["steps"]]
    title = (f"Onboard {plan['name']} like {plan['like']['name']}" if plan["mode"] == "mirror" and plan.get("like")
             else f"Onboard {plan['name']} into a group of its own")
    change = {"id": os.urandom(6).hex(), "title": title, "source": "Client Onboarding",
              "started": time.time(), "status": "in_progress", "request": {"kind": "onboard", **req},
              "steps": steps, "undo": [s.get("undo") for s in reversed(plan["steps"]) if s.get("undo")], "expect": expect}
    with howto_lock:
        st = howto_load()
        st["changes"] = [change] + st["changes"][:99]
        howto_save(st)
    # Learning Mode targets, listed in their own section of the page from now on (D-1069).
    # Each with the target list its steps make (or add to): the list to narrow later.
    made_for = lambda p: next((s["watch"]["name"] for s in plan["steps"] if (s.get("watch") or {}).get("kind") == "list"
                               and str(s.get("for") or "").startswith((f"{plan['name']} → {p['name']}" if p["side"] == "to" else f"{p['name']} → {plan['name']}") + " · ")), None)
    learning = [{"id": os.urandom(5).hex(), "change": change["id"], "mac": plan["mac"], "name": plan["name"], "group_name": plan.get("group_name"),
                 "side": p["side"], "ref": p["ref"], "target": p["name"], "why": p["why"], "started": change["started"], "list": made_for(p)}
                for p in plan.get("picks") or [] if p["mode"] == "learn"]
    if learning:
        with ob_learning_lock:
            ob_learning_save(learning + [i for i in ob_learning_load() if (i["mac"], i["side"], i["ref"]) not in {(n["mac"], n["side"], n["ref"]) for n in learning}])
    # Watched from now on: if the device turns private addressing (back) on, it
    # rejoins as a new entry with its name, listed under Changed Address.
    rotation_watch(req["mac"], [plan["client"]["name"], plan["name"]])
    return {"ok": True, "id": change["id"]}


# ============================================================
# CLIENT OFFBOARDING (owner, 23 Nov 2026, D-932). Removing a client starts
# with it off or gone but still in Firewalla (offline 30 days or more, or
# picked): while Firewalla still has it, the dashboard can find everything
# it has and take each piece away, in order, before it is deleted last:
#   its lines in your target lists, Allowed Devices entries naming it,
#   rules On or Matching it, port forwards to it, its address reservation,
#   then Delete in Firewalla.
# A client that is online is not offered (turn it off first). The
# before-and-after check confirms no other client loses anything.
# ============================================================

def off_has(x):
    """Everything a client has in your setup, found while Firewalla still has it."""
    ips = set(howto_addresses(x)[0]) | set(x.get("ips") or [])
    lists = []
    for tid, tl in sorted(msp["lists"].items(), key=lambda t: str(t[1].get("name") or "").lower()):
        mine = [text for text, ip, _ in list_check_lines(tl) if ip in ips]
        if mine:
            lists.append((tid, tl, mine))
    allowed, rules = [], []
    for r in (state.get("policy_rules") or {}).get("rules") or []:
        if r.get("disabled") is True:
            continue
        ends = [r.get("applies_on") or {}, r.get("matching") or {}]
        if not any(e.get("kind") == "device" and str(e.get("id") or "").upper() == x["mac"] for e in ends):
            continue
        # Firewalla's own rules for it (Device Active Protect's two) are Firewalla's to remove.
        if r.get("purpose") in OB_FIREWALLA_PURPOSES or r.get("action") == "qos":
            continue
        (allowed if r.get("purpose") == "ap_allow" else rules).append(r)
    forwards = [m for m in (feature_settings.get("box") or {}).get("port_forward_maps") or []
                if m.get("to_mac") == x["mac"] or (m.get("to_ip") and m.get("to_ip") in ips)]
    return {"lists": lists, "allowed": allowed, "rules": rules, "forwards": forwards, "reserved": howto_reserved(x["mac"])}


def off_plan(mac):
    sides, groups = access_sides()
    x = sides.get(str(mac or "").upper())
    if not x:
        return None
    has = off_has(x)
    gname = (groups.get(x["groups"][0]) or {}).get("name") if x["groups"] else None
    steps, fix = [], {"add": [], "replace": {}, "remove": [], "groups": {}}
    rules_all = [r for r in (state.get("policy_rules") or {}).get("rules") or [] if r.get("disabled") is not True]
    for tid, tl, mine in has["lists"]:
        lname = tl.get("name") or tid
        steps.append({"title": f"Remove {howto_id(x)} from your list \"{lname}\"",
                      "msp": {"path": ["Target Lists", lname], "fields": [["Remove", f"{len(mine)} line{'s' if len(mine) != 1 else ''}", "\n".join(mine)]], "lines": mine},
                      "app": {"note": "Target lists can only be edited on the MSP website."}, "note": "Delete each of these lines, then Save & Apply.",
                      "picture": "msp-targetlist-edit.jpg", "undo": f"Add the lines back to \"{lname}\": " + "; ".join(mine),
                      "watch": {"kind": "list_without", "name": lname, "lines": mine}})
        for r in rules_all:
            if access_target_list_side(r) and str((r.get(access_target_list_side(r)) or {}).get("id")) == str(tid):
                fix["replace"][str(r.get("pid"))] = {**r, "sim_targets": [t for t in tl.get("targets") or [] if str(t).strip() not in mine]}
    for r in has["allowed"]:
        owner, ticked = access_allowed_owner(r)
        steps.append({"title": f"Untick {ticked.get('name') or ticked.get('id')} in {owner.get('name') or owner.get('id')}'s Allowed Devices",
                      "msp": {"path": (["Groups & Users"] if owner.get("kind") == "group" else ["Devices"]) + [owner.get("name") or "", "Allowed Devices"],
                              "fields": [["Untick", ticked.get("name") or "", None]]},
                      "app": howto_app("allowed", owner=owner.get("name") or "", owner_kind=owner.get("kind"), names=[ticked.get("name") or ""], remove=True),
                      "note": "Then Save.", "picture": "msp-group-allowed-devices.jpg",
                      "undo": f"Tick {ticked.get('name')} again in {owner.get('name')}'s Allowed Devices.",
                      "watch": {"kind": "gone", "pid": str(r.get("pid"))}})
        fix["remove"].append(str(r.get("pid")))
    for r in has["rules"]:
        text = access_rule_text(r)
        on_it = str((r.get("applies_on") or {}).get("id") or "").upper() == x["mac"]
        steps.append({"title": f"Delete rule #{r.get('pid')}: {text}",
                      "msp": {"path": ["Rules", f"#{r.get('pid')} {text}"], "fields": [["Button", "Delete", None]]},
                      "app": howto_app("pause", scope=x["name"], rule=text),
                      "note": f"It is a rule {'On' if on_it else 'Matching'} {x['name']}: it does nothing once the client is gone.",
                      "picture": "msp-rule-details.jpg", "undo": f"Make the rule again: {text}.", "watch": {"kind": "gone", "pid": str(r.get("pid"))}})
        fix["remove"].append(str(r.get("pid")))
    for m in has["forwards"]:
        what = f"{m.get('name') or 'port forward'} ({str(m.get('proto') or 'tcp').upper()} {m.get('port')} to {m.get('to_ip')}:{m.get('to_port')})"
        steps.append({"title": f"Delete the port forward {what}",
                      "msp": {"path": ["Network", "Port Forwarding"], "fields": [["Delete", what, None]]},
                      "app": {"path": ["Network", "Port Forwarding"], "note": "Swipe the forward to the left, then Delete."},
                      "note": "Nothing should be let in from the internet to an address that may go to another client.",
                      "undo": f"Make the port forward again: {what}.", "watch": {"kind": "no_forward", "mac": x["mac"], "ip": m.get("to_ip")}})
    for ip in has["reserved"]:
        steps.append({"title": f"Delete {x['name']}'s address reservation ({ip})",
                      "msp": {"path": ["Devices", x["name"]], "fields": [["IP", f"not reserved any more: {ip}", None]]},
                      "app": {"path": ["Devices", "All", x["name"], "IP Address"], "fields": [["IP ALLOCATION", "Dynamic", None]],
                              "note": "Set IP Allocation back to Dynamic, then Save."},
                      "note": "So the address is free again; with its list lines gone, a client that gets it later gets nothing of this one's.",
                      "undo": f"Reserve {ip} for {x['name']} again.", "watch": {"kind": "unreserved", "mac": x["mac"], "ip": ip}})
    steps.append({"title": f"Delete {howto_id(x)} in Firewalla",
                  "msp": {"path": ["Devices", x["name"]], "fields": [["Button", "Delete Device (at the bottom of its page)", None]]},
                  "app": {"path": ["Devices", "All", x["name"]], "note": "Scroll to the bottom of its page: Delete Device (or Forget), then confirm."},
                  "note": "Last, once everything above is done: Firewalla forgets it" + (f" and it leaves {gname}" if gname else "")
                          + ". If it ever comes back, Firewalla may not put it in Quarantine again (a client released from Quarantine isn't quarantined again): check where it lands and set it up with Client Onboarding.",
                  "undo": "If it reconnects, check where it lands and set it up again with Client Onboarding.",
                  "watch": {"kind": "device_gone", "mac": x["mac"]}})
    return {"mac": x["mac"], "client": {"name": x["name"], "ip": x.get("ip"), "online": x.get("online"), "network": x.get("network_name"), "group": gname},
            "has": {"lists": [{"name": tl.get("name") or tid, "lines": mine} for tid, tl, mine in has["lists"]],
                    "allowed": [access_rule_text(r) for r in has["allowed"]], "rules": [f"#{r.get('pid')} {access_rule_text(r)}" for r in has["rules"]],
                    "forwards": [f"{str(m.get('proto') or 'tcp').upper()} {m.get('port')} to {m.get('to_ip')}:{m.get('to_port')}" for m in has["forwards"]],
                    "reserved": has["reserved"]},
            "steps": steps, "_fix": fix}


OFF_LONG_DAYS = 30   # offline this long: listed as maybe gone


@app.get("/api/offboarding-page")
def api_offboarding_page(mac: str = None):
    """The Client Offboarding page: clients offline 30 days or more (there
    is no Missing Clients list since 24 Nov 2026, D-985), the plan for one,
    and offboarding changes."""
    sides, _ = access_sides()
    devices = {str(d.get("mac") or "").upper(): d for d in state.get("devices") or []}
    now = time.time()
    row = lambda s, why: {"mac": s["mac"], "name": s["name"], "ip": s.get("ip"), "online": s.get("online"), "network": s.get("network_name"),
                          "last": (devices.get(s["mac"]) or {}).get("last_active"), "why": why}
    rows = []
    for m, s in sides.items():
        last = (devices.get(m) or {}).get("last_active") or 0
        if not s.get("online") and not access_is_gear(s) and last and now - last >= OFF_LONG_DAYS * 86400:
            rows.append(row(s, f"offline {int((now - last) // 86400)} days"))
    plan = off_plan(mac) if mac else None
    if plan:
        plan.pop("_fix", None)
    changes = [c for c in howto_mark_done() if (c.get("request") or {}).get("kind") == "offboard" and c.get("status") != "done"]
    return {"candidates": sorted(rows, key=lambda r: str(r["name"]).lower()), "plan": plan, "changes": changes, "updated_at": now}


@app.post("/api/offboarding/start")
def api_offboarding_start(payload: dict = Body(default={})):
    """I'm Doing This for offboarding: {mac}. Refused while the client is online."""
    mac = Fields(payload).text("mac", 40, strip=False).upper()
    plan = off_plan(mac)
    if not plan:
        return {"ok": False, "error": "Pick a client first."}
    if plan["client"]["online"]:
        return {"ok": False, "error": f"{plan['client']['name']} is online: turn it off (or take it off the network) first."}
    sides, groups = access_sides()
    rules, iso = access_local_rules(), access_isolated()
    paused = {m: why for m, sd in sides.items() if (why := access_paused(sd))}
    expect = howto_expect(plan["_fix"], rules, groups, [], [None], iso, sides, paused)
    steps = [{**{k: s.get(k) for k in HOWTO_STEP_KEYS if s.get(k) is not None}, "title": s["title"], "watch": s["watch"]} for s in plan["steps"]]
    change = {"id": os.urandom(6).hex(), "title": f"Offboard {plan['client']['name']}", "source": "Client Offboarding",
              "started": time.time(), "status": "in_progress", "request": {"kind": "offboard", "mac": plan["mac"]},
              "steps": steps, "undo": [s.get("undo") for s in reversed(plan["steps"]) if s.get("undo")], "expect": expect}
    with howto_lock:
        st = howto_load()
        st["changes"] = [change] + st["changes"][:99]
        howto_save(st)
    return {"ok": True, "id": change["id"]}
